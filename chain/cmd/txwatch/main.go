// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// Command txwatch subscribes to a running threatattestd node and prints
// transactions as they arrive.
//
// By default it prints every transaction (height, tx hash, and decoded
// messages). With -publish-only it subscribes only to attestation
// publications and prints a compact one-line summary of each.
//
// The connection is monitored: if the subscription drops or a periodic health
// check fails, txwatch reconnects automatically (with backoff). The health
// check also watches a NewBlockHeader feed as a liveness signal, so a
// silently-dead websocket (e.g. after a node redeploy) is detected and healed.
//
// Usage:
//
//	txwatch [flags] [tcp://host:26657]
//
// Flags:
//
//	-node          CometBFT RPC node URL (default tcp://s6l.com:26657)
//	-publish-only  print only MsgPublishAttestation transactions
//	-debug         verbose diagnostic logging to stderr (connection, health, feed liveness)
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	tmclient "github.com/cometbft/cometbft/rpc/client/http"
	"github.com/cometbft/cometbft/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/app"
	attestmsgs "github.com/threatattest/chain/x/attestation/msgs"
	atttypes "github.com/threatattest/chain/x/attestation/types"
)

// publishAction is the sdk.Msg type URL emitted as the "message.action"
// event attribute for MsgPublishAttestation (see msgs.XXX_MessageName).
const publishAction = "/threatattest.attestation.MsgPublishAttestation"

// healthInterval is how often txwatch verifies the node is still reachable.
const healthInterval = 30 * time.Second

// maxBlockGap is how many blocks behind the node's latest height our websocket
// feed may lag before we treat it as stale and reconnect. The node emits a
// block header every block (even empty ones), so a healthy feed never lags
// more than a couple of blocks; 10 gives a comfortable margin against network
// jitter while still catching a silently-dead subscription within one health
// interval (~30s).
const maxBlockGap int64 = 10

func main() {
	nodeURL := flag.String("node", "tcp://s6l.com:26657", "CometBFT RPC node URL")
	publishOnly := flag.Bool("publish-only", false, "print only attestation publications")
	debug := flag.Bool("debug", false, "enable verbose diagnostic logging to stderr")
	flag.Parse()
	// Legacy positional form: txwatch tcp://host:26657
	if flag.NArg() > 0 {
		*nodeURL = flag.Arg(0)
	}

	enc := app.MakeEncodingConfig()
	txDecoder := enc.TxConfig.TxDecoder()

	query := "tm.event='Tx'"
	mode := "transactions"
	if *publishOnly {
		query = "tm.event='Tx' AND message.action='" + publishAction + "'"
		mode = "attestation publications"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("shutting down")
		cancel()
	}()

	fmt.Printf("watching for %s on %s (Ctrl-C to quit)\n", mode, *nodeURL)
	if *debug {
		fmt.Fprintf(os.Stderr, "[debug] diagnostics enabled\n")
	}

	// Reconnect loop: retry with backoff whenever the watch returns.
	backoff := time.Second
	for {
		err := watch(ctx, *nodeURL, query, *publishOnly, *debug, enc, txDecoder)
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintf(os.Stderr, "txwatch: %v — reconnecting in %v\n", err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// watch connects, subscribes, and streams transactions until the subscription
// drops, a periodic health check fails, or ctx is cancelled. It returns an
// error so the caller can reconnect.
func watch(ctx context.Context, nodeURL, query string, publishOnly, debug bool, enc app.EncodingConfig, txDecoder sdk.TxDecoder) error {
	cli, err := tmclient.New(nodeURL, "/websocket")
	if err != nil {
		return err
	}
	if err := cli.Start(); err != nil {
		return err
	}

	txs, err := cli.Subscribe(ctx, "txwatch", query)
	if err != nil {
		return err
	}
	logDebug(debug, "subscribed to transactions: %s", query)

	// A second subscription to NewBlockHeader is the liveness signal: the node
	// emits a block header every block (even empty ones), so a feed that stops
	// delivering headers while the node is still advancing means the websocket
	// died silently. The HTTP Status check alone cannot see that.
	blocks, err := cli.Subscribe(ctx, "txwatch-blocks", "tm.event='NewBlockHeader'")
	if err != nil {
		return err
	}
	logDebug(debug, "subscribed to block headers for liveness")

	health := time.NewTicker(healthInterval)
	defer health.Stop()

	var lastBlockHeight int64
	var lastBlockLog time.Time

	for {
		select {
		case evt, ok := <-txs:
			if !ok {
				return fmt.Errorf("tx subscription channel closed")
			}
			data, ok := evt.Data.(types.EventDataTx)
			if !ok {
				continue
			}

			hash := sha256.Sum256(data.Tx)
			hashStr := hex.EncodeToString(hash[:])

			tx, err := txDecoder(data.Tx)
			if err != nil {
				fmt.Printf("─ tx height=%d hash=%s decode error: %v\n",
					data.Height, hashStr, err)
				continue
			}

			if publishOnly {
				printPublish(data, tx, hashStr)
			} else {
				printTx(data, tx, enc, hashStr)
			}

		case evt, ok := <-blocks:
			if !ok {
				return fmt.Errorf("block subscription channel closed")
			}
			if data, ok := evt.Data.(types.EventDataNewBlockHeader); ok {
				lastBlockHeight = data.Header.Height
				if debug && time.Since(lastBlockLog) >= 10*time.Second {
					logDebug(debug, "block feed alive at height %d", lastBlockHeight)
					lastBlockLog = time.Now()
				}
			}

		case <-health.C:
			if err := checkHealth(ctx, cli, lastBlockHeight, debug); err != nil {
				return err
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// checkHealth verifies the node is reachable and that the websocket feed is
// still live. The HTTP Status call alone cannot detect a silently-dead event
// subscription, so we compare the node's latest height against the last block
// header actually received: if the node has advanced well past our feed, the
// subscription is stale and the caller reconnects.
func checkHealth(ctx context.Context, cli *tmclient.HTTP, lastBlockHeight int64, debug bool) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := cli.Status(checkCtx)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	latest := status.SyncInfo.LatestBlockHeight
	gap := latest - lastBlockHeight
	logDebug(debug, "health: node_height=%d last_seen=%d gap=%d", latest, lastBlockHeight, gap)
	if gap > maxBlockGap {
		return fmt.Errorf("websocket feed stale: node at height %d but last block seen is %d",
			latest, lastBlockHeight)
	}
	return nil
}

// logDebug prints a diagnostic line to stderr when debug logging is enabled.
// stdout is reserved for transaction output, so diagnostics always go to
// stderr regardless of mode.
func logDebug(debug bool, format string, args ...interface{}) {
	if !debug {
		return
	}
	fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
}

// printTx prints every message in a transaction as JSON (default mode).
func printTx(data types.EventDataTx, tx sdk.Tx, enc app.EncodingConfig, hashStr string) {
	fmt.Printf("─ tx height=%d hash=%s\n", data.Height, hashStr)

	for i, msg := range tx.GetMsgs() {
		bz, err := enc.Codec.MarshalJSON(msg)
		if err != nil {
			fmt.Printf("  msg[%d]: %T (json error: %v)\n", i, msg, err)
			continue
		}
		fmt.Printf("  msg[%d]: %s\n", i, bz)
	}
}

// printPublish prints a compact summary of each attestation publication in a
// transaction. The server-computed attestation ID is read from the emitted
// publish_attestation event (it is not present in the message itself).
func printPublish(data types.EventDataTx, tx sdk.Tx, hashStr string) {
	attrs := publishEventAttrs(data)

	for _, msg := range tx.GetMsgs() {
		p, ok := msg.(*attestmsgs.MsgPublishAttestation)
		if !ok {
			continue
		}
		id := attrs[atttypes.AttributeKeyAttestationID]
		if id == "" {
			id = "-"
		}
		fmt.Printf("publish height=%d hash=%s id=%s attester=%s type=%s sha256=%s severity=%s tlp=%s\n",
			data.Height, hashStr, id, p.Attester, p.ArtifactType.String(),
			p.ArtifactSHA256, p.Severity.String(), p.TLP.String())
	}
}

// publishEventAttrs extracts the attributes of the publish_attestation event
// emitted with a successful MsgPublishAttestation, keyed by attribute name.
func publishEventAttrs(data types.EventDataTx) map[string]string {
	out := map[string]string{}
	for _, ev := range data.Result.Events {
		if ev.Type != atttypes.EventTypePublishAttestation {
			continue
		}
		for _, a := range ev.Attributes {
			out[a.Key] = a.Value
		}
	}
	return out
}
