// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// Command txwatch subscribes to a running threatattestd node and prints
// transactions as they arrive.
//
// By default it prints every transaction (height, tx hash, and decoded
// messages). With -publish-only it subscribes only to attestation
// publications and prints a compact one-line summary of each.
//
// Usage:
//
//	txwatch [flags] [tcp://host:26657]
//
// Flags:
//
//	-node          CometBFT RPC node URL (default tcp://s6l.com:26657)
//	-publish-only  print only MsgPublishAttestation transactions
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

func main() {
	nodeURL := flag.String("node", "tcp://s6l.com:26657", "CometBFT RPC node URL")
	publishOnly := flag.Bool("publish-only", false, "print only attestation publications")
	flag.Parse()
	// Legacy positional form: txwatch tcp://host:26657
	if flag.NArg() > 0 {
		*nodeURL = flag.Arg(0)
	}

	enc := app.MakeEncodingConfig()
	txDecoder := enc.TxConfig.TxDecoder()

	cli, err := tmclient.New(*nodeURL, "/websocket")
	if err != nil {
		fatal("connect: %v", err)
	}
	if err := cli.Start(); err != nil {
		fatal("start websocket: %v", err)
	}
	defer func() { _ = cli.Stop() }()

	query := "tm.event='Tx'"
	mode := "transactions"
	if *publishOnly {
		query = "tm.event='Tx' AND message.action='" + publishAction + "'"
		mode = "attestation publications"
	}

	txs, err := cli.Subscribe(context.Background(), "txwatch", query)
	if err != nil {
		fatal("subscribe: %v", err)
	}

	fmt.Printf("watching for %s on %s (Ctrl-C to quit)\n", mode, *nodeURL)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case evt := <-txs:
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

			if *publishOnly {
				printPublish(data, tx, hashStr)
			} else {
				printTx(data, tx, enc, hashStr)
			}

		case <-sigCh:
			fmt.Println("shutting down")
			return
		}
	}
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

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
