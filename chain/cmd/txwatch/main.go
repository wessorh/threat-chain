// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// Command txwatch subscribes to a running threatattestd node and prints every
// transaction (height, tx hash, and decoded messages) to stdout as it arrives.
//
// Usage:
//
//	txwatch [tcp://host:26657]
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tmclient "github.com/cometbft/cometbft/rpc/client/http"
	"github.com/cometbft/cometbft/types"

	"github.com/threatattest/chain/app"
)

func main() {
	nodeURL := "tcp://localhost:26657"
	if len(os.Args) > 1 {
		nodeURL = os.Args[1]
	}

	enc := app.MakeEncodingConfig()
	txDecoder := enc.TxConfig.TxDecoder()

	cli, err := tmclient.New(nodeURL, "/websocket")
	if err != nil {
		fatal("connect: %v", err)
	}
	if err := cli.Start(); err != nil {
		fatal("start websocket: %v", err)
	}
	defer func() { _ = cli.Stop() }()

	txs, err := cli.Subscribe(context.Background(), "txwatch", "tm.event='Tx'")
	if err != nil {
		fatal("subscribe: %v", err)
	}

	fmt.Printf("watching for transactions on %s (Ctrl-C to quit)\n", nodeURL)

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
			fmt.Printf("─ tx height=%d hash=%s\n", data.Height, hex.EncodeToString(hash[:]))

			tx, err := txDecoder(data.Tx)
			if err != nil {
				fmt.Printf("  decode error: %v\n", err)
				continue
			}

			for i, msg := range tx.GetMsgs() {
				bz, err := enc.Codec.MarshalJSON(msg)
				if err != nil {
					fmt.Printf("  msg[%d]: %T (json error: %v)\n", i, msg, err)
					continue
				}
				fmt.Printf("  msg[%d]: %s\n", i, bz)
			}

		case <-sigCh:
			fmt.Println("shutting down")
			return
		}
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
