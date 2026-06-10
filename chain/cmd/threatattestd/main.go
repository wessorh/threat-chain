// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// threatattestd is the node binary for the ThreatAttest Cosmos SDK blockchain.
// It provides the full node daemon plus CLI commands for key management,
// genesis initialisation, and transaction submission.
package main

import (
	"os"

	"cosmossdk.io/log"
	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"

	"github.com/threatattest/chain/app"
	"github.com/threatattest/chain/cmd/threatattestd/cmd"
)

func main() {
	rootCmd := cmd.NewRootCmd()
	if err := svrcmd.Execute(rootCmd, "", app.DefaultNodeHome); err != nil {
		log.NewLogger(os.Stderr).Error("failed to execute", "error", err)
		os.Exit(1)
	}
}