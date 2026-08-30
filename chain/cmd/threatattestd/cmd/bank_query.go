// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package cmd

import (
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/spf13/cobra"
)

// bankQueryCmds returns the query subcommands for the x/bank module.
//
// Cosmos SDK v0.55 no longer ships a hand-written `bankcli.NewQueryCmd`; bank
// query commands are normally produced by the AutoCLI machinery. This function
// reconstructs that command set manually so `threatattestd q bank ...` works
// without pulling in the full AutoCLI reflection service. The command names and
// arguments mirror the module's AutoCLIOptions() (x/bank/autocli.go).
func bankQueryCmds() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "bank",
		Short:                      "Querying commands for the bank module",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(
		bankBalanceCmd(),
		bankBalancesCmd(),
		bankSpendableBalancesCmd(),
		bankSpendableBalanceCmd(),
		bankTotalSupplyCmd(),
		bankSupplyOfCmd(),
		bankParamsCmd(),
		bankDenomMetadataCmd(),
		bankDenomsMetadataCmd(),
		bankDenomOwnersCmd(),
		bankSendEnabledCmd(),
	)
	return cmd
}

func bankBalanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "balance [address] [denom]",
		Short: "Query an account balance by address and denom",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).Balance(cmd.Context(),
				&banktypes.QueryBalanceRequest{Address: args[0], Denom: args[1]})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankBalancesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "balances [address]",
		Short: "Query for account balances by address",
		Long:  "Query the total balance of an account or of a specific denomination.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).AllBalances(cmd.Context(),
				&banktypes.QueryAllBalancesRequest{Address: args[0], Pagination: pageReq})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankSpendableBalancesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spendable-balances [address]",
		Short: "Query for account spendable balances by address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).SpendableBalances(cmd.Context(),
				&banktypes.QuerySpendableBalancesRequest{Address: args[0], Pagination: pageReq})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankSpendableBalanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spendable-balance [address] [denom]",
		Short: "Query the spendable balance of a single denom for a single account",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).SpendableBalanceByDenom(cmd.Context(),
				&banktypes.QuerySpendableBalanceByDenomRequest{Address: args[0], Denom: args[1]})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankTotalSupplyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "total-supply",
		Aliases: []string{"total"},
		Short:   "Query the total supply of coins of the chain",
		Long:    "Query total supply of coins that are held by accounts in the chain. To query for the total supply of a specific coin denomination use --denom flag.",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).TotalSupply(cmd.Context(),
				&banktypes.QueryTotalSupplyRequest{Pagination: pageReq})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankSupplyOfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "total-supply-of [denom]",
		Short: "Query the supply of a single coin denom",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).SupplyOf(cmd.Context(),
				&banktypes.QuerySupplyOfRequest{Denom: args[0]})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankParamsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "params",
		Short: "Query the current bank parameters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).Params(cmd.Context(),
				&banktypes.QueryParamsRequest{})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankDenomMetadataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "denom-metadata [denom]",
		Short: "Query the client metadata of a given coin denomination",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).DenomMetadata(cmd.Context(),
				&banktypes.QueryDenomMetadataRequest{Denom: args[0]})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankDenomsMetadataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "denoms-metadata",
		Short: "Query the client metadata for all registered coin denominations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).DenomsMetadata(cmd.Context(),
				&banktypes.QueryDenomsMetadataRequest{Pagination: pageReq})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankDenomOwnersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "denom-owners [denom]",
		Short: "Query for all account addresses that own a particular token denomination",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).DenomOwners(cmd.Context(),
				&banktypes.QueryDenomOwnersRequest{Denom: args[0], Pagination: pageReq})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func bankSendEnabledCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send-enabled [denom1 ...]",
		Short: "Query for send enabled entries",
		Long: `Query for send enabled entries that have been specifically set.

To look up one or more specific denoms, supply them as arguments to this command.
To look up all denoms, do not provide any arguments.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			pageReq, err := client.ReadPageRequest(cmd.Flags())
			if err != nil {
				return err
			}
			res, err := banktypes.NewQueryClient(clientCtx).SendEnabled(cmd.Context(),
				&banktypes.QuerySendEnabledRequest{Denoms: args, Pagination: pageReq})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddPaginationFlagsToCmd(cmd, cmd.Use)
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
