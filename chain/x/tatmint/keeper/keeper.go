// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"context"
	"encoding/json"
	"fmt"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log/v2"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/tatmint/types"
)

// BankKeeper is the subset of x/bank needed by tatmint.
type BankKeeper interface {
	MintCoins(ctx context.Context, moduleName string, amounts sdk.Coins) error
	SendCoinsFromModuleToModule(ctx context.Context, senderModule, recipientModule string, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	GetSupply(ctx context.Context, denom string) sdk.Coin
}

// DistributionKeeper routes community pool contributions.
type DistributionKeeper interface {
	FundCommunityPool(ctx context.Context, amount sdk.Coins, sender sdk.AccAddress) error
}

// AttesterMintReporter records the attester-share minted each block so the
// attestation module can track its per-epoch replenishment.
type AttesterMintReporter interface {
	RecordAttesterMint(ctx sdk.Context, amount int64) error
}

// Keeper provides state access for the tatmint module.
type Keeper struct {
	cdc                  codec.BinaryCodec
	storeService         store.KVStoreService
	logger               log.Logger
	bankKeeper           BankKeeper
	distKeeper           DistributionKeeper
	attesterMintReporter AttesterMintReporter
	feeCollector         string // module account name for validator rewards
}

// NewKeeper constructs a new tatmint Keeper.
func NewKeeper(
	cdc codec.BinaryCodec,
	storeService store.KVStoreService,
	logger log.Logger,
	bankKeeper BankKeeper,
	distKeeper DistributionKeeper,
	attesterMintReporter AttesterMintReporter,
	feeCollector string,
) Keeper {
	return Keeper{
		cdc:                  cdc,
		storeService:         storeService,
		logger:               logger.With("module", types.ModuleName),
		bankKeeper:           bankKeeper,
		distKeeper:           distKeeper,
		attesterMintReporter: attesterMintReporter,
		feeCollector:         feeCollector,
	}
}

// Logger returns the module logger.
func (k Keeper) Logger() log.Logger { return k.logger }

// ============================================================
// Params
// ============================================================

func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	bz, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal tatmint params: %w", err)
	}
	return k.storeService.OpenKVStore(ctx).Set([]byte{types.ParamsKeyByte}, bz)
}

func (k Keeper) GetParams(ctx sdk.Context) (types.Params, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get([]byte{types.ParamsKeyByte})
	if err != nil {
		return types.Params{}, err
	}
	if bz == nil {
		return types.DefaultParams(), nil
	}
	var p types.Params
	if err := json.Unmarshal(bz, &p); err != nil {
		return types.Params{}, fmt.Errorf("unmarshal tatmint params: %w", err)
	}
	return p, nil
}

// ============================================================
// MintState
// ============================================================

func (k Keeper) SetMintState(ctx sdk.Context, ms types.MintState) error {
	bz, err := json.Marshal(ms)
	if err != nil {
		return fmt.Errorf("marshal mint state: %w", err)
	}
	return k.storeService.OpenKVStore(ctx).Set([]byte{types.MintStateKeyByte}, bz)
}

func (k Keeper) GetMintState(ctx sdk.Context) (types.MintState, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get([]byte{types.MintStateKeyByte})
	if err != nil {
		return types.MintState{}, err
	}
	if bz == nil {
		return types.MintState{
			CurrentBlockReward: types.InitialBlockReward,
			HalvingEpoch:       0,
			TotalMinted:        0,
			NextHalvingBlock:   types.HalvingInterval,
		}, nil
	}
	var ms types.MintState
	if err := json.Unmarshal(bz, &ms); err != nil {
		return types.MintState{}, fmt.Errorf("unmarshal mint state: %w", err)
	}
	return ms, nil
}

// ============================================================
// Block minting logic
// ============================================================

// MintBlockReward mints the reward for the current block and distributes it
// according to the configured fractions.
//
// Distribution:
//   - ValidatorRewardBPS% → fee_collector module account (distributed by x/distribution)
//   - CommunityPoolBPS%   → community pool
//   - AttesterRewardBPS%  → attestation module account (queued for active attesters)
//
// Called from BeginBlocker.
func (k Keeper) MintBlockReward(ctx sdk.Context) error {
	params, err := k.GetParams(ctx)
	if err != nil {
		return err
	}
	ms, err := k.GetMintState(ctx)
	if err != nil {
		return err
	}

	height := ctx.BlockHeight()

	// Check for halving
	if height >= ms.NextHalvingBlock && ms.HalvingEpoch < uint32(types.MaxHalvings) {
		ms.HalvingEpoch++
		ms.CurrentBlockReward = types.BlockRewardAtEpoch(ms.HalvingEpoch)
		ms.NextHalvingBlock = (int64(ms.HalvingEpoch) + 1) * types.HalvingInterval

		k.logger.Info("TATST halving",
			"epoch", ms.HalvingEpoch,
			"new_block_reward", ms.CurrentBlockReward,
			"next_halving_block", ms.NextHalvingBlock,
		)

		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"tatmint_halving",
			sdk.NewAttribute("epoch", fmt.Sprintf("%d", ms.HalvingEpoch)),
			sdk.NewAttribute("new_block_reward_utatst", fmt.Sprintf("%d", ms.CurrentBlockReward)),
		))
	}

	// No reward once emission ends
	if ms.CurrentBlockReward == 0 {
		return nil
	}

	// Check supply cap
	currentSupply := k.bankKeeper.GetSupply(ctx, types.MintDenom)
	remaining := types.TotalSupplyCap - currentSupply.Amount.Int64() - ms.TotalMinted
	if remaining <= 0 {
		ms.CurrentBlockReward = 0
		return k.SetMintState(ctx, ms)
	}

	reward := ms.CurrentBlockReward
	if reward > remaining {
		reward = remaining
	}

	// Mint coins into the tatmint module account
	mintCoins := sdk.NewCoins(sdk.NewInt64Coin(types.MintDenom, reward))
	if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, mintCoins); err != nil {
		return fmt.Errorf("mint block reward: %w", err)
	}

	// Split the reward according to BPS fractions
	validatorShare := reward * int64(params.ValidatorRewardBPS) / 10_000
	communityShare := reward * int64(params.CommunityPoolBPS) / 10_000
	attesterShare := reward - validatorShare - communityShare // remainder avoids rounding loss

	// Route validator share → fee_collector
	if validatorShare > 0 {
		if err := k.bankKeeper.SendCoinsFromModuleToModule(
			ctx,
			types.ModuleName,
			k.feeCollector,
			sdk.NewCoins(sdk.NewInt64Coin(types.MintDenom, validatorShare)),
		); err != nil {
			return fmt.Errorf("route validator share: %w", err)
		}
	}

	// Route community share → distribution pool
	if communityShare > 0 {
		if err := k.bankKeeper.SendCoinsFromModuleToModule(
			ctx,
			types.ModuleName,
			"distribution",
			sdk.NewCoins(sdk.NewInt64Coin(types.MintDenom, communityShare)),
		); err != nil {
			return fmt.Errorf("route community share: %w", err)
		}
	}

	// Route attester share → attestation incentive pool
	if attesterShare > 0 {
		if err := k.bankKeeper.SendCoinsFromModuleToModule(
			ctx,
			types.ModuleName,
			"attestation",
			sdk.NewCoins(sdk.NewInt64Coin(types.MintDenom, attesterShare)),
		); err != nil {
			return fmt.Errorf("route attester share: %w", err)
		}
		if k.attesterMintReporter != nil {
			if err := k.attesterMintReporter.RecordAttesterMint(ctx, attesterShare); err != nil {
				return fmt.Errorf("record attester mint: %w", err)
			}
		}
	}

	ms.TotalMinted += reward
	return k.SetMintState(ctx, ms)
}

// TotalMinted returns the cumulative minted supply.
func (k Keeper) TotalMinted(ctx sdk.Context) (int64, error) {
	ms, err := k.GetMintState(ctx)
	if err != nil {
		return 0, err
	}
	return ms.TotalMinted, nil
}
