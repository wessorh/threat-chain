// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package ante

import (
	"encoding/binary"

	"cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"

	attestkeeper "github.com/threatattest/chain/x/attestation/keeper"
	attestmsgs "github.com/threatattest/chain/x/attestation/msgs"
	attesttypes "github.com/threatattest/chain/x/attestation/types"
)

// ============================================================
// AttesterEligibilityDecorator
// ============================================================

// AttesterEligibilityDecorator checks that the sender of a MsgPublishAttestation
// has sufficient delegated stake to be allowed to publish.
type AttesterEligibilityDecorator struct {
	attestKeeper attestkeeper.Keeper
}

// NewAttesterEligibilityDecorator creates a new AttesterEligibilityDecorator.
func NewAttesterEligibilityDecorator(k attestkeeper.Keeper) AttesterEligibilityDecorator {
	return AttesterEligibilityDecorator{attestKeeper: k}
}

// AnteHandle checks attester eligibility for attestation messages.
func (d AttesterEligibilityDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	for _, msg := range tx.GetMsgs() {
		pub, ok := msg.(*attestmsgs.MsgPublishAttestation)
		if !ok {
			continue
		}

		// Check blacklist
		bl, err := d.attestKeeper.IsBlacklisted(ctx, pub.Attester)
		if err != nil {
			return ctx, errors.Wrap(sdkerrors.ErrUnauthorized, "blacklist check failed")
		}
		if bl {
			return ctx, errors.Wrapf(attesttypes.ErrAttesterBlacklisted,
				"attester %s is blacklisted", pub.Attester)
		}

		// Check minimum reputation
		params, err := d.attestKeeper.GetParams(ctx)
		if err != nil {
			return ctx, errors.Wrap(sdkerrors.ErrLogic, "failed to load attestation params")
		}

		rs, err := d.attestKeeper.GetAttesterRS(ctx, pub.Attester)
		if err != nil {
			return ctx, errors.Wrap(sdkerrors.ErrLogic, "failed to load reputation score")
		}
		if rs < params.MinReputationToAttest {
			return ctx, errors.Wrapf(attesttypes.ErrInsufficientReputation,
				"score=%d required=%d", rs, params.MinReputationToAttest)
		}
	}

	return next(ctx, tx, simulate)
}

// ============================================================
// AttesterRateLimitDecorator
// ============================================================

// AttesterRateLimitDecorator enforces the per-epoch publication rate limit
// at the ante-handler level, before any state changes are applied.
type AttesterRateLimitDecorator struct {
	attestKeeper attestkeeper.Keeper
}

// NewAttesterRateLimitDecorator creates a new AttesterRateLimitDecorator.
func NewAttesterRateLimitDecorator(k attestkeeper.Keeper) AttesterRateLimitDecorator {
	return AttesterRateLimitDecorator{attestKeeper: k}
}

// AnteHandle checks that the attester has not exceeded the per-epoch rate limit.
func (d AttesterRateLimitDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	// Count publish messages in this tx
	var publishCount int
	var attester string
	for _, msg := range tx.GetMsgs() {
		pub, ok := msg.(*attestmsgs.MsgPublishAttestation)
		if !ok {
			continue
		}
		publishCount++
		attester = pub.Attester
	}

	if publishCount == 0 {
		return next(ctx, tx, simulate)
	}

	params, err := d.attestKeeper.GetParams(ctx)
	if err != nil {
		return ctx, errors.Wrap(sdkerrors.ErrLogic, "failed to load attestation params")
	}

	epoch := attesttypes.CurrentEpoch(ctx.BlockHeight())
	count, err := d.attestKeeper.GetEpochCount(ctx, epoch, attester)
	if err != nil {
		return ctx, errors.Wrap(sdkerrors.ErrLogic, "failed to read epoch count")
	}

	// Ensure adding this tx's publish messages won't exceed the limit
	if count+uint32(publishCount) > params.MaxAttestationsPerEpoch {
		return ctx, errors.Wrapf(attesttypes.ErrRateLimitExceeded,
			"epoch=%d count=%d limit=%d", epoch, count, params.MaxAttestationsPerEpoch)
	}

	return next(ctx, tx, simulate)
}

// ============================================================
// TimestampToleranceDecorator
// ============================================================

// TimestampToleranceDecorator rejects attestations whose publish timestamp
// deviates too far from the current block time.
type TimestampToleranceDecorator struct {
	attestKeeper attestkeeper.Keeper
}

// NewTimestampToleranceDecorator creates a new TimestampToleranceDecorator.
func NewTimestampToleranceDecorator(k attestkeeper.Keeper) TimestampToleranceDecorator {
	return TimestampToleranceDecorator{attestKeeper: k}
}

// AnteHandle validates that TTL values in publish messages are within the
// allowed range given the current block time.
func (d TimestampToleranceDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	params, err := d.attestKeeper.GetParams(ctx)
	if err != nil {
		return ctx, errors.Wrap(sdkerrors.ErrLogic, "failed to load attestation params")
	}

	for _, msg := range tx.GetMsgs() {
		pub, ok := msg.(*attestmsgs.MsgPublishAttestation)
		if !ok {
			continue
		}

		// TTL range check
		if pub.TTLSeconds < params.MinTTLSeconds || pub.TTLSeconds > params.MaxTTLSeconds {
			return ctx, errors.Wrapf(attesttypes.ErrTTLOutOfRange,
				"ttl=%d min=%d max=%d", pub.TTLSeconds, params.MinTTLSeconds, params.MaxTTLSeconds)
		}

		// IPv4 TTL cap
		if pub.ArtifactType == attesttypes.ArtifactType_IPV4 &&
			pub.TTLSeconds > params.MaxTTLIPv4Seconds {
			return ctx, errors.Wrapf(attesttypes.ErrTTLOutOfRange,
				"ipv4 ttl=%d max=%d", pub.TTLSeconds, params.MaxTTLIPv4Seconds)
		}

		// IPv4 minimum confidence
		if pub.ArtifactType == attesttypes.ArtifactType_IPV4 &&
			pub.Confidence < params.IPv4MinConfidence {
			return ctx, errors.Wrapf(attesttypes.ErrInvalidConfidence,
				"ipv4 confidence=%d min=%d", pub.Confidence, params.IPv4MinConfidence)
		}
	}

	return next(ctx, tx, simulate)
}

// ============================================================
// NewAnteHandler builds the full ThreatAttest ante-handler chain.
// ============================================================

// HandlerOptions extends the standard SDK auth ante handler options with
// ThreatAttest-specific keepers.
type HandlerOptions struct {
	ante.HandlerOptions
	AttestKeeper attestkeeper.Keeper
}

// NewAnteHandler creates the complete ante-handler chain for threatattestd.
// It prepends the ThreatAttest-specific decorators before the standard SDK ones.
func NewAnteHandler(opts HandlerOptions) (sdk.AnteHandler, error) {
	// Validate standard options
	if opts.AccountKeeper == nil {
		return nil, errors.Wrap(sdkerrors.ErrLogic, "account keeper is required")
	}
	if opts.BankKeeper == nil {
		return nil, errors.Wrap(sdkerrors.ErrLogic, "bank keeper is required")
	}
	if opts.SignModeHandler == nil {
		return nil, errors.Wrap(sdkerrors.ErrLogic, "sign mode handler is required")
	}

	anteDecorators := []sdk.AnteDecorator{
		// Standard SDK decorators
		ante.NewSetUpContextDecorator(),
		ante.NewExtensionOptionsDecorator(opts.ExtensionOptionChecker),
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(opts.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(opts.AccountKeeper),
		ante.NewDeductFeeDecorator(opts.AccountKeeper, opts.BankKeeper, opts.FeegrantKeeper, opts.TxFeeChecker),
		ante.NewSetPubKeyDecorator(opts.AccountKeeper),
		ante.NewValidateSigCountDecorator(opts.AccountKeeper),
		ante.NewSigGasConsumeDecorator(opts.AccountKeeper, opts.SigGasConsumer),
		ante.NewSigVerificationDecorator(opts.AccountKeeper, opts.SignModeHandler),
		ante.NewIncrementSequenceDecorator(opts.AccountKeeper),

		// ThreatAttest-specific decorators
		NewAttesterEligibilityDecorator(opts.AttestKeeper),
		NewAttesterRateLimitDecorator(opts.AttestKeeper),
		NewTimestampToleranceDecorator(opts.AttestKeeper),
	}

	return sdk.ChainAnteDecorators(anteDecorators...), nil
}

// ============================================================
// Helper: encodeUint64BigEndian used by epoch keys
// ============================================================

func encodeUint64BigEndian(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}