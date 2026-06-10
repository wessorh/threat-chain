// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package msgs

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/ipfsverify/types"
)

// ============================================================
// MsgSubmitVerificationReport
// ============================================================

// MsgSubmitVerificationReport is submitted by the off-chain IPFS verifier daemon
// (running as a whitelisted relayer account) after fetching and hashing CID content.
type MsgSubmitVerificationReport struct {
	Sender string                   `json:"sender"`
	Report types.VerificationReport `json:"report"`
}

func (m *MsgSubmitVerificationReport) Route() string { return types.ModuleName }
func (m *MsgSubmitVerificationReport) Type() string  { return "submit_verification_report" }

func (m *MsgSubmitVerificationReport) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Sender); err != nil {
		return err
	}
	if m.Report.JobID == "" {
		return fmt.Errorf("job_id is required")
	}
	if m.Report.CID == "" {
		return fmt.Errorf("cid is required")
	}
	return nil
}

func (m *MsgSubmitVerificationReport) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Sender)
	return []sdk.AccAddress{addr}
}

func (m *MsgSubmitVerificationReport) ProtoMessage()  {}
func (m *MsgSubmitVerificationReport) Reset()         {}
func (m *MsgSubmitVerificationReport) String() string { return m.Report.JobID }

// ============================================================
// MsgUpdateIPFSParams (governance)
// ============================================================

// MsgUpdateIPFSParams updates x/ipfsverify parameters via governance.
type MsgUpdateIPFSParams struct {
	Authority string       `json:"authority"`
	Params    types.Params `json:"params"`
}

func (m *MsgUpdateIPFSParams) Route() string { return types.ModuleName }
func (m *MsgUpdateIPFSParams) Type() string  { return "update_ipfs_params" }

func (m *MsgUpdateIPFSParams) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Authority); err != nil {
		return err
	}
	return m.Params.Validate()
}

func (m *MsgUpdateIPFSParams) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Authority)
	return []sdk.AccAddress{addr}
}

func (m *MsgUpdateIPFSParams) ProtoMessage()  {}
func (m *MsgUpdateIPFSParams) Reset()         {}
func (m *MsgUpdateIPFSParams) String() string { return "update_ipfs_params" }