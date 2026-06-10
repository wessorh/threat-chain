// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package msgs

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/reputation/types"
)

// ============================================================
// MsgUpdateParams (governance)
// ============================================================

// MsgUpdateReputationParams updates x/reputation parameters via governance.
type MsgUpdateReputationParams struct {
	Authority string       `json:"authority"`
	Params    types.Params `json:"params"`
}

func (m *MsgUpdateReputationParams) Route() string { return types.ModuleName }
func (m *MsgUpdateReputationParams) Type() string  { return "update_reputation_params" }

func (m *MsgUpdateReputationParams) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Authority); err != nil {
		return err
	}
	return m.Params.Validate()
}

func (m *MsgUpdateReputationParams) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Authority)
	return []sdk.AccAddress{addr}
}

func (m *MsgUpdateReputationParams) ProtoMessage() {}
func (m *MsgUpdateReputationParams) Reset()        {}
func (m *MsgUpdateReputationParams) String() string { return "update_reputation_params" }

// ============================================================
// MsgBlacklistAttester (governance)
// ============================================================

// MsgBlacklistAttester blacklists or un-blacklists an attester via governance.
type MsgBlacklistAttester struct {
	Authority   string `json:"authority"`
	Attester    string `json:"attester"`
	Blacklisted bool   `json:"blacklisted"`
	Reason      string `json:"reason,omitempty"`
}

func (m *MsgBlacklistAttester) Route() string { return types.ModuleName }
func (m *MsgBlacklistAttester) Type() string  { return "blacklist_attester" }

func (m *MsgBlacklistAttester) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Authority); err != nil {
		return err
	}
	if _, err := sdk.AccAddressFromBech32(m.Attester); err != nil {
		return err
	}
	return nil
}

func (m *MsgBlacklistAttester) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Authority)
	return []sdk.AccAddress{addr}
}

func (m *MsgBlacklistAttester) ProtoMessage() {}
func (m *MsgBlacklistAttester) Reset()        {}
func (m *MsgBlacklistAttester) String() string { return m.Attester }