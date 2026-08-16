// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package pb

import (
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

// RegisterMsgServiceDesc marks the generated Msg service as a Cosmos SDK msg
// service (cosmos.msg.v1.service), enabling reflection-based signer extraction
// and silencing the proto-registry annotation warning.
func RegisterMsgServiceDesc(registry codectypes.InterfaceRegistry) {
	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}
