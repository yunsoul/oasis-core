// Package p2p provides common P2P interfaces.
package p2p

import (
	"context"
	"net"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

// ProtocolID is a protocol identifier.
type ProtocolID string

// XXX: is this the right place?
var CommitteeProtocolID = ProtocolID("/oasis/committee/" + version.RuntimeCommitteeProtocol.String())

// P2P is the p2p communication interface.
type P2P interface {
	Listen(protocolID ProtocolID) (net.Listener, error)

	Dial(ctx context.Context, protocolID ProtocolID, node *node.Node) (net.Conn, error)
}
