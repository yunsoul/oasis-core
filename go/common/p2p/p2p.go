// Package p2p provides common P2P interfaces.
package p2p

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p-core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

// XXX: is this the right place?
var CommitteeProtocolID = protocol.ID("/oasis/committee/" + version.RuntimeCommitteeProtocol.String())

// P2P is the p2p communication interface.
type P2P interface {
	Listen(protocolID protocol.ID) (net.Listener, error)

	Dial(ctx context.Context, protocolID protocol.ID, node *node.Node) (net.Conn, error)
}
