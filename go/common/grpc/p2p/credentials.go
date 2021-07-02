package p2p

import (
	"context"
	"net"
	"fmt"

	"google.golang.org/grpc/credentials"

	"github.com/oasisprotocol/oasis-core/go/common/p2p"
)

// NewCredentials returns transport credentials that use underlying P2P stream authentication.
func NewCredentials() credentials.TransportCredentials {
	return p2pTC{}
}

type p2pTC struct{}

// Implements credentials.TransportCredentials.
func (p2pTC) ClientHandshake(ctx context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	ai, err := newAuthInfoForConn(conn)
	if err != nil {
		return nil, ai, err
	}
	return conn, ai, nil
}

// Implements credentials.TransportCredentials.
func (p2pTC) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	ai, err := newAuthInfoForConn(conn)
	if err != nil {
		return nil, ai, err
	}
	return conn, ai, nil
}

// Implements credentials.TransportCredentials.
func (p2pTC) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "p2p"}
}

// Implements credentials.TransportCredentials.
func (p2pTC) Clone() credentials.TransportCredentials {
	return p2pTC{}
}

// Implements credentials.TransportCredentials.
func (p2pTC) OverrideServerName(string) error {
	return nil
}

// AuthInfo contains the authentication information for a p2p connection.
type AuthInfo struct {
	credentials.CommonAuthInfo

	// PeerID is the authenticated peer identifier of the other peer.
	PeerID signature.PublicKey
}

// Implements credentials.AuthInfo.
func (AuthInfo) AuthType() string {
	return "p2p"
}

func newAuthInfoForConn(conn net.Conn) (AuthInfo, error) {
	// Make sure that the connection is authenticated.
	pc, ok := conn.(p2p.Conn)
	if !ok {
		return AuthInfo{}, fmt.Errorf("not a p2p connection")
	}

	return AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity
		},
		PeerID: pc.PeerID(),
	}, nil
}