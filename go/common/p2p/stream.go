package p2p

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// Network returns the network protocol name used in net.Addr addresses.
const Network = "p2p"

// Conn represents a connection backed by libp2p stream.
type Conn interface {
	// PeerID returns the P2P public key identifying the remote peer.
	PeerID() signature.PublicKey
}

type conn struct {
	s network.Stream
}

// Implements net.Conn.
func (c *conn) Read(b []byte) (n int, err error) {
	return c.s.Read(b)
}

// Implements net.Conn.
func (c *conn) Write(b []byte) (n int, err error) {
	return c.s.Write(b)
}

// Implements net.Conn.
func (c *conn) Close() error {
	return c.s.Close()
}

// Implements net.Conn.
func (c *conn) LocalAddr() net.Addr {
	return &addr{c.s.Conn().LocalPeer()}
}

// Implements net.Conn.
func (c *conn) RemoteAddr() net.Addr {
	return &addr{c.s.Conn().RemotePeer()}
}

// Implements net.Conn.
func (c *conn) SetDeadline(t time.Time) error {
	return c.s.SetDeadline(t)
}

// Implements net.Conn.
func (c *conn) SetReadDeadline(t time.Time) error {
	return c.s.SetReadDeadline(t)
}

// Implements net.Conn.
func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.s.SetWriteDeadline(t)
}

// Implements Conn.
func (c *conn) PeerID() signature.PublicKey {
	pk, err := PubKeyToPublicKey(c.s.Conn().RemotePublicKey())
	if err != nil {
		panic(err)
	}
	return pk
}

// addr implements net.Addr and holds a libp2p peer ID.
type addr struct {
	id peer.ID
}

// Implements net.Addr.
func (a *addr) Network() string {
	return Network
}

// Implements net.Addr.
func (a *addr) String() string {
	return a.id.Pretty()
}

// Dial opens a libp2p stream to the destination peer.
func Dial(ctx context.Context, host host.Host, protocolID protocol.ID, node *node.Node) (net.Conn, error) {
	peerID, err := PublicKeyToPeerID(node.P2P.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to determine peer ID for node %s: %w", node.ID, err)
	}

	stream, err := host.NewStream(ctx, peerID, protocolID)
	if err != nil {
		return nil, err
	}
	return &conn{stream}, nil
}

type listener struct {
	host       host.Host
	protocolID protocol.ID

	streamCh chan network.Stream
	stopCh   chan struct{}
}

// Implements net.Listener.
func (ln *listener) Accept() (net.Conn, error) {
	select {
	case s := <-ln.streamCh:
		return &conn{s}, nil
	case <-ln.stopCh:
		return nil, fmt.Errorf("listener is terminating")
	}
}

// Implements net.Listener.
func (ln *listener) Close() error {
	select {
	case <-ln.stopCh:
	default:
		close(ln.stopCh)
	}

	ln.host.RemoveStreamHandler(ln.protocolID)
	return nil
}

// Implements net.Listener.
func (ln *listener) Addr() net.Addr {
	return &addr{ln.host.ID()}
}

// Listen provides a net.Listener wrapper that is backed by incoming libp2p streams.
func Listen(host host.Host, protocolID protocol.ID) (net.Listener, error) {
	ln := &listener{
		host:       host,
		protocolID: protocolID,
		streamCh:   make(chan network.Stream),
		stopCh:     make(chan struct{}),
	}

	host.SetStreamHandler(protocolID, func(s network.Stream) {
		select {
		case ln.streamCh <- s:
		case <-ln.stopCh:
			s.Reset()
		}
	})

	return ln, nil
}
