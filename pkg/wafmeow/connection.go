package wafmeow

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// rejectedWrite is immutable after publication to the connection's writer.
type rejectedWrite struct{ err error }

// guardedConn prevents a rejected retry from reaching the wire even if the
// transport selects an idle connection after GetConn cancels the request.
// The transport still owns connection closure; trace hooks never close it.
type guardedConn struct {
	net.Conn
	rejected atomic.Pointer[rejectedWrite]
	owner    *ownedConnections
}

func (c *guardedConn) Write(p []byte) (int, error) {
	if rejected := c.rejected.Load(); rejected != nil {
		return 0, rejected.err
	}
	return c.Conn.Write(p)
}

// rejectConnectionWrite runs in GotConn, before HTTP/1 can enqueue its write.
// Rejection is permanent: the transport retires the connection after the failed
// write or cancellation. TLS (including TLS through an HTTPS proxy) may wrap the
// guarded socket; leave its handshake and connection-state reporting intact.
func rejectConnectionWrite(conn net.Conn, cause error) {
	if cause == nil {
		return
	}
	for {
		switch c := conn.(type) {
		case *guardedConn:
			c.rejected.CompareAndSwap(nil, &rejectedWrite{cause})
			return
		case *tls.Conn:
			conn = c.NetConn()
		default:
			return
		}
	}
}

func (c *guardedConn) Close() error {
	if c.owner != nil {
		c.owner.forget(c)
	}
	return c.Conn.Close()
}

// ownedConnections tracks the raw sockets of a run-owned transport so that
// shutdown can be bounded. Go's transport closes idle connections serially,
// and each TLS close_notify write gets a fresh five-second deadline, so a peer
// that stops reading can otherwise stall Run for seconds per idle connection
// after every result was emitted.
type ownedConnections struct {
	mu     sync.Mutex
	conns  map[*guardedConn]struct{}
	closed bool
}

func newOwnedConnections() *ownedConnections {
	return &ownedConnections{conns: make(map[*guardedConn]struct{})}
}

// track reports whether the connection may still be used. Once shutdown has
// sealed the set, a late dial must not become usable again.
func (o *ownedConnections) track(conn *guardedConn) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return false
	}
	o.conns[conn] = struct{}{}
	return true
}

func (o *ownedConnections) forget(conn *guardedConn) {
	o.mu.Lock()
	delete(o.conns, conn)
	o.mu.Unlock()
}

// closeAll closes the raw sockets, unblocking any in-progress TLS alert write.
// Later dials are refused by track rather than left open.
func (o *ownedConnections) closeAll() {
	o.mu.Lock()
	o.closed = true
	conns := make([]net.Conn, 0, len(o.conns))
	for conn := range o.conns {
		conns = append(conns, conn.Conn)
	}
	clear(o.conns)
	o.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// ownedTransportCloseGrace bounds graceful shutdown of run-owned connections.
const ownedTransportCloseGrace = 250 * time.Millisecond

// closeOwnedTransport attempts a graceful close, then force-closes any remaining
// tracked sockets and refuses late dials on every exit path. The grace period
// bounds the wait before forcing closure; the CloseIdleConnections call is joined.
func closeOwnedTransport(ctx context.Context, transport *http.Transport, owned *ownedConnections) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		transport.CloseIdleConnections()
	}()
	timer := time.NewTimer(ownedTransportCloseGrace)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-ctx.Done():
	}
	// A completed idle-pool close does not imply that every socket is closed:
	// dials and transport-initiated closes can still be in progress. Seal the
	// tracker even on the fast path, closing stragglers and rejecting late dials.
	if owned != nil {
		owned.closeAll()
	}
	<-done
}

// guardOwnedConnections keeps the configured dialer's behavior and adds a
// write barrier below the transport's TLS layer. A custom TLS dialer hides that
// socket and must retain fresh connections rather than allow unguarded retries.
func guardOwnedConnections(transport *http.Transport, owned *ownedConnections) {
	if transport.DialTLSContext != nil || transport.DialTLS != nil {
		transport.DisableKeepAlives = true
		return
	}
	dialContext, dial := transport.DialContext, transport.Dial
	var defaultDialer net.Dialer
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn
		var err error
		switch {
		case dialContext != nil:
			conn, err = dialContext(ctx, network, addr)
		case dial != nil:
			conn, err = dial(network, addr)
		default:
			conn, err = defaultDialer.DialContext(ctx, network, addr)
		}
		if err != nil || conn == nil {
			return conn, err
		}
		guarded := &guardedConn{Conn: conn, owner: owned}
		if owned != nil && !owned.track(guarded) {
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		return guarded, nil
	}
}
