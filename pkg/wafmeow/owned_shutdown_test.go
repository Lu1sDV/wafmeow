package wafmeow

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func assertOwnedConnectionsClosed(t *testing.T, owned *ownedConnections) {
	t.Helper()
	owned.mu.Lock()
	closed, remaining := owned.closed, len(owned.conns)
	owned.mu.Unlock()
	if !closed || remaining != 0 {
		t.Errorf("shutdown left tracker closed=%v with %d connections", closed, remaining)
	}
}

func assertOwnedPeerClosed(t *testing.T, peer net.Conn) {
	t.Helper()
	// A deadline makes a missed close fail rather than hang the test.
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, err := peer.Read(buf[:]); !errors.Is(err, io.EOF) {
		t.Errorf("peer read = %v, want EOF from closed socket", err)
	}
}

func TestCloseOwnedTransportSealsGracefulShutdown(t *testing.T) {
	owned := newOwnedConnections()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &guardedConn{Conn: client, owner: owned}
	if !owned.track(conn) {
		t.Fatal("live connection was refused")
	}
	// A dial or a TLS close can still own a socket that is not in the idle
	// pool. CloseIdleConnections returns immediately, but it is not enough.
	closeOwnedTransport(context.Background(), &http.Transport{}, owned)
	assertOwnedConnectionsClosed(t, owned)
	assertOwnedPeerClosed(t, server)
	if owned.track(conn) {
		t.Error("graceful shutdown accepted another connection")
	}
}

func TestCloseOwnedTransportRejectsLateDial(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "DialContext"
		if legacy {
			name = "Dial"
		}
		t.Run(name, func(t *testing.T) {
			owned := newOwnedConnections()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseDial := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseDial()
			dial := func() (net.Conn, error) {
				close(started)
				<-release
				return client, nil
			}
			transport := &http.Transport{}
			if legacy {
				transport.Dial = func(string, string) (net.Conn, error) { return dial() }
			} else {
				// Model successful completion racing cancellation. The socket
				// must be rejected even if the dialer returns it after shutdown.
				transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return dial() }
			}
			guardOwnedConnections(transport, owned)
			defer transport.CloseIdleConnections()
			type dialResult struct {
				conn net.Conn
				err  error
			}
			dialDone := make(chan dialResult, 1)
			guardedDial := transport.DialContext
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := guardedDial(ctx, network, addr)
				dialDone <- dialResult{conn, err}
				return conn, err
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://late.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			requestDone := make(chan error, 1)
			go func() {
				response, err := transport.RoundTrip(req)
				if response != nil {
					response.Body.Close()
				}
				requestDone <- err
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not start dialing")
			}
			cancel()
			select {
			case err := <-requestDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("RoundTrip returned %v, want cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("request did not return while its dial was pending")
			}
			// The request has ended, while the caller's run context is live.
			// Only release the dial after the fast shutdown path has returned.
			closeOwnedTransport(context.Background(), transport, owned)
			releaseDial()
			select {
			case result := <-dialDone:
				if result.conn != nil || !errors.Is(result.err, net.ErrClosed) {
					t.Errorf("late dial returned (%T, %v), want (nil, net.ErrClosed)", result.conn, result.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("released dial did not return")
			}
			assertOwnedConnectionsClosed(t, owned)
			assertOwnedPeerClosed(t, server)
		})
	}
}

func TestCloseOwnedTransportSealsCancelledShutdown(t *testing.T) {
	// Both the cancellation and the fast graceful-close case can be ready.
	// Either select branch must leave the same terminal ownership state.
	for range 32 {
		owned := newOwnedConnections()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		closeOwnedTransport(ctx, &http.Transport{}, owned)
		assertOwnedConnectionsClosed(t, owned)
	}
}

func TestOwnedConnectionsConcurrentShutdown(t *testing.T) {
	owned := newOwnedConnections()
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 32 {
		client, server := net.Pipe()
		defer server.Close()
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			conn := &guardedConn{Conn: client, owner: owned}
			if owned.track(conn) {
				_ = conn.Close()
			} else {
				_ = client.Close()
			}
		}()
	}
	close(start)
	closeOwnedTransport(context.Background(), &http.Transport{}, owned)
	workers.Wait()
	assertOwnedConnectionsClosed(t, owned)
}
