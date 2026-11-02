package wafmeow

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func blockedTLSPeer(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "blocked.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"blocked.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveBlockedTLS completes one keep-alive HTTP/1 exchange and then stops
// reading, so the client's TLS close_notify alert is never drained. TLS 1.2
// keeps the synchronous net.Pipe handshake deterministic; the close path is
// independent of the negotiated version.
func serveBlockedTLS(conn net.Conn, cert tls.Certificate, stop <-chan struct{}) {
	defer conn.Close()
	server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12})
	request, err := http.ReadRequest(bufio.NewReader(server))
	if err != nil {
		return
	}
	_ = request.Body.Close()
	if _, err := io.WriteString(server, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"); err != nil {
		return
	}
	<-stop
}

func blockedTLSDialer(t *testing.T, cert tls.Certificate, dials *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	stop := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(stop) }) })
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		dials.Add(1)
		go serveBlockedTLS(server, cert, stop)
		return client, nil
	}
}

func useBlockedTLSTransport(t *testing.T, cert tls.Certificate) *atomic.Int32 {
	t.Helper()
	var dials atomic.Int32
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	http.DefaultTransport = &http.Transport{
		DialContext:     blockedTLSDialer(t, cert, &dials),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, // test fixture certificate
	}
	return &dials
}

func runBlockedTLS(t *testing.T, ctx context.Context) (Result, time.Time) {
	t.Helper()
	config := DefaultConfig()
	config.BaselineOnly = true
	var result Result
	var emittedAt time.Time
	err := Run(ctx, emptyEngine(t), strings.NewReader("https://blocked.test/\n"), config, func(value Result) error {
		result, emittedAt = value, time.Now()
		return nil
	})
	if err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].StatusCode != http.StatusNoContent {
		t.Fatalf("target did not complete before cleanup: %+v", result)
	}
	return result, emittedAt
}

func TestRunBoundsOwnedTLSCloseAfterResults(t *testing.T) {
	useBlockedTLSTransport(t, blockedTLSPeer(t))
	start := time.Now()
	_, emittedAt := runBlockedTLS(t, context.Background())
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("Run spent %v after the final result", waited)
	}
	if waited := time.Since(emittedAt); waited > 2*time.Second {
		t.Fatalf("Run returned %v after the final result", waited)
	}
}

func TestRunReportsDeadlineDuringOwnedTLSClose(t *testing.T) {
	useBlockedTLSTransport(t, blockedTLSPeer(t))
	// The deadline must expire while graceful shutdown is still in progress,
	// so the deferred cancellation check is what reports it.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	emitted := false
	err := func() error {
		config := DefaultConfig()
		config.BaselineOnly = true
		return Run(ctx, emptyEngine(t), strings.NewReader("https://blocked.test/\n"), config, func(Result) error {
			emitted = true
			return nil
		})
	}()
	if !emitted {
		t.Fatal("target result was not emitted before the deadline")
	}
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run returned %v after its deadline expired during cleanup", err)
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("Run spent %v returning after cancellation", waited)
	}
}

func TestRunBoundsOwnedTLSCloseAcrossConnections(t *testing.T) {
	dials := useBlockedTLSTransport(t, blockedTLSPeer(t))
	config := DefaultConfig()
	config.BaselineOnly = true
	config.Concurrency = 1
	var emitted int
	start := time.Now()
	// Distinct origins keep the connections separate without overlapping the
	// synchronous pipe handshakes.
	err := Run(context.Background(), emptyEngine(t), strings.NewReader("https://one.blocked.test/\nhttps://two.blocked.test/\nhttps://three.blocked.test/\n"), config, func(Result) error {
		emitted++
		return nil
	})
	if err != nil || emitted != 3 {
		t.Fatalf("Run emitted %d results: %v", emitted, err)
	}
	if dials.Load() < 3 {
		t.Fatalf("only %d connections exercised cleanup", dials.Load())
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("Run spent %v closing %d connections", waited, dials.Load())
	}
}
