package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/grepplabs/kafka-proxy/config"
	"github.com/stretchr/testify/assert"
)

// newDrainTestClient builds a minimal Client usable for exercising drain().
func newDrainTestClient(grace time.Duration) *Client {
	cfg := &config.Config{}
	cfg.Proxy.ShutdownGracePeriod = grace
	return &Client{conns: NewConnSet(), config: cfg}
}

// addBlockedConn registers a connection that only unblocks when it is closed,
// simulating an idle-but-open client that must be force-closed.
func addBlockedConn(cl *Client) {
	_, server := net.Pipe()
	cl.conns.Add("broker", server)
	cl.connWg.Add(1)
	go func() {
		defer cl.connWg.Done()
		buf := make([]byte, 1)
		_, _ = server.Read(buf) // returns once drain force-closes the conn
	}()
}

// With a grace period, an idle connection that never closes on its own must be
// force-closed only after the grace period elapses.
func TestClientDrainForceClosesAfterGracePeriod(t *testing.T) {
	cl := newDrainTestClient(150 * time.Millisecond)
	addBlockedConn(cl)

	start := time.Now()
	cl.drain()
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 150*time.Millisecond, "drain must wait the full grace period before force-closing")
	assert.Less(t, elapsed, 5*time.Second, "drain must return shortly after the grace period")
}

// If all connections close on their own, drain must return early rather than
// waiting out the whole grace period.
func TestClientDrainCompletesBeforeGracePeriod(t *testing.T) {
	cl := newDrainTestClient(10 * time.Second)
	cl.connWg.Add(1)
	go func() {
		defer cl.connWg.Done()
		time.Sleep(50 * time.Millisecond) // connection closes on its own
	}()

	start := time.Now()
	cl.drain()
	assert.Less(t, time.Since(start), 2*time.Second, "drain must complete as soon as connections are gone")
}

// With grace period 0 (default), drain keeps the previous behaviour of closing
// connections immediately.
func TestClientDrainImmediateWhenGraceZero(t *testing.T) {
	cl := newDrainTestClient(0)
	addBlockedConn(cl)

	done := make(chan struct{})
	go func() {
		cl.drain()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain with grace 0 should return promptly")
	}
}

// Listeners.Close must stop the listening socket so that no new connections are
// accepted, while leaving already-open connections untouched.
func TestListenersCloseStopsAccepting(t *testing.T) {
	cfg := &config.Config{}
	cfg.Proxy.DefaultListenerIP = "127.0.0.1"
	cfg.Proxy.BootstrapServers = []config.ListenerConfig{
		{BrokerAddress: "127.0.0.1:19092", ListenerAddress: "127.0.0.1:0", AdvertisedAddress: "127.0.0.1:0"},
	}
	listeners, err := NewListeners(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = listeners.ListenInstances(cfg.Proxy.BootstrapServers); err != nil {
		t.Fatal(err)
	}

	addr := listeners.openListeners[0].Addr().String()

	// Before Close: the listener accepts connections.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("expected to connect before Close: %v", err)
	}
	_ = conn.Close()

	listeners.Close()

	// After Close: dialing the same address must fail.
	if c2, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c2.Close()
		t.Fatal("expected dial to fail after listeners are closed")
	}

	// Close must be idempotent.
	listeners.Close()
}
