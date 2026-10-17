// Package fwd implements the local ADB forward: it accepts plain TCP on the
// PC and relays each connection through a pinned TLS tunnel to the phone-side
// ShizBridge server, which proxies bytes to adbd.
package fwd

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/cryptox"
	"github.com/kotekompotek/ShizBridge/agent/internal/tlsclient"
)

// Options configures the forwarder.
type Options struct {
	ListenAddr  string // e.g. "127.0.0.1:5555"
	ServerAddr  string // e.g. "phone:8787"
	Identity    *cryptox.Identity
	Pin         string
	Logf        func(format string, args ...any)
	DialTimeout time.Duration
	RedialDelay time.Duration
}

// Stats tracks tunnel counters.
type Stats struct {
	Conns   atomic.Int64
	BytesUp atomic.Int64
	BytesDn atomic.Int64
	Errors  atomic.Int64
}

// Serve runs the local listener until ctx is cancelled or the listener fails.
// Each accepted connection is dialed independently over mTLS, so phone-side
// outages degrade per-connection instead of killing the listener.
func Serve(ctx context.Context, opt Options) (*Stats, error) {
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 10 * time.Second
	}

	ln, err := net.Listen("tcp", opt.ListenAddr)
	if err != nil {
		return nil, err
	}
	stats := &Stats{}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	opt.Logf("[ok] local listener on %s -> %s (tls, pinned)", ln.Addr(), opt.ServerAddr)

	var (
		mu      sync.Mutex
		lastErr string
	)
	dialError := func(err error) {
		stats.Errors.Add(1)
		mu.Lock()
		defer mu.Unlock()
		if msg := err.Error(); msg != lastErr {
			lastErr = msg
			opt.Logf("[err] phone unreachable: %v", err)
		}
	}

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return stats, nil
			}
			return stats, err
		}
		stats.Conns.Add(1)
		go func() {
			remote, err := tlsclient.Dial(opt.ServerAddr, opt.Identity, opt.Pin, opt.DialTimeout)
			if err != nil {
				dialError(err)
				_ = local.Close()
				return
			}
			mu.Lock()
			lastErr = ""
			mu.Unlock()
			opt.Logf("[conn] tunnel established (%d total)", stats.Conns.Load())
			pipeBoth(local, remote, stats)
		}()
	}
}

// pipeBoth copies in both directions and closes both ends when done.
func pipeBoth(a, b net.Conn, stats *Stats) {
	done := make(chan struct{}, 2)
	go func() { // upstream: local client -> phone
		n, _ := copyHalf(b, a)
		stats.BytesUp.Add(n)
		done <- struct{}{}
	}()
	go func() { // downstream: phone -> local client
		n, _ := copyHalf(a, b)
		stats.BytesDn.Add(n)
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

type closeWriter interface{ CloseWrite() error }

// copyHalf copies src→dst and half-closes dst when supported (adbd waits for
// FIN on stdin/stdout streams), returning bytes copied.
func copyHalf(dst, src net.Conn) (int64, error) {
	n, err := io.Copy(dst, src)
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	return n, err
}
