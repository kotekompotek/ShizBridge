// Package fwd implements the local ADB forward: it accepts plain TCP on the
// PC and relays each connection through a pinned TLS tunnel to the phone-side
// ShizBridge server, which proxies bytes to adbd.
package fwd

import (
	"context"
	"encoding/hex"
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

	// PauseAfterSilent closes the local listener after this many consecutive
	// sessions where TLS succeeded but the phone sent zero bytes back
	// (classic symptom: mini-adbd / Shizuku UserService dead on the phone
	// while the TLS server is still up). 0 disables the breaker.
	PauseAfterSilent int
	// PauseFor is how long the listener stays closed before re-arming.
	PauseFor time.Duration
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

	var connSeq atomic.Int64
	var silent atomic.Int64   // consecutive TLS-ok sessions where phone said nothing
	var pauseUntil atomic.Int64 // unix nano; 0 = not paused

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return stats, nil
			}
			return stats, err
		}

		// Circuit breaker: phone TLS is alive but mini-adbd is dead —
		// refuse the local client instead of hammering the phone and
		// flooding the log (and whoever is tailing it) forever.
		if until := pauseUntil.Load(); until > 0 && time.Now().UnixNano() < until {
			_ = local.Close()
			continue
		}
		if until := pauseUntil.Load(); until > 0 {
			pauseUntil.Store(0)
			silent.Store(0)
			opt.Logf("[..] pause over — re-arming accepts")
		}

		stats.Conns.Add(1)
		id := connSeq.Add(1)
		go func() {
			t0 := time.Now()
			remote, err := tlsclient.Dial(opt.ServerAddr, opt.Identity, opt.Pin, opt.DialTimeout)
			if err != nil {
				dialError(err)
				_ = local.Close()
				return
			}
			mu.Lock()
			lastErr = ""
			mu.Unlock()
			streak := silent.Load()
			// Verbose per-conn logs only while healthy or on the first
			// failures — a silent-storm used to write 3 lines × 6k conns.
			verbose := streak < 3
			if verbose {
				opt.Logf("[conn] #%d established in %s (%d total)", id, time.Since(t0).Round(time.Millisecond), stats.Conns.Load())
			}
			down, up := pipeBoth(local, remote, stats, opt.Logf, id, verbose)
			if down == 0 && up > 0 {
				// Client spoke (ADB CNXN), phone closed with nothing back.
				n := silent.Add(1)
				if opt.PauseAfterSilent > 0 {
					switch {
					case n == 1:
						opt.Logf("[warn] phone closed ADB session without reply — mini-adbd/Shizuku UserService may be down on the phone")
					case n == int64(opt.PauseAfterSilent):
						pauseUntil.Store(time.Now().Add(opt.PauseFor).UnixNano())
						silent.Store(0)
						opt.Logf("[err] %d consecutive silent ADB sessions — pausing accepts for %s; fix Shizuku/ShizBridge app on the phone (open app → Connect Shizuku → Start server)", opt.PauseAfterSilent, opt.PauseFor.Round(time.Second))
					}
				}
			} else if down > 0 {
				silent.Store(0)
			}
		}()
	}
}

// pipeBoth copies in both directions and closes both ends when done.
// When verbose is true it logs, per connection, the first bytes seen in
// each direction; silent-storm connections skip that to keep the log small.
// Returns bytes copied phone→local and local→phone.
func pipeBoth(a, b net.Conn, stats *Stats, logf func(string, ...any), id int64, verbose bool) (nDn, nUp int64) {
	var (
		peekUp, peekDn []byte
		errUp, errDn   error
	)
	peek := func(dst *[]byte) io.Writer {
		return peekFunc(func(p []byte) {
			if room := 48 - len(*dst); room > 0 {
				if len(p) < room {
					*dst = append(*dst, p...)
				} else {
					*dst = append(*dst, p[:room]...)
				}
			}
		})
	}
	done := make(chan struct{}, 2)
	go func() { // upstream: local client -> phone
		nUp, errUp = copyHalf(b, io.TeeReader(a, peek(&peekUp)))
		stats.BytesUp.Add(nUp)
		if verbose {
			logf("[u#%d] local->phone %dB err=%v peek=%s", id, nUp, errUp, hex.EncodeToString(peekUp))
		}
		done <- struct{}{}
	}()
	go func() { // downstream: phone -> local client
		nDn, errDn = copyHalf(a, io.TeeReader(b, peek(&peekDn)))
		stats.BytesDn.Add(nDn)
		if verbose {
			logf("[d#%d] phone->local %dB err=%v peek=%s", id, nDn, errDn, hex.EncodeToString(peekDn))
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
	return nDn, nUp
}

type peekFunc func(p []byte)

func (f peekFunc) Write(p []byte) (int, error) { f(p); return len(p), nil }

type closeWriter interface{ CloseWrite() error }

// copyHalf copies src→dst and half-closes dst when supported (adbd waits for
// FIN on stdin/stdout streams), returning bytes copied.
func copyHalf(dst net.Conn, src io.Reader) (int64, error) {
	n, err := io.Copy(dst, src)
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	return n, err
}
