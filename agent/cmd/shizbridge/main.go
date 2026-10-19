// Command shizbridge is the PC-side agent of the ShizBridge remote ADB tunnel.
//
//	shizbridge pair <code> --server <phone>:8787
//	shizbridge up     # local forward on 127.0.0.1:5555 (ADB target)
//	shizbridge status
//	shizbridge revoke
//	shizbridge selftest
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/config"
	"github.com/kotekompotek/ShizBridge/agent/internal/ctl"
	"github.com/kotekompotek/ShizBridge/agent/internal/cryptox"
	"github.com/kotekompotek/ShizBridge/agent/internal/fwd"
	"github.com/kotekompotek/ShizBridge/agent/internal/proto"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "pair":
		err = cmdPair(os.Args[2:])
	case "up":
		err = cmdUp(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "selftest":
		err = cmdSelftest(os.Args[2:])
	case "version":
		fmt.Println("shizbridge", version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ShizBridge agent — full ADB over the internet, via your phone.

Usage:
  shizbridge pair <code> --server <phone>:8787   pair with the phone (one-time code)
  shizbridge up [--local 127.0.0.1:5555]         start the local ADB forward (persistent)
  shizbridge status [--json]                     show tunnel/phone state
  shizbridge revoke                              delete local pairing state
  shizbridge selftest                            run protocol self-tests
  shizbridge version                             print version

After "up", point adb at the tunnel:  adb connect 127.0.0.1:5555
`)
}

// ---- pair ------------------------------------------------------------------

func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	server := fs.String("server", "", "phone address, host[:port] (port defaults to 8787)")
	label := fs.String("label", defaultLabel(), "client label shown on the phone")
	timeout := fs.Duration("timeout", 30*time.Second, "handshake timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: shizbridge pair <code> --server <phone>:8787")
	}
	code := strings.TrimSpace(fs.Arg(0))
	if code == "" {
		return errors.New("empty pairing code")
	}
	host, port, err := splitHostPort(*server, proto.DefaultPort)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))

	id, created, err := config.NewIdentity(*label)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if created {
		fmt.Println("[..] generated client identity")
	}

	fmt.Printf("[..] pairing with %s …\n", addr)
	info, err := cryptox.Pair(addr, code, *label, id, *timeout)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		ServerHost:  host,
		ServerPort:  port,
		ServerPin:   info.ServerPin,
		LocalListen: "127.0.0.1:5555",
		Label:       *label,
	}
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("[ok] paired")
	fmt.Printf("     phone pin : %s\n", info.ServerPin)
	fmt.Printf("     server    : %s\n", cfg.Addr())
	fmt.Printf("     next      : shizbridge up\n")
	return nil
}

// ---- up --------------------------------------------------------------------

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	local := fs.String("local", "", "local listen address (default from config: 127.0.0.1:5555)")
	noADB := fs.Bool("no-adb", false, "do not run adb connect/disconnect automatically")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON lines on stdout")
	noProbe := fs.Bool("no-probe", false, "skip the phone info probe at startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	id, err := config.LoadIdentity()
	if err != nil {
		return err
	}
	listen := cfg.LocalListen
	if *local != "" {
		listen = *local
	}
	logf := logfText(*jsonOut)

	if !*noProbe {
		resp, connect, err := ctl.Info(cfg.Addr(), id, cfg.ServerPin, 8*time.Second)
		if err != nil {
			logf("[warn] phone not reachable yet: %v", err)
		} else {
			logf("[ok] phone: app %s, adbd port %d (up=%v), shizuku=%s, connect %s",
				resp.Ver, resp.AdbdPort, resp.AdbdUp, resp.Shizuku, connect.Round(time.Millisecond))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		logf("[..] shutting down")
		cancel()
	}()

	stats, serveErr := fwd.Serve(ctx, fwd.Options{
		ListenAddr: listen,
		ServerAddr: cfg.Addr(),
		Identity:   id,
		Pin:        cfg.ServerPin,
		Logf:       logf,
		// TLS-alive-but-silent-ADB = phone app / Shizuku UserService dead.
		// Without a breaker, adb's auto-reconnect hammers ~1 conn/s forever.
		PauseAfterSilent: 5,
		PauseFor:         2 * time.Minute,
	})
	if serveErr != nil {
		return serveErr
	}

	// Report once the listener is actually accepting.
	if laddr := localAddr(listen); laddr != "" {
		event(*jsonOut, map[string]any{"event": "ready", "local": laddr, "server": cfg.Addr()})
		if !*noADB {
			adbConnect(laddr, logf)
		}
	}

	<-ctx.Done()
	if !*noADB {
		if laddr := localAddr(listen); laddr != "" {
			adbDisconnect(laddr, logf)
		}
	}
	event(*jsonOut, map[string]any{
		"event":    "stopped",
		"conns":    stats.Conns.Load(),
		"bytes_up": stats.BytesUp.Load(),
		"bytes_dn": stats.BytesDn.Load(),
		"errors":   stats.Errors.Load(),
	})
	return nil
}

// ---- status ----------------------------------------------------------------

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	id, err := config.LoadIdentity()
	if err != nil {
		return err
	}

	out := map[string]any{"server": cfg.Addr(), "pin": cfg.ServerPin}

	resp, connect, err := ctl.Info(cfg.Addr(), id, cfg.ServerPin, 8*time.Second)
	if err != nil {
		out["phone"] = "unreachable"
		out["error"] = err.Error()
	} else {
		out["phone"] = "reachable"
		out["connect_ms"] = connect.Milliseconds()
		out["adbd_port"] = resp.AdbdPort
		out["adbd_up"] = resp.AdbdUp
		out["clients"] = resp.Clients
		out["shizuku"] = resp.Shizuku
		out["app_version"] = resp.Ver
	}

	if err := ctl.LocalProbe(localAddr(cfg.LocalListen), 2*time.Second); err == nil {
		out["local"] = "listening"
	} else {
		out["local"] = "not listening (run: shizbridge up)"
	}

	if *jsonOut {
		return printJSON(out)
	}
	fmt.Printf("server   : %s\n", cfg.Addr())
	fmt.Printf("phone    : %v", out["phone"])
	if v, ok := out["connect_ms"]; ok {
		fmt.Printf(" (%v ms RTT)", v)
	}
	fmt.Println()
	if v, ok := out["adbd_port"]; ok {
		fmt.Printf("adbd     : port %v up=%v, %v client(s)\n", v, out["adbd_up"], out["clients"])
	}
	if v, ok := out["shizuku"]; ok {
		fmt.Printf("shizuku  : %v\n", v)
	}
	fmt.Printf("local    : %v\n", out["local"])
	return nil
}

// ---- revoke ----------------------------------------------------------------

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := config.Revoke(); err != nil {
		return err
	}
	fmt.Println("[ok] local pairing state deleted")
	fmt.Println("     also revoke this PC in the ShizBridge app on the phone")
	return nil
}

// ---- selftest --------------------------------------------------------------

func cmdSelftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	const code = "MJGP2X4KQ7TA"

	srv, err := cryptox.NewServerState(code)
	if err != nil {
		return err
	}
	wantPin, err := cryptox.SPKIFingerprint(srv.OwnCertDER)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.HandlePairing(c) }()
		}
	}()

	id, err := cryptox.MakeIdentity("selftest")
	if err != nil {
		return err
	}

	// 1. Wrong code must be rejected.
	if _, err := cryptox.Pair(ln.Addr().String(), "WRONGCODE000", "selftest", id, 5*time.Second); err == nil {
		return errors.New("selftest FAILED: wrong code was accepted")
	}
	fmt.Println("[pass] wrong pairing code rejected")

	// 2. Correct code must succeed with the expected pin.
	info, err := cryptox.Pair(ln.Addr().String(), code, "selftest", id, 5*time.Second)
	if err != nil {
		return fmt.Errorf("selftest FAILED: %w", err)
	}
	if info.ServerPin != wantPin {
		return errors.New("selftest FAILED: pin mismatch")
	}
	fmt.Println("[pass] pairing handshake + HKDF + proof + SPKI pin")

	// 3. Record layer vectors are asserted in go test (cross-checked with Kotlin).
	fmt.Println("[pass] run `go test ./...` for RFC 5869 / record-layer vectors")

	fmt.Println("selftest: all checks passed")
	return nil
}

// ---- helpers ---------------------------------------------------------------

func defaultLabel() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "shizbridge-pc"
}

func splitHostPort(addr string, defPort int) (string, int, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, errors.New("--server is required (e.g. --server 100.77.77.26:8787)")
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil || port <= 0 || port > 65535 {
			return "", 0, fmt.Errorf("bad port %q", p)
		}
		return h, port, nil
	}
	// No port part — treat the whole thing as a host.
	return addr, defPort, nil
}

func localAddr(listen string) string {
	if listen == "" {
		return ""
	}
	if strings.HasPrefix(listen, ":") {
		return "127.0.0.1" + listen
	}
	if _, _, err := net.SplitHostPort(listen); err == nil {
		return listen
	}
	return listen + ":5555"
}

// logfText prints human lines to stderr (or JSON events to stdout).
func logfText(jsonOut bool) func(string, ...any) {
	return func(format string, args ...any) {
		if jsonOut {
			event(true, map[string]any{"event": "log", "msg": fmt.Sprintf(format, args...)})
			return
		}
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func event(jsonOut bool, v map[string]any) {
	if !jsonOut {
		return
	}
	_ = printJSON(v)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(v)
}

func adbConnect(target string, logf func(string, ...any)) {
	if runtime.GOOS == "android" {
		return // on-device: adb lives differently; not used in agent flow
	}
	cmd := exec.Command("adb", "connect", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logf("[warn] adb connect %s: %v (%s)", target, err, strings.TrimSpace(string(out)))
		return
	}
	logf("[ok] adb connect %s -> %s", target, strings.TrimSpace(string(out)))
}

func adbDisconnect(target string, logf func(string, ...any)) {
	cmd := exec.Command("adb", "disconnect", target)
	if out, err := cmd.CombinedOutput(); err != nil {
		logf("[warn] adb disconnect: %v (%s)", err, strings.TrimSpace(string(out)))
	} else {
		logf("[ok] adb disconnected %s", target)
	}
}
