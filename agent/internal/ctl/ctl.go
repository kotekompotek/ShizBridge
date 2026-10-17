// Package ctl implements the ShizBridge control channel: after the mTLS
// session is up, the client sends the magic "SBCTL" followed by framed JSON.
package ctl

import (
	"fmt"
	"net"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/cryptox"
	"github.com/kotekompotek/ShizBridge/agent/internal/proto"
	"github.com/kotekompotek/ShizBridge/agent/internal/tlsclient"
)

// Info dials the phone over pinned mTLS, performs the control handshake and
// returns the phone-side info plus the measured connect time.
func Info(server string, id *cryptox.Identity, pin string, timeout time.Duration) (*proto.InfoResp, time.Duration, error) {
	start := time.Now()
	conn, err := tlsclient.Dial(server, id, pin, timeout)
	if err != nil {
		return nil, 0, fmt.Errorf("connect: %w", err)
	}
	connect := time.Since(start)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte(proto.ControlMagic)); err != nil {
		return nil, connect, fmt.Errorf("control magic: %w", err)
	}
	if err := proto.WriteJSON(conn, proto.InfoReq{Op: "info"}); err != nil {
		return nil, connect, fmt.Errorf("info request: %w", err)
	}
	var resp proto.InfoResp
	if err := proto.ReadJSON(conn, &resp); err != nil {
		return nil, connect, fmt.Errorf("info response: %w", err)
	}
	if resp.Op != "info" {
		return nil, connect, fmt.Errorf("unexpected control reply %q", resp.Op)
	}
	return &resp, connect, nil
}

// Ping measures a control-channel round trip after connect.
func Ping(server string, id *cryptox.Identity, pin string, timeout time.Duration) (connect, rtt time.Duration, err error) {
	start := time.Now()
	conn, err := tlsclient.Dial(server, id, pin, timeout)
	if err != nil {
		return 0, 0, fmt.Errorf("connect: %w", err)
	}
	connect = time.Since(start)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte(proto.ControlMagic)); err != nil {
		return connect, 0, err
	}
	pingStart := time.Now()
	if err := proto.WriteJSON(conn, proto.Ping{Op: "ping"}); err != nil {
		return connect, 0, err
	}
	var pong proto.Pong
	if err := proto.ReadJSON(conn, &pong); err != nil {
		return connect, 0, err
	}
	if pong.Op != "pong" {
		return connect, 0, fmt.Errorf("unexpected reply %q", pong.Op)
	}
	return connect, time.Since(pingStart), nil
}

// LocalProbe checks whether a local port (e.g. the ADB forward) accepts TCP.
func LocalProbe(addr string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}
