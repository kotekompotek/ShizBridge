// Package proto implements the ShizBridge wire format: length-prefixed
// JSON frames used by the pairing handshake and the control channel.
package proto

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// DefaultPort is the phone-side TCP port of the ShizBridge server.
	DefaultPort = 8787
	// MaxFrame is the maximum size of a single frame payload.
	MaxFrame = 65536
	// ControlMagic marks a control-channel connection (first 5 bytes).
	ControlMagic = "SBCTL"
	// PairMagic marks a pairing connection (first 4 bytes).
	PairMagic = "SBPR"
	// ProtocolVersion is the current pairing protocol version.
	ProtocolVersion = 1
)

// ErrFrameTooLarge is returned when an incoming frame exceeds MaxFrame.
var ErrFrameTooLarge = errors.New("proto: frame too large")

// WriteFrame writes a length-prefixed payload.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed payload.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteJSON marshals v and writes it as a frame.
func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFrame(w, b)
}

// ReadJSON reads one frame and unmarshals it into v.
func ReadJSON(r io.Reader, v any) error {
	b, err := ReadFrame(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// PeekMode inspects the first byte of an incoming connection and returns
// "tls" (data session) or "pair" (pairing handshake).
func PeekMode(br *bufio.Reader) (string, error) {
	b, err := br.Peek(1)
	if err != nil {
		return "", fmt.Errorf("proto: peek mode: %w", err)
	}
	if b[0] == 0x16 {
		return "tls", nil
	}
	return "pair", nil
}

// Pairing messages.

// Hello is the first message of the pairing handshake (both directions).
type Hello struct {
	T       string `json:"t"`
	V       int    `json:"v"`
	EphPub  string `json:"eph_pub"`
	Nonce   string `json:"nonce"`
	SrvCert string `json:"srv_cert,omitempty"`
}

// Auth is the encrypted client authentication message.
type Auth struct {
	T       string `json:"t"`
	Proof   string `json:"proof"`
	CliCert string `json:"cli_cert"`
	Label   string `json:"label"`
}

// Result is the encrypted server response of the pairing handshake.
type Result struct {
	T      string `json:"t"`
	OK     bool   `json:"ok"`
	FP     string `json:"fp,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Control channel messages.

// Ping is a control-channel liveness request.
type Ping struct {
	Op string `json:"op"`
}

// Pong is a control-channel liveness response.
type Pong struct {
	Op string `json:"op"`
	TS int64  `json:"ts"`
}

// InfoReq is a control-channel info request.
type InfoReq struct {
	Op string `json:"op"`
}

// InfoResp reports phone-side server state.
type InfoResp struct {
	Op       string `json:"op"`
	App      string `json:"app"`
	Proto    int    `json:"proto"`
	Ver      string `json:"ver"`
	AdbdPort int    `json:"adbd_port"`
	AdbdUp   bool   `json:"adbd_up"`
	Clients  int    `json:"clients"`
	Shizuku  string `json:"shizuku"`
}
