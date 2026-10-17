// Package tlsclient dials the phone-side ShizBridge server with pinned mTLS.
package tlsclient

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/cryptox"
)

// Dial opens a TLS connection to addr, presenting the local identity and
// verifying the server certificate against the SPKI-SHA256 pin captured
// during pairing. Chain validation is intentionally skipped: trust is pin-based.
func Dial(addr string, id *cryptox.Identity, pin string, timeout time.Duration) (net.Conn, error) {
	cert, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // verified via pin in VerifyConnection
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tls: server sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			got := hex.EncodeToString(sum[:])
			if got != pin {
				return fmt.Errorf("tls: server pin mismatch (got %s, want %s)", got, pin)
			}
			return nil
		},
	}
	d := &net.Dialer{Timeout: timeout}
	td := tls.Dialer{NetDialer: d, Config: cfg}
	conn, err := td.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if t, ok := conn.(*tls.Conn); ok {
		_ = t.SetDeadline(time.Time{})
	}
	return conn, nil
}
