package cryptox

import (
	"bufio"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/proto"
)

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Identity is the client's long-term self-signed identity used for mTLS.
type Identity struct {
	CertDER []byte
	CertPEM []byte
	KeyPEM  []byte
}

// MakeIdentity generates a fresh client identity.
func MakeIdentity(label string) (*Identity, error) {
	der, certPEM, keyPEM, err := MakeSelfSigned(label)
	if err != nil {
		return nil, err
	}
	return &Identity{CertDER: der, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// PairInfo is the result of a successful pairing handshake.
type PairInfo struct {
	// ServerPin is the SPKI-SHA256 pin of the phone's server certificate.
	ServerPin string
	// ServerCert is the DER of the phone's server certificate.
	ServerCert []byte
}

// Pair runs the client side of the ShizBridge pairing handshake (v1) against
// addr ("host:port"). code is the one-time pairing code shown on the phone,
// label is a human-readable client name. timeout bounds the whole handshake.
func Pair(addr, code, label string, id *Identity, timeout time.Duration) (*PairInfo, error) {
	dialer := &net.Dialer{Timeout: timeout}
	td := tls.Dialer{NetDialer: dialer, Config: UnverifiedClientConfig(id)}
	conn, err := td.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte(proto.PairMagic)); err != nil {
		return nil, fmt.Errorf("pair magic: %w", err)
	}

	br := bufio.NewReader(conn)

	// 1. Client hello (plaintext).
	eph, err := ecdh.P256().GenerateKey(randReader())
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	cnonce, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}
	hello := proto.Hello{
		T:      "pair_hello",
		V:      proto.ProtocolVersion,
		EphPub: encodeB64(eph.PublicKey().Bytes()),
		Nonce:  encodeB64(cnonce),
	}
	if err := proto.WriteJSON(conn, &hello); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	// 2. Server hello (plaintext).
	var sh proto.Hello
	if err := proto.ReadJSON(br, &sh); err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}
	if sh.T != "pair_hello" {
		return nil, fmt.Errorf("unexpected message %q", sh.T)
	}
	if sh.V != proto.ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d", sh.V)
	}
	snonce, err := decodeB64(sh.Nonce)
	if err != nil || len(snonce) != 16 {
		return nil, errors.New("bad server nonce")
	}
	spubRaw, err := decodeB64(sh.EphPub)
	if err != nil {
		return nil, errors.New("bad server eph_pub")
	}
	srvCertDER, err := decodeB64(sh.SrvCert)
	if err != nil || len(srvCertDER) == 0 {
		return nil, errors.New("bad server certificate")
	}

	// 3. Derive the session key.
	spub, err := ecdh.P256().NewPublicKey(spubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse server ephemeral: %w", err)
	}
	shared, err := eph.ECDH(spub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	salt := append(append([]byte(nil), cnonce...), snonce...)
	key, err := HKDFSHA256(shared, salt, []byte("ShizBridge pairing v1"), 32)
	if err != nil {
		return nil, err
	}

	sealer := NewRecord(key, DirC2S)
	opener := NewRecord(key, DirS2C)

	// 4. Encrypted pair_auth with the code proof.
	proof := CodeProof(key, code)
	auth := proto.Auth{
		T:       "pair_auth",
		Proof:   encodeB64(proof),
		CliCert: encodeB64(id.CertDER),
		Label:   label,
	}
	plain, err := json.Marshal(&auth)
	if err != nil {
		return nil, err
	}
	ct, err := sealer.Seal(plain)
	if err != nil {
		return nil, err
	}
	if err := proto.WriteFrame(conn, ct); err != nil {
		return nil, fmt.Errorf("send auth: %w", err)
	}

	// 5. Encrypted result.
	respCT, err := proto.ReadFrame(br)
	if err != nil {
		return nil, fmt.Errorf("read result: %w", err)
	}
	respPlain, err := opener.Open(respCT)
	if err != nil {
		return nil, fmt.Errorf("decrypt result: %w", err)
	}
	var res proto.Result
	if err := json.Unmarshal(respPlain, &res); err != nil {
		return nil, fmt.Errorf("parse result: %w", err)
	}
	if res.T != "pair_result" {
		return nil, fmt.Errorf("unexpected message %q", res.T)
	}
	if !res.OK {
		return nil, fmt.Errorf("pairing rejected: %s", res.Reason)
	}

	// 6. Consistency: fp must match the certificate we received.
	want, err := SPKIFingerprint(srvCertDER)
	if err != nil {
		return nil, err
	}
	if res.FP != want {
		return nil, errors.New("server fingerprint does not match certificate")
	}
	if _, err := x509.ParseCertificate(srvCertDER); err != nil {
		return nil, fmt.Errorf("server certificate invalid: %w", err)
	}
	return &PairInfo{ServerPin: res.FP, ServerCert: srvCertDER}, nil
}

// VerifyProof reports whether proof matches CodeProof(sessionKey, code).
func VerifyProof(sessionKey []byte, code string, proof []byte) bool {
	expected := CodeProof(sessionKey, code)
	return hmac.Equal(expected, proof)
}
