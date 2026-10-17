package cryptox

import (
	"bufio"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/proto"
)

// ServerState is a reference implementation of the phone-side pairing
// handler. It mirrors android/app/.../core/PairingServer.kt and is used by
// the `shizbridge selftest` command and unit tests.
type ServerState struct {
	Code        string
	Attempts    int
	MaxAttempts int
	LockedUntil time.Time
	OwnCertDER  []byte
	Enrolled    map[string]string // SPKI-SHA256 -> label

	certPEM []byte
	keyPEM  []byte
	tlsCfg  *tls.Config
}

// NewServerState creates pairing state with a fresh server identity.
func NewServerState(code string) (*ServerState, error) {
	der, certPEM, keyPEM, err := MakeSelfSigned("ShizBridge-reference")
	if err != nil {
		return nil, err
	}
	id := &Identity{CertDER: der, CertPEM: certPEM, KeyPEM: keyPEM}
	return &ServerState{
		Code:        code,
		MaxAttempts: 3,
		OwnCertDER:  der,
		Enrolled:    map[string]string{},
		certPEM:     certPEM,
		keyPEM:      keyPEM,
		tlsCfg:      ServerTLSConfig(id),
	}, nil
}

// HandlePairing serves one pairing connection to completion (blocking).
// conn is a raw TCP socket: the TLS layer is established here, followed by
// the SBPR magic and the framed handshake.
func (s *ServerState) HandlePairing(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	tc := tls.Server(conn, s.tlsCfg)
	defer tc.Close()
	br := bufio.NewReader(tc)

	var magic [4]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	if string(magic[:]) != proto.PairMagic {
		return errors.New("bad pairing magic")
	}

	var hello proto.Hello
	if err := proto.ReadJSON(br, &hello); err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	if hello.T != "pair_hello" || hello.V != proto.ProtocolVersion {
		return errors.New("bad hello")
	}
	cpubRaw, err := decodeB64(hello.EphPub)
	if err != nil {
		return errors.New("bad client eph_pub")
	}
	cnonce, err := decodeB64(hello.Nonce)
	if err != nil || len(cnonce) != 16 {
		return errors.New("bad client nonce")
	}

	eph, err := ecdh.P256().GenerateKey(randReader())
	if err != nil {
		return err
	}
	snonce, err := RandomBytes(16)
	if err != nil {
		return err
	}
	sh := proto.Hello{
		T:      "pair_hello",
		V:      proto.ProtocolVersion,
		EphPub: encodeB64(eph.PublicKey().Bytes()),
		Nonce:  encodeB64(snonce),
		SrvCert: encodeB64(s.OwnCertDER),
	}
	if err := proto.WriteJSON(tc, &sh); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	cpub, err := ecdh.P256().NewPublicKey(cpubRaw)
	if err != nil {
		return fmt.Errorf("parse client ephemeral: %w", err)
	}
	shared, err := eph.ECDH(cpub)
	if err != nil {
		return err
	}
	salt := append(append([]byte(nil), cnonce...), snonce...)
	key, err := HKDFSHA256(shared, salt, []byte("ShizBridge pairing v1"), 32)
	if err != nil {
		return err
	}

	opener := NewRecord(key, DirC2S)
	sealer := NewRecord(key, DirS2C)

	sendResult := func(ok bool, reason string) error {
		res := proto.Result{T: "pair_result", OK: ok, Reason: reason}
		if ok {
			fp, err := SPKIFingerprint(s.OwnCertDER)
			if err != nil {
				return err
			}
			res.FP = fp
		}
		plain, err := json.Marshal(&res)
		if err != nil {
			return err
		}
		ct, err := sealer.Seal(plain)
		if err != nil {
			return err
		}
		return proto.WriteFrame(tc, ct)
	}

	if time.Now().Before(s.LockedUntil) {
		return sendResult(false, "locked")
	}

	ct, err := proto.ReadFrame(br)
	if err != nil {
		return fmt.Errorf("read auth: %w", err)
	}
	plain, err := opener.Open(ct)
	if err != nil {
		return errors.New("auth decrypt failed")
	}
	var auth proto.Auth
	if err := json.Unmarshal(plain, &auth); err != nil {
		return fmt.Errorf("parse auth: %w", err)
	}
	if auth.T != "pair_auth" {
		return errors.New("bad auth message")
	}

	cliDER, err := decodeB64(auth.CliCert)
	if err != nil {
		return errors.New("bad client cert")
	}
	proof, err := decodeB64(auth.Proof)
	if err != nil {
		return errors.New("bad proof")
	}

	s.Attempts++
	if !VerifyProof(key, s.Code, proof) {
		if s.Attempts >= s.MaxAttempts {
			s.LockedUntil = time.Now().Add(10 * time.Minute)
			return sendResult(false, "locked")
		}
		return sendResult(false, "bad_code")
	}

	spki, err := SPKIFingerprint(cliDER)
	if err != nil {
		return errors.New("client cert invalid")
	}
	label := auth.Label
	if label == "" {
		label = "unknown"
	}
	s.Enrolled[spki] = label
	return sendResult(true, "")
}
