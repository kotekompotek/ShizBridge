package cryptox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// HKDFSHA256 implements RFC 5869 HKDF-Extract + HKDF-Expand with SHA-256.
func HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*sha256.Size {
		return nil, fmt.Errorf("hkdf: invalid length %d", length)
	}
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	// Extract
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(ikm)
	prk := extractor.Sum(nil)
	// Expand
	var (
		t        []byte
		okm      []byte
		counter  byte = 1
		expander        = hmac.New(sha256.New, prk)
	)
	for len(okm) < length {
		expander.Reset()
		if t != nil {
			expander.Write(t)
		}
		expander.Write(info)
		expander.Write([]byte{counter})
		t = expander.Sum(nil)
		okm = append(okm, t...)
		counter++
	}
	return okm[:length], nil
}

// HMACSHA256 returns HMAC-SHA256(key, msg).
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// ProofLabel is the domain-separation prefix of the pairing code proof.
const ProofLabel = "ShizBridge code proof"

// CodeProof computes HMAC-SHA256(sessionKey, ProofLabel || code).
func CodeProof(sessionKey []byte, code string) []byte {
	return HMACSHA256(sessionKey, append([]byte(ProofLabel), code...))
}

// Record direction markers for AES-GCM nonces.
const (
	DirC2S byte = 0x01
	DirS2C byte = 0x02
)

// Record is an AES-256-GCM record layer with a direction-bound counter nonce.
// nonce = dir || counter_be_u64 || 0x000000
type Record struct {
	key []byte
	dir byte
	ctr uint64
}

// NewRecord creates a record layer for the given direction.
func NewRecord(key []byte, dir byte) *Record {
	if len(key) != 32 {
		panic("cryptox: record key must be 32 bytes")
	}
	return &Record{key: append([]byte(nil), key...), dir: dir}
}

func (r *Record) nonce() []byte {
	n := make([]byte, 12)
	n[0] = r.dir
	binary.BigEndian.PutUint64(n[1:], r.ctr)
	r.ctr++
	return n
}

// Seal encrypts plaintext, incrementing the counter.
func (r *Record) Seal(plain []byte) ([]byte, error) {
	gcm, err := newGCM(r.key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, r.nonce(), plain, nil), nil
}

// Open decrypts ciphertext, incrementing the counter.
func (r *Record) Open(ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(r.key)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, r.nonce(), ciphertext, nil)
	if err != nil {
		return nil, errors.New("cryptox: record authentication failed")
	}
	return plain, nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader(), b); err != nil {
		return nil, err
	}
	return b, nil
}
