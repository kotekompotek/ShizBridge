package cryptox

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Test vectors shared with the Android implementation
// (android/app/src/test/resources/vectors.json must stay in sync).

type Vectors struct {
	Hkdf struct {
		IkmHex  string `json:"ikm_hex"`
		SaltHex string `json:"salt_hex"`
		Info    string `json:"info"`
		Length  int    `json:"length"`
		OkmHex  string `json:"okm_hex"`
	} `json:"hkdf"`
	Proof struct {
		KeyHex    string `json:"key_hex"`
		Code      string `json:"code"`
		ProofHex  string `json:"proof_hex"`
	} `json:"proof"`
	Record struct {
		KeyHex       string `json:"key_hex"`
		Dir          int    `json:"dir"`
		NonceCtr     int    `json:"nonce_ctr"`
		PlaintextHex string `json:"plaintext_hex"`
		CipherHex    string `json:"cipher_hex"`
	} `json:"record"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func loadVectors(t *testing.T) Vectors {
	t.Helper()
	p := filepath.Join("testdata", "vectors.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func TestVectors(t *testing.T) {
	v := loadVectors(t)

	// HKDF-SHA256
	okm, err := HKDFSHA256(mustHex(t, v.Hkdf.IkmHex), mustHex(t, v.Hkdf.SaltHex), []byte(v.Hkdf.Info), v.Hkdf.Length)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	if hex.EncodeToString(okm) != v.Hkdf.OkmHex {
		t.Errorf("hkdf mismatch:\n got %s\nwant %s", hex.EncodeToString(okm), v.Hkdf.OkmHex)
	}

	// Code proof
	key := mustHex(t, v.Proof.KeyHex)
	proof := CodeProof(key, v.Proof.Code)
	if hex.EncodeToString(proof) != v.Proof.ProofHex {
		t.Errorf("proof mismatch:\n got %s\nwant %s", hex.EncodeToString(proof), v.Proof.ProofHex)
	}

	// Record seal/open round-trip against the frozen ciphertext
	rk := mustHex(t, v.Record.KeyHex)
	sealer := NewRecord(rk, byte(v.Record.Dir))
	sealer.ctr = uint64(v.Record.NonceCtr)
	ct, err := sealer.Seal(mustHex(t, v.Record.PlaintextHex))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if hex.EncodeToString(ct) != v.Record.CipherHex {
		t.Errorf("record cipher mismatch:\n got %s\nwant %s", hex.EncodeToString(ct), v.Record.CipherHex)
	}
	opener := NewRecord(rk, byte(v.Record.Dir))
	opener.ctr = uint64(v.Record.NonceCtr)
	pt, err := opener.Open(ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, mustHex(t, v.Record.PlaintextHex)) {
		t.Errorf("record roundtrip mismatch")
	}
}

// TestHKDFRFC5869Case1 asserts RFC 5869 Test Case 1.
func TestHKDFRFC5869Case1(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	got, err := HKDFSHA256(ikm, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("rfc5869 case1 mismatch:\n got %s\nwant %s", hex.EncodeToString(got), want)
	}
}
