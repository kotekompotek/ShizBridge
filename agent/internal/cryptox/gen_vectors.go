//go:build ignore

// Generates testdata/vectors.json — the cross-language test vectors asserted
// by both the Go and Kotlin test suites. Run:
//
//	go run ./gen_vectors.go
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/kotekompotek/ShizBridge/agent/internal/cryptox"
)

func main() {
	type hkdf struct {
		IkmHex  string `json:"ikm_hex"`
		SaltHex string `json:"salt_hex"`
		Info    string `json:"info"`
		Length  int    `json:"length"`
		OkmHex  string `json:"okm_hex"`
	}
	type proof struct {
		KeyHex   string `json:"key_hex"`
		Code     string `json:"code"`
		ProofHex string `json:"proof_hex"`
	}
	type record struct {
		KeyHex       string `json:"key_hex"`
		Dir          int    `json:"dir"`
		NonceCtr     int    `json:"nonce_ctr"`
		PlaintextHex string `json:"plaintext_hex"`
		CipherHex    string `json:"cipher_hex"`
	}
	type vectors struct {
		Hkdf   hkdf   `json:"hkdf"`
		Proof  proof  `json:"proof"`
		Record record `json:"record"`
	}

	// HKDF: deterministic fixed inputs.
	ikm := make([]byte, 32)
	salt := make([]byte, 32)
	for i := range ikm {
		ikm[i] = byte(i)
		salt[i] = byte(0xA0 + i)
	}
	info := "ShizBridge pairing v1"
	okm, err := cryptox.HKDFSHA256(ikm, salt, []byte(info), 32)
	if err != nil {
		panic(err)
	}

	// Proof: key = okm (the derived session key), fixed code.
	code := "MJGP2X4KQ7TA"
	proofB := cryptox.CodeProof(okm, code)

	// Record: key = fixed 0x42..., dir=0x01, ctr=0, fixed plaintext.
	rk := make([]byte, 32)
	for i := range rk {
		rk[i] = 0x42
	}
	sealer := cryptox.NewRecord(rk, cryptox.DirC2S)
	pt := []byte("hello shizbridge")
	ct, err := sealer.Seal(pt)
	if err != nil {
		panic(err)
	}

	v := vectors{
		Hkdf: hkdf{
			IkmHex:  hex.EncodeToString(ikm),
			SaltHex: hex.EncodeToString(salt),
			Info:    info,
			Length:  32,
			OkmHex:  hex.EncodeToString(okm),
		},
		Proof: proof{
			KeyHex:   hex.EncodeToString(okm),
			Code:     code,
			ProofHex: hex.EncodeToString(proofB),
		},
		Record: record{
			KeyHex:       hex.EncodeToString(rk),
			Dir:          int(cryptox.DirC2S),
			NonceCtr:     0,
			PlaintextHex: hex.EncodeToString(pt),
			CipherHex:    hex.EncodeToString(ct),
		},
	}

	_ = hex.EncodeToString
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("testdata/vectors.json", append(out, '\n'), 0o644); err != nil {
		panic(err)
	}
	println("wrote testdata/vectors.json")
}
