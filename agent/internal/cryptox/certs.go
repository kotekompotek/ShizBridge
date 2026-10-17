package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

func randReader() io.Reader { return rand.Reader }

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SPKIFingerprint returns the lowercase hex SHA-256 of a certificate's
// SubjectPublicKeyInfo (the pin format used across ShizBridge).
func SPKIFingerprint(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

// MakeSelfSigned generates a self-signed ECDSA P-256 certificate.
// Returns the DER encoding plus PEM-encoded certificate and key.
func MakeSelfSigned(cn string) (certDER []byte, certPEM []byte, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"ShizBridge"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certDER, certPEM, keyPEM, nil
}

// CertDERFromPEM extracts the DER bytes from a PEM-encoded certificate.
func CertDERFromPEM(certPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("cryptox: no PEM block in certificate")
	}
	return block.Bytes, nil
}

// MustKeyPair loads identity PEMs into a TLS certificate (panics on bad input;
// identities are always generated or loaded from our own storage).
func MustKeyPair(id *Identity) tls.Certificate {
	cert, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		panic("cryptox: bad identity: " + err.Error())
	}
	return cert
}

// UnverifiedClientConfig is the TLS client config used during pairing:
// it presents the local identity but skips chain verification — trust is
// established by the code proof and pin exchange inside the channel.
func UnverifiedClientConfig(id *Identity) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{MustKeyPair(id)},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// ServerTLSConfig requires (without chain validation) a client certificate.
// SPKI allowlisting happens at the application layer.
func ServerTLSConfig(id *Identity) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{MustKeyPair(id)},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

// B64 encodes raw bytes to standard Base64.
func B64(b []byte) string { return encodeB64(b) }

// B64Decode decodes standard Base64.
func B64Decode(s string) ([]byte, error) { return decodeB64(s) }
