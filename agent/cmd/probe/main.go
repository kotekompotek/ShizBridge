package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/config"
	"github.com/kotekompotek/ShizBridge/agent/internal/cryptox"
)

func main() {
	addr := os.Args[1]
	id, _, err := config.NewIdentity("probe")
	if err != nil {
		panic(err)
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    cryptox.UnverifiedClientConfig(id),
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	fmt.Println("tls version:", st.Version, "did resume:", st.DidResume)
	for i, c := range st.PeerCertificates {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		fp := base64.StdEncoding.EncodeToString(sum[:])
		fmt.Printf("peer[%d] subject=%q issuer=%q\n", i, c.Subject.String(), c.Issuer.String())
		fmt.Printf("         spki-sha256(b64)=%s\n", fp)
		fmt.Printf("         notBefore=%s notAfter=%s\n", c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
	}
}
