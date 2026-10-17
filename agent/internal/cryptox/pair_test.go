package cryptox

import (
	"net"
	"testing"
	"time"
)

func TestPairingRoundTrip(t *testing.T) {
	const code = "MJGP2X4KQ7TA"
	srv, err := NewServerState(code)
	if err != nil {
		t.Fatal(err)
	}
	wantPin, err := SPKIFingerprint(srv.OwnCertDER)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = srv.HandlePairing(c)
	}()

	id, err := MakeIdentity("test-host")
	if err != nil {
		t.Fatal(err)
	}
	info, err := Pair(ln.Addr().String(), code, "test-host", id, 10*time.Second)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if info.ServerPin != wantPin {
		t.Errorf("pin mismatch: got %s want %s", info.ServerPin, wantPin)
	}
	if len(srv.Enrolled) != 1 {
		t.Errorf("expected 1 enrolled client, got %d", len(srv.Enrolled))
	}
	myPin, err := SPKIFingerprint(id.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.Enrolled[myPin]; !ok {
		t.Error("client certificate not enrolled")
	}
}

func TestPairingRejectsBadCodeAndLocks(t *testing.T) {
	const code = "GOODCODE1234"
	srv, err := NewServerState(code)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.HandlePairing(c) }()
		}
	}()

	id, _ := MakeIdentity("evil")
	// Two bad attempts → bad_code.
	for i := 0; i < 2; i++ {
		_, err := Pair(ln.Addr().String(), "BADCODE00000", "evil", id, 10*time.Second)
		if err == nil {
			t.Fatal("expected rejection")
		}
	}
	// Third bad attempt → locked.
	_, err = Pair(ln.Addr().String(), "BADCODE00000", "evil", id, 10*time.Second)
	if err == nil {
		t.Fatal("expected lockout")
	}
	// Even the correct code is refused while locked.
	_, err = Pair(ln.Addr().String(), code, "evil", id, 10*time.Second)
	if err == nil {
		t.Fatal("expected locked rejection with correct code")
	}
	if len(srv.Enrolled) != 0 {
		t.Error("nothing must be enrolled after failures")
	}
}

func TestFingerprintStable(t *testing.T) {
	der, _, _, err := MakeSelfSigned("fp")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := SPKIFingerprint(der)
	b, _ := SPKIFingerprint(der)
	if a != b || len(a) != 64 {
		t.Errorf("bad fingerprint: %q / %q", a, b)
	}
}
