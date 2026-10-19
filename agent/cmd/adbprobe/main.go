package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/kotekompotek/ShizBridge/agent/internal/config"
	"github.com/kotekompotek/ShizBridge/agent/internal/tlsclient"
)

const (
	aCNXN = 0x4e584e43
	aOPEN = 0x4e45504f
	aOKAY = 0x59414b4f
	aCLSE = 0x45534c43
	aWRTE = 0x45545257
	ver   = 0x01000001
)

type msg struct {
	cmd, arg0, arg1 uint32
	payload         []byte
}

func writeMsg(w io.Writer, m msg) error {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:4], m.cmd)
	binary.LittleEndian.PutUint32(h[4:8], m.arg0)
	binary.LittleEndian.PutUint32(h[8:12], m.arg1)
	binary.LittleEndian.PutUint32(h[12:16], uint32(len(m.payload)))
	binary.LittleEndian.PutUint32(h[16:20], 0)
	binary.LittleEndian.PutUint32(h[20:24], m.cmd^0xffffffff)
	if _, err := w.Write(h); err != nil {
		return err
	}
	if len(m.payload) > 0 {
		if _, err := w.Write(m.payload); err != nil {
			return err
		}
	}
	return nil
}

func readMsg(r io.Reader) (msg, error) {
	h := make([]byte, 24)
	if _, err := io.ReadFull(r, h); err != nil {
		return msg{}, err
	}
	cmd := binary.LittleEndian.Uint32(h[0:4])
	magic := binary.LittleEndian.Uint32(h[20:24])
	length := binary.LittleEndian.Uint32(h[12:16])
	if magic != cmd^0xffffffff {
		return msg{}, fmt.Errorf("bad magic 0x%08x for cmd 0x%08x", magic, cmd)
	}
	if length > 1<<20 {
		return msg{}, fmt.Errorf("implausible payload length %d", length)
	}
	p := make([]byte, length)
	if _, err := io.ReadFull(r, p); err != nil {
		return msg{}, err
	}
	return msg{cmd, binary.LittleEndian.Uint32(h[4:8]), binary.LittleEndian.Uint32(h[8:12]), p}, nil
}

func name(m msg) string {
	switch m.cmd {
	case aCNXN:
		return "CNXN"
	case aOPEN:
		return "OPEN"
	case aOKAY:
		return "OKAY"
	case aCLSE:
		return "CLSE"
	case aWRTE:
		return "WRTE"
	}
	return fmt.Sprintf("0x%08x", m.cmd)
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("config:", err)
		os.Exit(1)
	}
	id, err := config.LoadIdentity()
	if err != nil {
		fmt.Println("identity:", err)
		os.Exit(1)
	}
	addr := cfg.Addr()
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	fmt.Println("dialing", addr, "…")
	var conn net.Conn
	if os.Getenv("PLAIN") != "" {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err == nil {
			fmt.Println("tcp ok (plain, no tls)")
		}
	} else {
		conn, err = tlsclient.Dial(addr, id, cfg.ServerPin, 10*time.Second)
		if err == nil {
			fmt.Println("tls ok")
		}
	}
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer conn.Close()

	send := func(m msg) {
		if err := writeMsg(conn, m); err != nil {
			fmt.Println("send", name(m), ":", err)
			os.Exit(1)
		}
		fmt.Printf("-> %-4s arg0=%d arg1=%d len=%d\n", name(m), m.arg0, m.arg1, len(m.payload))
	}
	recv := func() (msg, error) {
		_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		m, err := readMsg(conn)
		if err != nil {
			return m, err
		}
		fmt.Printf("<- %-4s arg0=%d arg1=%d len=%d payload=%s\n",
			name(m), m.arg0, m.arg1, len(m.payload), short(m.payload))
		return m, nil
	}

	send(msg{cmd: aCNXN, arg0: ver, arg1: 1024 * 1024, payload: []byte("host:features=sendrecv_v2,sendrecv_v2_brotli,shell_v2,cmd,stat_v2,ls_v2")})
	m, err := recv()
	if err != nil {
		fmt.Println("after CNXN:", err)
		if err == io.EOF {
			fmt.Println("phone closed the connection without replying")
		}
		os.Exit(1)
	}
	if m.cmd == aCNXN {
		fmt.Println("handshake OK, opening shell:id …")
		send(msg{cmd: aOPEN, arg0: 1, arg1: 0, payload: []byte("shell:id")})
		for i := 0; i < 6; i++ {
			m, err = recv()
			if err != nil {
				fmt.Println("stream:", err)
				break
			}
			if m.cmd == aWRTE {
				send(msg{cmd: aOKAY, arg0: 1, arg1: m.arg0})
				fmt.Printf("stdout: %q\n", string(m.payload))
			}
			if m.cmd == aCLSE {
				break
			}
		}
	}
	fmt.Println("done")
}

func short(p []byte) string {
	if len(p) == 0 {
		return "-"
	}
	if len(p) <= 80 {
		return fmt.Sprintf("%q", string(p))
	}
	return fmt.Sprintf("%q… (%d bytes)", string(p[:80]), len(p))
}

var _ = hex.EncodeToString
