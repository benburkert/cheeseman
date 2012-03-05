package server

import (
	"io/ioutil"
	"net"
	"path/filepath"
	"testing"
)

func TestTCPListener(t *testing.T) {
	conns := make(chan net.Conn, 1024)

	lst, err := NewListener("tcp", "0.0.0.0:4433", conns)

	if err != nil {
		t.Fatalf("Error creating a tcp listener: %s", err.Error())
	}

	go func() {
		rerr := lst.Run()

		if rerr != nil {
			t.Fatalf("Error running the tcp listener: %s", rerr.Error())
		}
	}()

	cli1, err := net.Dial("tcp", "127.0.0.1:4433")

	if err != nil {
		t.Fatalf("Error connecting to the tcp listener: %s", err.Error())
	}

	defer cli1.Close()

	cli2, err := net.Dial("tcp", "127.0.0.1:4433")

	if err != nil {
		t.Fatalf("Error connecting to the tcp listener: %s", err.Error())
	}

	defer cli2.Close()

	lst.Stop()

	<-conns
	<-conns
}

func TestUnixListener(t *testing.T) {
	conns := make(chan net.Conn, 1024)
	socketPath := testSocket(t)

	lst, err := NewListener("unix", socketPath, conns)

	if err != nil {
		t.Fatalf("Error creating a unix listener: %s", err.Error())
	}

	go func() {
		rerr := lst.Run()

		if rerr != nil {
			t.Fatalf("%+v", rerr)
			t.Fatalf("Error running the unix listener: %s", rerr.Error())
		}
	}()

	cli1, err := net.Dial("unix", socketPath)

	if err != nil {
		t.Fatalf("Error connecting to the unix listener: %s", err.Error())
	}

	defer cli1.Close()

	cli2, err := net.Dial("unix", socketPath)

	if err != nil {
		t.Fatalf("Error connecting to the unix listener: %s", err.Error())
	}

	defer cli2.Close()

	lst.Stop()

	<-conns
	<-conns
}

func testSocket(t *testing.T) string {
	dir, err := ioutil.TempDir("", "socket")

	if err != nil {
		t.Fatalf("Error creating tmp socket dir: %s", err.Error())
	}

	return filepath.Join(dir, "server.sock")
}
