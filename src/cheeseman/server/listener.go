package server

import (
	"net"
	"syscall"
)

type Listener struct {
	inner    net.Listener
	incoming chan net.Conn
	closed   bool
}

func NewListener(ltype, laddr string, incoming chan net.Conn) (lst *Listener, err error) {
	lst = new(Listener)
	lst.inner, err = net.Listen(ltype, laddr)

	if err != nil {
		return nil, err
	}

	lst.incoming = incoming
	lst.closed = false

	return lst, nil
}

func (lst *Listener) Run() (err error) {
	for {
		conn, err := lst.inner.Accept()

		if err == syscall.EINVAL {

			if lst.closed {
				return nil
			} else {
				return err
			}

		} else if nerr, ok := err.(net.Error); ok {

			if lst.closed && !nerr.Temporary() {
				return nil
			} else {
				return nerr
			}

		} else if err != nil {
			return err
		}

		lst.incoming <- conn
	}

	return nil
}

func (lst *Listener) Stop() {
	lst.closed = true
	lst.inner.Close()
}
