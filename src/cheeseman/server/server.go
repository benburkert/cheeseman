package server

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

type Server struct {
	log         *log.Logger
	listener    net.Listener
	certificate tls.Certificate
	tlsConfig   *tls.Config
}

func NewServer(config *Config) (srv *Server) {
	srv = new(Server)
	srv.setup(config)
	return srv
}

func (srv *Server) Start() {
	go srv.Run()
}

func (srv *Server) Run() {
	defer srv.listener.Close()

	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			srv._error(err.Error())
			return
		}

		srv.handle(conn)
	}
}

func (srv *Server) Stop() {
}

func (srv *Server) handle(inner net.Conn) {
	conn := tls.Server(inner, srv.tlsConfig)
	defer conn.Close()

	conn.Handshake()
}

func (srv *Server) setup(config *Config) {
	var logWriter io.Writer
	var err error

	switch strings.ToLower(config.Log) {
	case "stdout":
		logWriter = os.Stdout
	default:
		logWriter, err = os.OpenFile(config.Log, os.O_APPEND, 0666)

		if err != nil {
			panic(err.Error())
		}
	}

	srv.log = log.New(logWriter, "cheesed", os.O_APPEND)

	srv.listener, err = net.Listen(config.Type, config.Address)
	if err != nil {
		srv._fatal(err.Error())
	}

	srv.certificate, err = tls.LoadX509KeyPair(config.Certificate, config.Key)
	if err != nil {
		srv._fatal(err.Error())
	}

	srv.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{srv.certificate},
	}

}

func (srv *Server) _error(message string) {
	srv.log.Print(message)
}

func (srv *Server) _fatal(message string) {
	srv.log.Fatal(message)
}
