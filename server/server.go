package server

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/benburkert/cheeseman/sni"
)

type Server struct {
	connections chan net.Conn
	log         *log.Logger
	listener    *Listener
	certificate tls.Certificate
	tlsConfig   *tls.Config
	sniAdapter  sni.Adapter
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
	go func() {
		for {
			conn := <-srv.connections
			go srv.handle(conn)
		}
	}()

	err := srv.listener.Run()

	if err != nil {
		srv._error(err.Error())
	}
}

func (srv *Server) Stop() {
	srv.listener.Stop()
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

	srv.connections = make(chan net.Conn, 1024)

	srv.listener, err = NewListener(config.Type, config.Address, srv.connections)
	if err != nil {
		srv._fatal(err.Error())
	}

	srv.certificate, err = tls.LoadX509KeyPair(config.Certificate, config.Key)
	if err != nil {
		srv._fatal(err.Error())
	}

	srv.sniAdapter, err = sni.NewAdapter(config.SNIAdapterName, config.SNIAdapterConfig)
	if err != nil {
		srv._fatal(err.Error())
	}

	srv.tlsConfig = &tls.Config{
		Certificates:   []tls.Certificate{srv.certificate},
		GetCertificate: srv.sniCallback,
	}

}

func (srv *Server) sniCallback(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return srv.sniAdapter.Callback(hello)
}

func (srv *Server) _error(message string) {
	srv.log.Print(message)
}

func (srv *Server) _fatal(message string) {
	srv.log.Fatal(message)
}
