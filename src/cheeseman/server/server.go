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
}

func NewServer(config *Config) (srv *Server) {
	srv = new(Server)
	srv.setup(config)
	return srv
}

func (srv *Server) Run() {
}

func (srv *Server) setup(config *Config) {
	var logWriter io.Writer

	switch strings.ToLower(config.Log) {
	case "stdout":
		logWriter = os.Stdout
	default:
		var oerr error
		logWriter, oerr = os.OpenFile(config.Log, os.O_APPEND, 0666)

		if oerr != nil {
			panic(oerr.Error())
		}
	}

	srv.log = log.New(logWriter, "cheesed", os.O_APPEND)

	listener, lerr := net.Listen(config.Type, config.Address)
	if lerr != nil {
		srv._fatal(lerr.Error())
	}

	certificate, cerr := tls.LoadX509KeyPair(config.Certificate, config.Key)
	if cerr != nil {
		srv._fatal(cerr.Error())
	}

	srv.listener = listener
	srv.certificate = certificate
}

func (srv *Server) _fatal(message string) {
	srv.log.Fatal(message)
}
