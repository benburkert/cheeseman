package server

type Server struct {
}

func NewServer(config *Config) (srv *Server) {
	return new(Server)
}

func (srv *Server) Run() {
}
