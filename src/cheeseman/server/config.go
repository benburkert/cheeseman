package server

import (
	"net"
	"github.com/benburkert/goini"
)

type Error struct {
	message string
}

type Config struct {
	Addr string
	Type string
}

func NewConfig() (*Config) {
	return &Config{
		Addr: "0.0.0.0:443",
		Type: "tcp4",
	}
}

func LoadConfig(filePath string) (config *Config) {
	config = NewConfig()

	config.Load(filePath)

	return
}

func (config *Config) Load(filePath string) (err error) {
	dict, err := ini.Load(filePath)

	if err != nil {
		return
	}

	s, found := dict.GetString("cheesed", "addr")
	if found {
		config.Addr = s
	}

	s, found = dict.GetString("cheesed", "type")
	if found {
		config.Type = s
	}

	return
}

func (config *Config) Verify() (err error) {
	if config.Addr == "" {
		return _error("Addr cannot be empty")
	}

	if config.Type == "" {
		return _error("Type cannot be empty")
	}

	switch config.Type {
	case "tcp", "tcp4", "tcp6":
		_, err = net.ResolveTCPAddr(config.Type, config.Addr)
	}

	return
}

func _error(message string) (err error) {
	return Error{message: message}
}

func (err Error) Error() string {
	return err.message
}
