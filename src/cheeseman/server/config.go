package server

import (
	"github.com/benburkert/goini"
	"net"
)

type Error struct {
	message string
}

type Config struct {
	Address     string
	Type        string
	Certificate string
	Key         string
	Log         string
}

func NewConfig() *Config {
	return &Config{
		Address: "0.0.0.0:443",
		Type:    "tcp4",
		Log:     "stdout",
	}
}

func LoadConfig(filePath string) (config *Config, err error) {
	config = NewConfig()

	config.Load(filePath)

	err = config.Verify()

	return
}

func (config *Config) Load(filePath string) (err error) {
	dict, err := ini.Load(filePath)

	if err != nil {
		return
	}

	s, found := dict.GetString("cheesed", "address")
	if found {
		config.Address = s
	}

	s, found = dict.GetString("cheesed", "type")
	if found {
		config.Type = s
	}

	return
}

func (config *Config) Verify() (err error) {
	if config.Address == "" {
		return _error("Address cannot be empty")
	}

	if config.Type == "" {
		return _error("Type cannot be empty")
	}

	switch config.Type {
	case "tcp", "tcp4", "tcp6":
		_, err = net.ResolveTCPAddr(config.Type, config.Address)
	case "unix", "unixpacket", "unixgram":
		_, err = net.ResolveUnixAddr(config.Type, config.Address)
	}

	return
}

func _error(message string) (err error) {
	return Error{message: message}
}

func (err Error) Error() string {
	return err.message
}
