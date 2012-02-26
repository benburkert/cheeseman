package server

import (
	"github.com/benburkert/goini"
)

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
	return nil
}
