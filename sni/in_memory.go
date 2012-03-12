package sni

import (
	"../tls"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
)

type InMemoryAdapter struct {
	table map[string]*tls.Config
}

func NewInMemoryAdapter(config map[string]string) (Adapter, error) {
	adapter := new(InMemoryAdapter)
	adapter.table = make(map[string]*tls.Config)

	for servername, glob := range config {
		config, err := loadConfig(glob)

		if err != nil {
			return nil, err
		}

		adapter.table[strings.ToLower(servername)] = config
	}

	return adapter, nil
}

func (adp *InMemoryAdapter) Callback(servername string) (config *tls.Config) {
	config, ok := adp.table[strings.ToLower(servername)]

	if !ok {
		return nil
	}

	return
}

var _ = Register("inmemory", func(config map[string]string) (Adapter, error) {
	return NewInMemoryAdapter(config)
})

func loadConfig(globs string) (config *tls.Config, err error) {
	cert, err := loadCert(globs)

	if err != nil {
		return
	}

	config = new(tls.Config)

	config.Certificates = []tls.Certificate{cert}

	return
}

func loadCert(globs string) (tls.Certificate, error) {
	var cbytes, kbytes *[]byte

	parts := strings.Split(globs, ",")

	for _, glob := range parts {
		paths, err := filepath.Glob(glob)

		if err != nil {
			return tls.Certificate{}, err
		}

		for _, path := range paths {
			block, bytes, err := decode(path)

			if err != nil {
				return tls.Certificate{}, err
			}

			switch block.Type {
			case "CERTIFICATE":
				cbytes = bytes
			case "RSA PRIVATE KEY":
				kbytes = bytes
			default:
				return tls.Certificate{}, _error("Unknown file type " + block.Type + ": " + path)
			}
		}
	}

	if cbytes == nil {
		return tls.Certificate{}, _error("Certificate file not found.")
	}
	if kbytes == nil {
		return tls.Certificate{}, _error("RSA Key file not found.")
	}

	return tls.X509KeyPair(*cbytes, *kbytes)
}

func decode(filepath string) (*pem.Block, *[]byte, error) {
	file, err := os.Open(filepath)

	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()

	if err != nil {
		return nil, nil, err
	}

	var buf []byte = make([]byte, info.Size())

	_, err = file.Read(buf)

	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(buf)

	return block, &buf, nil
}

func _error(message string) error {
	return Error{message: message}
}
