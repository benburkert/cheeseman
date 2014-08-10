package sni

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type InMemoryAdapter struct {
	table map[string]*tls.Certificate
}

func NewInMemoryAdapter(config map[string]string) (Adapter, error) {
	adapter := new(InMemoryAdapter)
	adapter.table = make(map[string]*tls.Certificate)

	for servername, glob := range config {
		config, err := loadCertificate(glob)

		if err != nil {
			return nil, err
		}

		adapter.table[strings.ToLower(servername)] = config
	}

	return adapter, nil
}

func (adp *InMemoryAdapter) Callback(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, ok := adp.table[strings.ToLower(hello.ServerName)]
	if !ok {
		return nil, nil
	}

	return cert, nil
}

var _ = Register("inmemory", func(config map[string]string) (Adapter, error) {
	return NewInMemoryAdapter(config)
})

func loadCertificate(globs string) (*tls.Certificate, error) {
	var cbytes, kbytes *[]byte

	parts := strings.Split(globs, ",")

	for _, glob := range parts {
		paths, err := filepath.Glob(glob)

		if err != nil {
			return nil, err
		}

		for _, path := range paths {
			block, bytes, err := decode(path)

			if err != nil {
				return nil, err
			}

			switch block.Type {
			case "CERTIFICATE":
				cbytes = bytes
			case "RSA PRIVATE KEY":
				kbytes = bytes
			default:
				return nil, errors.New("Unknown file type " + block.Type + ": " + path)
			}
		}
	}

	if cbytes == nil {
		return nil, errors.New("Certificate file not found.")
	}
	if kbytes == nil {
		return nil, errors.New("RSA Key file not found.")
	}

	cert, err := tls.X509KeyPair(*cbytes, *kbytes)
	return &cert, err
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
