package sni

import (
	"../tls"
)

type InMemoryAdapter struct {
}

func NewInMemoryAdapter(config map[string]string) (adapter Adapter, err error) {
	return new(InMemoryAdapter), nil
}

func (adp *InMemoryAdapter) Callback(servername string) *tls.Config {
	return nil
}

var _ = Register("inmemory", func (config map[string]string) (adapter Adapter, err error) {
	return new(InMemoryAdapter), nil
})
