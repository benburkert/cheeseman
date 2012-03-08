package sni

import (
	"../tls"
)

type Adapter interface {
	Callback(servername string) *tls.Config
}

type Error struct {
	message string
}

var (
	registry = make(map[string]func(config map[string]string) (Adapter, error))
)

func Register(name string, initializer func(config map[string]string) (Adapter, error)) error {
	registry[name] = initializer

	return nil
}

func NewAdapter(name string, config map[string]string) (adapter Adapter, err error) {
	initializer, ok := registry[name]

	if !ok {
		return nil, Error{message: name + " is not a registered adapter."}
	}

	return initializer(config)
}

func (err Error) Error() string {
	return err.message
}
