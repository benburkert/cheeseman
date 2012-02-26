package server

import (
	"testing"
)

func TestConfigVerify(t *testing.T) {
	config := NewConfig()

	err := config.Verify()
	if err != nil {
		t.Fatalf("Default config was not valid: " + err.Error())
	}

	// empty address
	config = NewConfig()
	config.Addr = ""

	if config.Verify() == nil {
		t.Fatalf("Verify did not catch an empty address")
	}

	// empty type
	config = NewConfig()
	config.Type = ""

	if config.Verify() == nil {
		t.Fatalf("Verify did not catch an empty type")
	}

	// missing port
	config = NewConfig()
	config.Addr = "0.0.0.0:"
	config.Type = "tcp4"

	err = config.Verify()
	if err == nil {
		t.Fatalf("Verify did not catch a tcp4 address error")
	}
}
