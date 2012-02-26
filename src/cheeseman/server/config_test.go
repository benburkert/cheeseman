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
}
