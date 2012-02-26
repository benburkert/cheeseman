package server

import (
	"io/ioutil"
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
	config.Address = ""

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
	config.Address = "0.0.0.0:"
	config.Type = "tcp4"

	err = config.Verify()
	if err == nil {
		t.Fatalf("Verify did not catch a tcp4 address error")
	}

}

func TestLoadIni(t *testing.T) {
	defaultConfig := loadTempConfig(defaultIni, t)
	assertEqual(defaultConfig.Address, "0.0.0.0:443", "Address", t)
	assertEqual(defaultConfig.Type, "tcp4", "Type", t)

	socketConfig := loadTempConfig(socketIni, t)
	assertEqual(socketConfig.Address, "/path/to/server.sock", "Address", t)
	assertEqual(socketConfig.Type, "unix", "Type", t)
}

func assertEqual(actual, expected, description string, t *testing.T) {
	if actual != expected {
		t.Fatalf("Ini parse failed on %s: %s != %s", description, actual, expected)
	}
}

func tempIniFile(body string) (path string, err error) {
	file, err := ioutil.TempFile("", "ini")
	if err != nil {
		return "", err
	}

	_, err = file.WriteString(body)
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

func loadTempConfig(body string, t *testing.T) (config *Config) {
	path, err := tempIniFile(body)
	if err != nil {
		t.Fatalf(err.Error())
	}

	config, err = LoadConfig(path)
	if err != nil {
		t.Fatalf(err.Error())
	}

	return
}

var (
	defaultIni = `#
# default ini file
#

[cheesed]

Address = 0.0.0.0:443;
Type    = tcp4;
`
	socketIni  = `#
# unix socket ini file
#

[Cheesed]

address = /path/to/server.sock;
TYPE    = unix;
`
)
