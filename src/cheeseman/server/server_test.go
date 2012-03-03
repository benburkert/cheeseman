package server

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestNewServer(t *testing.T) {
	config := testConfig(t)

	_, err := os.Stat(config.Address)

	if err == nil {
		t.Fatal("Socket file already exists")
	}

	_ = NewServer(config)

	fi, err := os.Stat(config.Address)

	if (fi.Mode() & os.ModeSocket) == 0 {
		t.Fatalf("Server is not listening on socket: %s\n", config.Address)
	}
}

func testConfig(t *testing.T) (cfg *Config) {
	cfg = NewConfig()

	dir, err := ioutil.TempDir("", "socket")
	if err != nil {
		t.Fatalf("Test config failed: %s", err.Error())
	}

	cfg.Address = filepath.Join(dir, "server.sock")
	cfg.Type = "unix"

	cfg.Certificate = loadTempFile("cert", certExampleOrg, t)
	cfg.Key = loadTempFile("key", keyExampleOrg, t)

	return
}

func loadTempFile(name, data string, t *testing.T) string {
	file, err := ioutil.TempFile("", name)

	if err != nil {
		t.Fatalf("Error creating temp file: %s", err.Error())
	}

	_, err = file.WriteString(data)

	if err != nil {
		t.Fatalf("Error writing data to temp file: %s", err.Error())
	}

	return file.Name()
}

var (
	certExampleOrg = `
-----BEGIN CERTIFICATE-----
MIIBxzCCATACCQD0F4Jg9YrPBTANBgkqhkiG9w0BAQUFADAoMRAwDgYDVQQKEwdB
Y21lIENvMRQwEgYDVQQDEwtleGFtcGxlLm9yZzAeFw0xMjAyMTIwMjUyMTRaFw0z
OTA2MjkwMjUyMTRaMCgxEDAOBgNVBAoTB0FjbWUgQ28xFDASBgNVBAMTC2V4YW1w
bGUub3JnMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7bbeY2N0uA6Au6YGb
tt18PRfy10TMQtSWbbV+tdAyh7JeiIMJI/4isDpr8PbBrdC9P/YrMgyiF99sByaw
60Q1O10/bAR6Xqt1L34XH4NNSv7/ZiWJA2lCLM8dm6eyiNPK5vLSW5SZDdiKJqH4
TLUtqjj3QZh1f5YzIjfllVL/rwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACajfHbw
8t4fuY3qEyvETev3lAw32xf6C4D7HfeX07g57PQjmSsmavNXSJu56Esj8REI54zH
d2p1SIE1PxpB2ZiOUyVNOaONtSeIacUSafCDd/fGjpYsUmuDMGWXrLiPqhS0DmT6
ZQ3YeYIUTVuwZrJsIf4SY8MkNOK4oZGcadjN
-----END CERTIFICATE-----
`
	keyExampleOrg  = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC7bbeY2N0uA6Au6YGbtt18PRfy10TMQtSWbbV+tdAyh7JeiIMJ
I/4isDpr8PbBrdC9P/YrMgyiF99sByaw60Q1O10/bAR6Xqt1L34XH4NNSv7/ZiWJ
A2lCLM8dm6eyiNPK5vLSW5SZDdiKJqH4TLUtqjj3QZh1f5YzIjfllVL/rwIDAQAB
AoGAF3ffe0X8O9y8W+NlFShKh1nm+8M0nBbqI4PNK/Z8ATe4f9m7/pMBKTrDtexQ
GWQ4NNojarkzl8BBe3dRwulSeti/Jwu5t+MDTHufrCyKhzBUzocQisYPtIMgH3DU
TgBHtStCJngc9cem9h6p256jjENXaAn+fXlsKcc42VbSUtECQQDw97EAm1ph81ee
Bvx/zLVld8CQvPQqnedyii0FaVMi37As3+pZ/LqFumDhxcK81k+eTVXKQ8l3r01G
b3Mzw5+7AkEAxx7+8yefvvmk7tz/qcyQcenc0VHQGgr6Tc9PhRfplNHuFeAwX9M1
bTQBiT54TrIKcWHir5fS55fuzMn9N3R+nQJAA8iP0eeeiq0scgHAEy2ep4Iy1tLw
rn6eNLEwtcYKlSCX/oxhfJo4P4NGpCTbwuVGiMDEGRHpZuSsvO9hCq4GowJAaNuZ
xtKG/TrZ8C/RMsnXByXwcwpyXESLq44QgjYle4lRp5N35f6DlA5fALc1A7weY7b4
eR+qoOsRhiaYgiuGwQJBAOcf4m1qt6uAwZAV+OFJKTJLi0w+e1iXbiHTHd8JGBYj
KO7JFQZQqEdJJmWb0kCCibHxsOKbFk5V8hpgVgjcTnU=
-----END RSA PRIVATE KEY-----
`
)
