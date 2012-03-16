package server

import (
	"../tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
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

func TestDefaultConnection(t *testing.T) {
	config := testConfig(t)

	srv := NewServer(config)
	defer srv.Stop()
	srv.Start()

	cli := socketClient(config.Address, t)
	defer cli.Close()

	cli.Handshake()
}

func TestMultipleConnections(t *testing.T) {
	config := testConfig(t)

	srv := NewServer(config)
	defer srv.Stop()
	srv.Start()

	cli1 := socketClient(config.Address, t)
	defer cli1.Close()

	cli2 := socketClient(config.Address, t)
	defer cli2.Close()

	cli3 := socketClient(config.Address, t)
	defer cli3.Close()

	cli2.Handshake()
	cli3.Handshake()
	cli1.Handshake()
}

func TestSNIConnection(t *testing.T) {
	config := testSNIConfig(t)

	srv := NewServer(config)
	defer srv.Stop()
	srv.Start()

	defaultClient := socketClient(config.Address, t)
	defer defaultClient.Close()

	fooClient := socketSNIClient(config.Address, "foo.example.org", t)
	defer fooClient.Close()

	defaultClient.Handshake()
	fooClient.Handshake()
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

	cfg.SNIAdapterName = "inmemory"

	return
}

func testSNIConfig(t *testing.T) (cfg *Config) {
	cfg = testConfig(t)

	paths := tempFile(certFooExampleOrg, t) + "," + tempFile(keyFooExampleOrg, t)
	cfg.SNIAdapterConfig["foo.example.org"] = paths

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

func socketClient(socketPath string, t *testing.T) (conn *tls.Conn) {
	sConn := unixConn(socketPath, t)

	conn = tls.Client(sConn, clientConfig(t))

	return
}

func socketSNIClient(socketPath, servername string, t *testing.T) (conn *tls.Conn) {
	sConn := unixConn(socketPath, t)
	conf := clientSNIConfig(servername, t)

	conn = tls.Client(sConn, conf)

	return
}

func unixConn(socketPath string, t *testing.T) (conn net.Conn) {
	conn, err := net.Dial("unix", socketPath)

	if err != nil {
		t.Fatalf("Error establishing client connection: %s", err.Error())
	}

	return
}

func clientConfig(t *testing.T) (cfg *tls.Config) {
	cblock, _ := pem.Decode([]byte(certExampleOrg))

	rootCert, err := x509.ParseCertificate(cblock.Bytes)

	if err != nil {
		t.Fatalf("Error parsing cert: %s", err.Error())
	}

	cfg = new(tls.Config)
	cfg.RootCAs = x509.NewCertPool()
	cfg.RootCAs.AddCert(rootCert)

	return
}

func clientSNIConfig(servername string, t *testing.T) (cfg *tls.Config) {
	cfg = clientConfig(t)

	cfg.ServerName = servername

	return
}

func tempFile(body string, t *testing.T) (path string) {
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err.Error())
	}

	_, err = file.WriteString(body)
	if err != nil {
		t.Fatalf("Error writing to temp file: %s", err.Error())
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
	keyExampleOrg = `
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
	certFooExampleOrg = `
-----BEGIN CERTIFICATE-----
MIIBhjCB8AIJAK9BK0MsWFFjMA0GCSqGSIb3DQEBBQUAMCgxEDAOBgNVBAoTB0Fj
bWUgQ28xFDASBgNVBAMTC2V4YW1wbGUub3JnMB4XDTEyMDIxMjAyNTIxNVoXDTM5
MDYyOTAyNTIxNVowLDEQMA4GA1UEChMHQWNtZSBDbzEYMBYGA1UEAxMPZm9vLmV4
YW1wbGUub3JnMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMKeXMzz0j/ba3st031C
xWUmUQNtE7/txtGKzuTYp5vvriVf+NOhEsynWZWlMVMCiNg8YALiH+4gubd/YHeE
gxECAwEAATANBgkqhkiG9w0BAQUFAAOBgQAsKfG3DLJPcKx4O9u1Bfn9efmSBjYm
nOGK3+MCrL0ZRMwJrwTTmJcPYNFMxcbnZ3d/e3bePu30inbf7SLWSzU/IV84d1ou
vMxIk+ic9hafN9yoVo24Wye963YExok2gdbe0yxz5ij/WEB82Hz7hr4QGl+npwUe
Dpv+sTN+P+FrZQ==
-----END CERTIFICATE-----
`
	keyFooExampleOrg = `
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAMKeXMzz0j/ba3st031CxWUmUQNtE7/txtGKzuTYp5vvriVf+NOh
EsynWZWlMVMCiNg8YALiH+4gubd/YHeEgxECAwEAAQJBAJEjnxut/i9nSMnNTDrP
T/z2TVabwy3QewSMW21pcd4k3AETYYE+ZMOp/3cxkMLj/ph05uWy22BXIl+xeJHi
pU0CIQDy66CQ5uzlczhXwUZRBJXZ/2TQhZCzs8rKQlKWgO0gJwIhAM0Y85PAbxxc
2ZYWAYcGV66RK37HEtMmj2QQTMvKFY4HAiAFRGCl46vtSbNGC9XHee753BTGhK7f
hp12BzwdMUxy7wIgDsI45Oz4EeZskexLd9fw/1La+miA5kjkEKNLo26LVokCIDGP
WhXudo1UBysfBu4EWopmQDgEdKFVs4eh2b1xqw4f
-----END RSA PRIVATE KEY-----
`
)
