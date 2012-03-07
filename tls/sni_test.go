package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func init() {
	pool := x509.NewCertPool()
	pool.AddCert(x509Cert(certExampleOrg))

	for hostname, cert := range certTable {
		x509Cert := x509Cert(cert)

		opts := x509.VerifyOptions{
			DNSName: hostname,
			Roots:   pool,
		}

		_, err := x509Cert.Verify(opts)

		if err != nil {
			panic(hostname + " error: " + err.Error())
		}
	}
}

func TestCallbackReturnsNil(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()

	go testClientConnect("example.org", c, t)

	serverWithCallback(func(servername string) *Config {
		return nil
	}, s, t)
}

func TestCallbackReturnsNewConfig(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()

	go testClientConnect("foo.example.org", c, t)

	serverWithCallback(func(servername string) (config *Config) {
		cert, ok := certTable[servername]

		if !ok {
			t.Fatalf("cert lookup failed for %s", servername)
		}

		config = newConfig()
		config.Certificates = []Certificate{*cert}

		config.BuildNameToCertificate()

		return
	}, s, t)
}

func TestMultipleCallbackCalls(t *testing.T) {
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	c3, s3 := net.Pipe()
	conns := make(chan net.Conn)
	quit := make(chan bool)
	defer func() {
		quit <- true
	}()

	go chanServerWithCallback(func(servername string) *Config {
		if cert, ok := certTable[servername] ; ok {
			config := newConfig()
			config.Certificates = []Certificate{*cert}

			config.BuildNameToCertificate()

			return config
		}

		return nil
	}, conns, quit, t)

	conns <- s1
	conns <- s2
	conns <- s3

	testClientConnect("foo.example.org", c1, t)
	testClientConnect("bar.example.org", c2, t)
	testClientConnect("example.org", c3, t)
}

func testClientConnect(servername string, c net.Conn, t *testing.T) {
	config := newConfig()
	config.ServerName = servername

	cli := Client(c, config)

	defer cli.Close()

	err := cli.Handshake()

	if err != nil {
		t.Errorf("client handshake error: %s", err.Error())
	}

	buf := make([]byte, len(servername))
	cli.Read(buf)

	if !bytes.Equal([]byte(servername), buf) {
		t.Fatalf("SNI failed, expected %s, got %s", servername, buf)
	}
}

func chanServerWithCallback(callback func(string)(*Config), conns chan net.Conn, quit chan bool, t *testing.T) {
	for {
		select {
		case con := <-conns:
			go serverWithCallback(callback, con, t)
		case <-quit:
			return
		}
	}
}

func serverWithCallback(callback func(string)(*Config), s net.Conn, t *testing.T) {
	config := newConfig()
	config.SNICallback = callback

	ser := Server(s, config)
	defer ser.Close()
	defer s.Close()

	err := ser.Handshake()

	if err != nil {
		t.Errorf("server handshake error: %s", err.Error())
	}

	state := ser.ConnectionState()

	ser.Write([]byte(state.ServerName))
}

func newConfig() (config *Config) {
	config = new(Config)
	config.Certificates = []Certificate{*certExampleOrg}
	config.CipherSuites = []uint16{TLS_RSA_WITH_RC4_128_SHA}
	config.RootCAs = x509.NewCertPool()
	config.RootCAs.AddCert(x509Cert(certExampleOrg))

	return
}

func loadCert(certPEM, keyPEM string) (*Certificate) {
	cblock, _ := pem.Decode([]byte(certPEM))
	kblock, _ := pem.Decode([]byte(keyPEM))

	if cblock.Type != "CERTIFICATE" {
		panic("error parsing pem cert")
	}

	if kblock.Type != "RSA PRIVATE KEY" {
		panic("error parsing pem key")
	}

	cert, err := X509KeyPair([]byte(certPEM), []byte(keyPEM))

	if err != nil {
		panic("error loading X509 pair")
	}

	return &cert
}

func x509Cert(oldCert *Certificate) (newCert *x509.Certificate) {
	newCert, err := x509.ParseCertificate(oldCert.Certificate[0])

	if err != nil {
		panic("failed to convert tls cert to x509")
	}

	return
}

var (
	certExampleOrg = loadCert(`
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
`, `
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
`)
	certFooExampleOrg = loadCert(`
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
`, `
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAMKeXMzz0j/ba3st031CxWUmUQNtE7/txtGKzuTYp5vvriVf+NOh
EsynWZWlMVMCiNg8YALiH+4gubd/YHeEgxECAwEAAQJBAJEjnxut/i9nSMnNTDrP
T/z2TVabwy3QewSMW21pcd4k3AETYYE+ZMOp/3cxkMLj/ph05uWy22BXIl+xeJHi
pU0CIQDy66CQ5uzlczhXwUZRBJXZ/2TQhZCzs8rKQlKWgO0gJwIhAM0Y85PAbxxc
2ZYWAYcGV66RK37HEtMmj2QQTMvKFY4HAiAFRGCl46vtSbNGC9XHee753BTGhK7f
hp12BzwdMUxy7wIgDsI45Oz4EeZskexLd9fw/1La+miA5kjkEKNLo26LVokCIDGP
WhXudo1UBysfBu4EWopmQDgEdKFVs4eh2b1xqw4f
-----END RSA PRIVATE KEY-----
`)
	certBarExampleOrg = loadCert(`
-----BEGIN CERTIFICATE-----
MIIBhjCB8AIJAK9BK0MsWFFkMA0GCSqGSIb3DQEBBQUAMCgxEDAOBgNVBAoTB0Fj
bWUgQ28xFDASBgNVBAMTC2V4YW1wbGUub3JnMB4XDTEyMDIxMjAyNTIxNVoXDTM5
MDYyOTAyNTIxNVowLDEQMA4GA1UEChMHQWNtZSBDbzEYMBYGA1UEAxMPYmFyLmV4
YW1wbGUub3JnMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOYEWCPLMa9qi0p+206t
yDV2HwnGYTkD5Qt9PR5HwE7K1SBFPlLb/ugexg957+qspO3HwNM86pP2ubC5mpxG
riMCAwEAATANBgkqhkiG9w0BAQUFAAOBgQBlTpoCLBXzr8oqYVziXRJZ4ouKmO9x
4+uAy98e7KyRZlvkUbe5Rfqlp/7bF5BIZNKI/WJWka37GhH+F5e/DxtFG2blogeV
ahDu0PX8A4BzZ4FK3izyZaswkjkYPC1j5VuDSkt5bdCaK+iqjXsbvzIzqdghW3jl
i2oFE8z2wLDkpg==
-----END CERTIFICATE-----
`, `
-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAOYEWCPLMa9qi0p+206tyDV2HwnGYTkD5Qt9PR5HwE7K1SBFPlLb
/ugexg957+qspO3HwNM86pP2ubC5mpxGriMCAwEAAQJADv5ZgHvOUVDwo3qBcS+C
zXlVrJ1x2PWYCJexVDf5ISmX7kc+OxmVmT3YqR4g4IICZq/Quez1wINciKFKnQRv
AQIhAP7vEW+bg2uzrwZqtdIukYoPIq09/HxDG7yUKJnoJwMLAiEA5vqZpk5eSTUw
Wo1ZFxrasOFjbwtSqt8rtHueO0q2cEkCIFSSIHmi4HUhNaXuToT8V+Gx5bINBy59
4Lytdc6g2hhDAiBqEgsdZD/IPrTF4MNY6Owk7lxLUlfUQEhBycMQV28QgQIgUupd
13zLODdBxjUoFSEzzxyG2o+R2QbO9dPvTscr/E8=
-----END RSA PRIVATE KEY-----
`)
	certTable = map[string]*Certificate{
		"example.org": certExampleOrg,
		"foo.example.org": certFooExampleOrg,
		"bar.example.org": certBarExampleOrg,
	}
)
