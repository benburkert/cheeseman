package sni

import (
	"io/ioutil"
	"testing"
)

func TestNewInMemoryAdapter(t *testing.T) {
	certFile, keyFile := testPair(t)

	pair := certFile + "," + keyFile

	config := map[string]string{
		"foo.example.com": pair,
	}

	adapter, err := NewInMemoryAdapter(config)

	if err != nil {
		t.Fatalf("Error creating an in memory adapter: %s", err.Error())
	}

	nilConfig := adapter.Callback("github.com")

	if nilConfig != nil {
		t.Fatal("An invalid config was returned by the InMemoryAdapter")
	}

	fooConfig := adapter.Callback("foo.example.com")

	if fooConfig == nil {
		t.Fatal("No tls config was found for foo.example.com")
	}
}

func testPair(t *testing.T) (string, string) {
	certFile, err := ioutil.TempFile("", "cert.pem")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err.Error())
	}

	_, err = certFile.WriteString(certExampleOrg)
	if err != nil {
		t.Fatalf("Error writing cert file: %s", err.Error())
	}

	keyFile, err := ioutil.TempFile("", "key.pem")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err.Error())
	}

	_, err = keyFile.WriteString(keyExampleOrg)
	if err != nil {
		t.Fatalf("Error writing key file: %s", err.Error())
	}

	return certFile.Name(), keyFile.Name()
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
)
