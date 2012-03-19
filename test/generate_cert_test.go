package test

import (
	"bytes"
	"crypto/x509"
	"io/ioutil"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	cert, _, err := GenerateCAPair("example.com")

	if err != nil {
		t.Fatalf("Error generating CA certificate: %s", err.Error())
	}

	assert(cert.Version == 3, "Version was not 3", t)

	assertEqual(cert.Subject.CommonName, "example.com", "CommonName", t)
	assertEqual(cert.Subject.Country[0], "US", "Country", t)
	assertEqual(cert.Subject.Province[0], "CA", "Province", t)
	assertEqual(cert.Subject.Locality[0], "SF", "Locality", t)
	assertEqual(cert.Subject.Organization[0], "Cheeseman", "Organization", t)

	assert(bytes.Compare(cert.SubjectKeyId, cert.AuthorityKeyId) == 0, "Cert is not self signed", t)
	assert(cert.IsCA, "Cert lacks X509v3 Basic Constraints CA:TRUE", t)

	err = cert.VerifyHostname("example.com")

	if err != nil {
		t.Fatalf("Error verifying CA certificate hostname: %s", err.Error())
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	chain, err := cert.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   pool,
	})

	if err != nil {
		t.Fatalf("Error verifying a single cert: %s", err.Error())
	}

	assertEqual(len(chain), 1, "Verified Cert Chain", t)
}

func TestGenerateCert(t *testing.T) {
	caCert, caKey, _ := GenerateCAPair("alpha")

	cert, _, err := GenerateCertPair("beta", caCert, caKey)
	if err != nil {
		t.Fatalf("Error generating intermediate certificate: %s", err.Error())
	}

	assert(bytes.Compare(cert.AuthorityKeyId, caCert.SubjectKeyId) == 0, "Cert is not signed by the CA", t)
	assert(!cert.IsCA, "Cert has X509v3 Basic Constraints CA:TRUE", t)
	assert(cert.KeyUsage^x509.KeyUsageCertSign == x509.KeyUsageCertSign, "Cert can sign other certs.", t)

	err = cert.VerifyHostname("beta")

	if err != nil {
		t.Fatalf("Error verifying certificate hostname: %s", err.Error())
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	chain, err := cert.Verify(x509.VerifyOptions{
		DNSName: "beta",
		Roots:   pool,
	})

	if err != nil {
		t.Fatalf("Error verifying a single cert: %s", err.Error())
	}

	assertEqual(len(chain), 1, "Verified Cert Chain", t)
}

func TestTempFilePair(t *testing.T) {
	cert, key, _ := GenerateCAPair("ca")

	certPath, keyPath, err := TempFilePair(cert, key)

	if err != nil {
		t.Fatalf("Error creating temp cert & key files: %s", err.Error())
	}

	_, err = ioutil.ReadFile(certPath)

	if err != nil {
		t.Fatalf("Error reading temp cert file: %s", err.Error())
	}

	_, err = ioutil.ReadFile(keyPath)

	if err != nil {
		t.Fatalf("Error reading temp cert file: %s", err.Error())
	}
}

func assertEqual(actual, expected interface{}, description string, t *testing.T) {
	if actual != expected {
		t.Fatalf("%s Error: %s != %s", description, actual, expected)
	}
}

func assert(result bool, description string, t *testing.T) {
	if !result {
		t.Fatalf("Error: %s", description)
	}
}
