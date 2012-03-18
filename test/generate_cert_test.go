package test

import (
	"bytes"
	"crypto/x509"
	"testing"
)

var (
	ca0Cert *x509.Certificate
)

func init() {
	var err error
	ca0Cert, err = GenerateCA("ca0")

	if err != nil {
		panic("Error generating CA certificate: " + err.Error())
	}
}

func TestGenerateCA(t *testing.T) {
	cert, err := GenerateCA("example.com")

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
}

func TestGenerateIntermediate(t *testing.T) {
	cert, err := GenerateIntermediate("example.com", ca0Cert)

	if err != nil {
		t.Fatalf("Error generating intermediate certificate: %s", err.Error())
	}

	assert(bytes.Compare(cert.AuthorityKeyId, ca0Cert.SubjectKeyId) == 0, "Cert is not signed by the CA", t)
	assert(!cert.IsCA, "Cert has X509v3 Basic Constraints CA:TRUE", t)
	assert(cert.KeyUsage & x509.KeyUsageCertSign == x509.KeyUsageCertSign, "Cert cannot sign other certs.", t)
}

func TestGenerateCert(t *testing.T) {
	cert, err := GenerateCert("example.com", ca0Cert)
	if err != nil {
		t.Fatalf("Error generating intermediate certificate: %s", err.Error())
	}

	assert(bytes.Compare(cert.AuthorityKeyId, ca0Cert.SubjectKeyId) == 0, "Cert is not signed by the CA", t)
	assert(!cert.IsCA, "Cert has X509v3 Basic Constraints CA:TRUE", t)
	assert(cert.KeyUsage ^ x509.KeyUsageCertSign == x509.KeyUsageCertSign, "Cert can sign other certs.", t)
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
