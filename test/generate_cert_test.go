package test

import (
	"bytes"
	"testing"
)

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
