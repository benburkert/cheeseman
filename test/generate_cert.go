package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

var (
	maxInt64 int64 = 0x7FFFFFFFFFFFFFFF
	maxBig64       = big.NewInt(maxInt64)
)

type Error struct {
	message string
}

type templateDecorator func(*x509.Certificate) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey, error)

func GenerateCAPair(hostname string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return buildCert(func(template *x509.Certificate) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey, error) {
		template.Subject.CommonName = hostname
		template.AuthorityKeyId = template.SubjectKeyId
		template.KeyUsage = x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.IsCA = true

		return template, template, nil, nil
	})
}

func GenerateCertPair(hostname string, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	return buildCert(func(template *x509.Certificate) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey, error) {
		template.Subject.CommonName = hostname
		template.AuthorityKeyId = parentCert.SubjectKeyId

		return template, parentCert, parentKey, nil
	})
}

func buildCert(decorator templateDecorator) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Version: 3,

		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"SF"},
			Organization: []string{"Cheeseman"},
		},

		SerialNumber: serial,
		NotBefore:    time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:     time.Now().Add(5 * time.Minute).UTC(),
		SubjectKeyId: keyId,
	}

	cert, parentCert, parentKey, err := decorator(&template)
	if err != nil {
		return nil, nil, err
	}

	if parentKey == nil {
		parentKey = priv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, cert, parentCert, &priv.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}

	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}

	if len(certs) != 1 {
		return nil, nil, newError("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}

func randBigInt() (value *big.Int) {
	value, _ = rand.Int(rand.Reader, maxBig64)
	return
}

func randBytes() (bytes []byte) {
	bytes = make([]byte, 20)
	rand.Read(bytes)
	return
}

func newError(message string) error {
	return &Error{
		message: message,
	}
}

func (err *Error) Error() string {
	return err.message
}
