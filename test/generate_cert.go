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

func GenerateCA(hostname string) (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Version: 3,

		Subject: pkix.Name{
			CommonName:   hostname,
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"SF"},
			Organization: []string{"Cheeseman"},
		},

		SerialNumber:   serial,
		NotBefore:      time.Now(),
		NotAfter:       time.Now(),
		SubjectKeyId:   keyId,
		AuthorityKeyId: keyId,

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certs, err := x509.ParseCertificates(derBytes)

	if err != nil {
		return nil, err
	}

	if len(certs) != 1 {
		return nil, newError("Failed to generate a parsable certificate")
	}

	return certs[0], nil
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
