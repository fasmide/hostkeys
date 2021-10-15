package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"

	"golang.org/x/crypto/ssh"
)

type RSA struct {
	BitSize int

	privateKey *rsa.PrivateKey
}

func (r *RSA) Name() string {
	return "rsa"
}

func (r *RSA) Generate() error {
	// make sure a bitsize is set
	if r.BitSize == 0 {
		r.BitSize = 4096
	}

	// Private Key generation
	var err error
	r.privateKey, err = rsa.GenerateKey(rand.Reader, r.BitSize)
	if err != nil {
		return err
	}

	// Validate Private Key
	err = r.privateKey.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (r *RSA) Encode(w io.Writer) error {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(r.privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	return pem.Encode(w, &privBlock)
}

func (r *RSA) EncodePublic(w io.Writer) error {
	publicRsaKey, err := ssh.NewPublicKey(r.privateKey)
	if err != nil {
		return err
	}

	_, err = w.Write(ssh.MarshalAuthorizedKey(publicRsaKey))
	if err != nil {
		return err
	}
	return nil

}
