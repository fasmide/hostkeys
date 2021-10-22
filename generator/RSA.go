package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/fasmide/hostkeys/internal/marshal"
	"golang.org/x/crypto/ssh"
)

type RSA struct {
	BitSize int
	Comment string

	privateKey *rsa.PrivateKey
}

func (r *RSA) Name() string {
	return "rsa"
}

func (r *RSA) Generate() error {
	// make sure a bitsize is set
	// https://github.com/openssh/openssh-portable/blob/master/ssh-keygen.c#L87
	if r.BitSize == 0 {
		r.BitSize = 3072
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
	block, err := marshal.MarshalPrivateKey(r.privateKey, r.Comment)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %w", err)
	}

	return pem.Encode(w, block)
}

func (r *RSA) EncodePublic(w io.Writer) error {
	publicRsaKey, err := ssh.NewPublicKey(&r.privateKey.PublicKey)
	if err != nil {
		return err
	}

	_, err = w.Write(ssh.MarshalAuthorizedKey(publicRsaKey))
	if err != nil {
		return err
	}
	return nil

}
