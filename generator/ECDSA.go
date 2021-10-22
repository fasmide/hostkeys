package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/fasmide/hostkeys/internal/marshal"
	"golang.org/x/crypto/ssh"
)

type ECDSA struct {
	Curve   elliptic.Curve
	Comment string

	privateKey *ecdsa.PrivateKey
}

func (e *ECDSA) Name() string {
	return "ecdsa"
}

func (e *ECDSA) Generate() error {
	// lets pick a default curve
	// https://github.com/openssh/openssh-portable/blob/master/ssh-keygen.c#L89
	if e.Curve == nil {
		e.Curve = elliptic.P256()
	}

	var err error
	e.privateKey, err = ecdsa.GenerateKey(e.Curve, rand.Reader)
	if err != nil {
		return err
	}

	return nil
}

func (e *ECDSA) Encode(w io.Writer) error {
	block, err := marshal.MarshalPrivateKey(e.privateKey, e.Comment)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %w", err)
	}

	return pem.Encode(w, block)
}

func (e *ECDSA) EncodePublic(w io.Writer) error {
	publicecdsaKey, err := ssh.NewPublicKey(&e.privateKey.PublicKey)
	if err != nil {
		return err
	}

	_, err = w.Write(ssh.MarshalAuthorizedKey(publicecdsaKey))
	if err != nil {
		return err
	}
	return nil

}
