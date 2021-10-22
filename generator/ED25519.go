package generator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/fasmide/hostkeys/internal/marshal"
	"golang.org/x/crypto/ssh"
)

type ED25519 struct {
	Comment string

	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (e *ED25519) Name() string {
	return "ed25519"
}

func (e *ED25519) Generate() error {
	var err error
	e.publicKey, e.privateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	return nil
}

func (e *ED25519) Encode(w io.Writer) error {
	block, err := marshal.MarshalPrivateKey(e.privateKey, e.Comment)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %w", err)
	}

	return pem.Encode(w, block)
}

func (e *ED25519) EncodePublic(w io.Writer) error {
	publicED25519Key, err := ssh.NewPublicKey(e.publicKey)
	if err != nil {
		return err
	}

	_, err = w.Write(ssh.MarshalAuthorizedKey(publicED25519Key))
	if err != nil {
		return err
	}
	return nil

}
