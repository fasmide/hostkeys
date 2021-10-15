package generator

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"

	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
)

type ED25519 struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (r *ED25519) Name() string {
	return "ed25519"
}

func (r *ED25519) Generate() error {
	var err error
	r.publicKey, r.privateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	return nil
}

func (r *ED25519) Encode(w io.Writer) error {
	b, err := sshkeys.Marshal(r.privateKey, &sshkeys.MarshalOptions{Format: sshkeys.FormatOpenSSHv1})
	if err != nil {
		return err
	}

	_, err = w.Write(b)
	if err != nil {
		return err
	}

	return nil
}

func (r *ED25519) EncodePublic(w io.Writer) error {
	publicED25519Key, err := ssh.NewPublicKey(r.publicKey)
	if err != nil {
		return err
	}

	_, err = w.Write(ssh.MarshalAuthorizedKey(publicED25519Key))
	if err != nil {
		return err
	}
	return nil

}
