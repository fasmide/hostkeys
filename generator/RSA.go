package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"io"

	"github.com/ScaleFT/sshkeys"
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
