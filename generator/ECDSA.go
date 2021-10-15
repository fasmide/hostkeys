package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"

	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
)

type ECDSA struct {
	Curve      elliptic.Curve
	privateKey *ecdsa.PrivateKey
}

func (r *ECDSA) Name() string {
	return "ecdsa"
}

func (r *ECDSA) Generate() error {
	// lets pick a default curve
	// https://github.com/openssh/openssh-portable/blob/master/ssh-keygen.c#L89
	if r.Curve == nil {
		r.Curve = elliptic.P256()
	}

	var err error
	r.privateKey, err = ecdsa.GenerateKey(r.Curve, rand.Reader)
	if err != nil {
		return err
	}

	return nil
}

func (r *ECDSA) Encode(w io.Writer) error {
	b, err := sshkeys.Marshal(r.privateKey, &sshkeys.MarshalOptions{Format: sshkeys.FormatClassicPEM})
	if err != nil {
		return err
	}

	_, err = w.Write(b)
	if err != nil {
		return err
	}

	return nil
}

func (r *ECDSA) EncodePublic(w io.Writer) error {
	publicecdsaKey, err := ssh.NewPublicKey(&r.privateKey.PublicKey)
	if err != nil {
		return err
	}

	_, err = w.Write(ssh.MarshalAuthorizedKey(publicecdsaKey))
	if err != nil {
		return err
	}
	return nil

}
