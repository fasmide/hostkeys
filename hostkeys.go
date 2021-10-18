package hostkeys

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/fasmide/hostkeys/generator"
	"golang.org/x/crypto/ssh"
)

type Manager struct {
	// Directory where keys are stored
	Directory string

	// NamingScheme, defaults to "<executable>_host_<keytype>_key"
	// must include a %s for inserting keytype
	NamingScheme string

	Keys []Generator
}

func (m *Manager) Manage(c *ssh.ServerConfig) error {
	err := m.defaults()
	if err != nil {
		return fmt.Errorf("hostkeys: default settings failed: %w", err)
	}

	for _, k := range m.Keys {
		signer, err := m.load(k)
		if err == nil {
			c.AddHostKey(signer)
			continue
		}

		if !os.IsNotExist(err) {
			return fmt.Errorf("hostkeys: invalid %s key: %w", k.Name(), err)
		}

		// this key should be generated, it did not exist
		signer, err = m.storeAndLoad(k)
		if err != nil {
			return err
		}

		c.AddHostKey(signer)
	}

	return nil
}

func (m *Manager) storeAndLoad(g Generator) (ssh.Signer, error) {
	err := g.Generate()
	if err != nil {
		return nil, err
	}

	// create private key
	private, err := os.OpenFile(
		path.Join(
			m.Directory,
			fmt.Sprintf(m.NamingScheme, g.Name()),
		),
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600,
	)
	if err != nil {
		return nil, err
	}
	defer private.Close()

	// write private key
	err = g.Encode(private)
	if err != nil {
		return nil, err
	}

	// create public key
	public, err := os.Create(
		path.Join(
			m.Directory,
			fmt.Sprint(fmt.Sprintf(m.NamingScheme, g.Name()), ".pub"),
		),
	)
	if err != nil {
		return nil, err
	}
	defer public.Close()

	// write public key
	err = g.EncodePublic(public)
	if err != nil {
		return nil, err
	}

	// return back a signer based on this new key
	var buffer bytes.Buffer
	err = g.Encode(&buffer)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(buffer.Bytes())
}

func (m *Manager) load(g Generator) (ssh.Signer, error) {
	fd, err := os.Open(
		path.Join(
			m.Directory,
			fmt.Sprintf(m.NamingScheme, g.Name()),
		),
	)
	if err != nil {
		return nil, err
	}

	// something is off we encounter a file larger then 64Kbyte
	b, err := io.ReadAll(io.LimitReader(fd, 1024*64))
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(b)
}

func (m *Manager) defaults() error {
	// is no NamingScheme is set, use a naming scheme similar to openssh
	if m.NamingScheme == "" {
		s, err := os.Readlink("/proc/self/exe")
		if err != nil {
			return fmt.Errorf("unable to read link of /proc/self/exe: %w", err)
		}

		m.NamingScheme = fmt.Sprintf("%s_host_%%s_key", path.Base(s))
	}

	// if no directory was provided, default to the current work directory
	if m.Directory == "" {
		var err error
		m.Directory, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("unable to determine current work directory: %w", err)
		}
	}

	// default set of keys
	if len(m.Keys) == 0 {
		m.Keys = []Generator{
			&generator.RSA{BitSize: 3072},
			&generator.ED25519{},
			&generator.ECDSA{Curve: elliptic.P256()},
		}
	}

	return nil
}
