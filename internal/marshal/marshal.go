package marshal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// An exact copy of the diff from this unmerged change:
// https://go-review.googlesource.com/c/crypto/+/218620/
//
// Once the above is merged or another solution is found,
// this should be removed and hostkeys should adopt.
//
// Kept in /internal/ to avoid api leakage

func MarshalPrivateKey(key crypto.PrivateKey, comment string) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, unencryptedOpenSSHMarshaler)
}

func unencryptedOpenSSHMarshaler(PrivKeyBlock []byte) ([]byte, string, string, string, error) {
	key := generateOpenSSHPadding(PrivKeyBlock, 8)
	return key, "none", "none", "", nil
}

type openSSHEncryptFunc func(PrivKeyBlock []byte) (ProtectedKeyBlock []byte, cipherName, kdfName, kdfOptions string, err error)

func marshalOpenSSHPrivateKey(key crypto.PrivateKey, comment string, encrypt openSSHEncryptFunc) (*pem.Block, error) {
	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}
	var pk1 struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}

	// Random check bytes.
	var check uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
		return nil, err
	}

	pk1.Check1 = check
	pk1.Check2 = check
	w.NumKeys = 1

	// Use a []byte directly on ed25519 keys.
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		E := new(big.Int).SetInt64(int64(k.PublicKey.E))
		// Marshal public key:
		// E and N are in reversed order in the public and private key.
		pubKey := struct {
			KeyType string
			E       *big.Int
			N       *big.Int
		}{
			ssh.KeyAlgoRSA,
			E, k.PublicKey.N,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			N       *big.Int
			E       *big.Int
			D       *big.Int
			Iqmp    *big.Int
			P       *big.Int
			Q       *big.Int
			Comment string
		}{
			k.PublicKey.N, E,
			k.D, k.Precomputed.Qinv, k.Primes[0], k.Primes[1],
			comment,
		}
		pk1.Keytype = ssh.KeyAlgoRSA
		pk1.Rest = ssh.Marshal(key)
	case ed25519.PrivateKey:
		pub := make([]byte, ed25519.PublicKeySize)
		priv := make([]byte, ed25519.PrivateKeySize)
		copy(pub, k[ed25519.PublicKeySize:])
		copy(priv, k)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Pub     []byte
		}{
			ssh.KeyAlgoED25519, pub,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			Pub     []byte
			Priv    []byte
			Comment string
		}{
			pub, priv,
			comment,
		}
		pk1.Keytype = ssh.KeyAlgoED25519
		pk1.Rest = ssh.Marshal(key)
	case *ecdsa.PrivateKey:
		var curve, keyType string
		switch name := k.Curve.Params().Name; name {
		case "P-256":
			curve = "nistp256"
			keyType = ssh.KeyAlgoECDSA256
		case "P-384":
			curve = "nistp384"
			keyType = ssh.KeyAlgoECDSA384
		case "P-521":
			curve = "nistp521"
			keyType = ssh.KeyAlgoECDSA521
		default:
			return nil, errors.New("ssh: unhandled elliptic curve " + name)
		}

		pub := elliptic.Marshal(k.Curve, k.PublicKey.X, k.PublicKey.Y)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Curve   string
			Pub     []byte
		}{
			keyType, curve, pub,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			Curve   string
			Pub     []byte
			D       *big.Int
			Comment string
		}{
			curve, pub, k.D,
			comment,
		}
		pk1.Keytype = keyType
		pk1.Rest = ssh.Marshal(key)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}

	var err error
	// Add padding and encrypt the key if necessary.
	w.PrivKeyBlock, w.CipherName, w.KdfName, w.KdfOpts, err = encrypt(ssh.Marshal(pk1))
	if err != nil {
		return nil, err
	}

	b := ssh.Marshal(w)
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(magic), b...),
	}
	return block, nil
}

const magic = "openssh-key-v1\x00"

func generateOpenSSHPadding(block []byte, blockSize int) []byte {
	for i, l := 0, len(block); (l+i)%blockSize != 0; i++ {
		block = append(block, byte(i+1))
	}
	return block
}
