package hostkeys

import "io"

// Generator is able to generate a specific type of key
// and export both private and public parts
type Generator interface {
	// Generate should do actual key generation
	Generate() error

	// Encode should write out the private key in openssh-key-v1 format
	Encode(io.Writer) error

	// EncodePublic should write out the public key, in openssh's authorized_key format
	EncodePublic(io.Writer) error

	// Name should provide the type of key
	Name() string
}
