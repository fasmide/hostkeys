package hostkeys

import "io"

type Generator interface {
	Generate() error
	Encode(io.Writer) error
	EncodePublic(io.Writer) error
	Name() string
}
