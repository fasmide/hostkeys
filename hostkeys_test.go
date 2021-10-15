package hostkeys

import (
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestManager(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("could not create tempdir: %s", err)
	}

	t.Logf("using %s", dir)

	m := Manager{
		Directory: dir,
	}

	config := ssh.ServerConfig{}

	err = m.Manage(config)
	if err != nil {
		t.Fatalf("broken manager: %s", err)
	}
}
