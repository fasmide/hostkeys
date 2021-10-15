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

	// lets see, how a new manager handles these existing keys
	m2 := Manager{
		Directory: dir,
	}

	config2 := ssh.ServerConfig{}

	err = m2.Manage(config2)
	if err != nil {
		t.Fatalf("broken second manager: %s", err)
	}

}
