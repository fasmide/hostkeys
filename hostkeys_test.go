package hostkeys

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestManager(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("could not create tempdir: %s", err)
	}

	t.Logf("using %s", dir)

	t.Run("manager", ManagerTest(dir))
	t.Run("sshkeytest", SshKeyTest(dir))

}

func SshKeyTest(dir string) func(*testing.T) {
	return func(t *testing.T) {
		m := &Manager{
			Directory: dir,
		}

		// manage a dummy config to make it roll
		m.Manage(&ssh.ServerConfig{})

		// for every key, check to see if ssh-keygen is able to parse it
		// and produce a public-key from it, then compare the public keys
		for _, v := range m.Keys {
			cmd := exec.Command("ssh-keygen", "-y", "-f", path.Join(dir, fmt.Sprintf(m.KeyFormat, v.Name())))
			publicKey, err := cmd.Output()
			if err != nil {
				e := err.(*exec.ExitError)
				t.Logf("Stderr from ssh-keygen: %s", e.Stderr)
				t.Fatalf("command failed %+v: %s", cmd, err)
			}

			// check if this public key is exactly like the hostkeys produced one
			fd, err := os.Open(fmt.Sprint(path.Join(dir, fmt.Sprintf(m.KeyFormat, v.Name())), ".pub"))
			if err != nil {
				t.Fatalf("unable to open hostkeys managed public key: %s", err)
			}
			defer fd.Close()

			hostkeysPublicKey, err := io.ReadAll(io.LimitReader(fd, 1024*64))
			if err != nil {
				t.Fatalf("unable to read hostkeys managed public key: %s", err)
			}

			if !bytes.Equal(hostkeysPublicKey, publicKey) {
				t.Fatalf("public keys did not match")
			}

		}
	}
}

func ManagerTest(dir string) func(*testing.T) {
	return func(t *testing.T) {
		m := &Manager{
			Directory: dir,
		}

		config := &ssh.ServerConfig{}

		err := m.Manage(config)
		if err != nil {
			t.Fatalf("broken manager: %s", err)
		}
	}
}
