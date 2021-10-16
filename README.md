hostkeys

A host key manager for your golang ssh daemons

hostkeys will manage private keys for an `ssh.ServerConfig`. It creates missing private keys if the application is run for the first time and makes sure to reuse them if they already exist. 

Its goal is predictability and does things exactly like one would expect a typical OpenSSH installation to do. 

By default, it manages three keys, rsa 3072 bits, ecdsa P256, and an ed25519 key, similar to running [ssh-keygen -A](https://man7.org/linux/man-pages/man1/ssh-keygen.1.html#:~:text=are%20as%20follows%3A-,-A,-For%20each%20of).

Basic usage:
```
// An SSH server is represented by a ServerConfig, which holds
// certificate details and handles authentication of ServerConns.
config := &ssh.ServerConfig{
    PasswordCallback: func(...) {
        // ... omitted ...
    },

    PublicKeyCallback: func(...) (...) {
        // ... omitted ...
    },
}

manager := &Manager{
    Directory: "/etc/app",
}

err := m.Manage(config)
if err != nil {
    t.Fatalf("hostkeys: %s", err)
}
```

Using existing openssh host keys:
```
manager := &Manager{
    Directory: "/etc/ssh",
    KeyFormat: "ssh_host_%s_key",
}
```

Using stronger keys:
```
manager := &Manager{
    Directory: "/etc/app",
    Keys: []Generator{
		&generator.RSA{BitSize: 4096},
		&generator.ECDSA{Curve: elliptic.P521()},
	}
}
```