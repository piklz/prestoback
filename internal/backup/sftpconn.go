package backup

// sftpconn.go — a thin connection helper over golang.org/x/crypto/ssh +
// github.com/pkg/sftp. Every SFTP-kind operation in remote.go dials fresh
// (SFTP/SSH connections are cheap to establish and this avoids any
// connection-pool lifecycle to manage for what is, at most, a few
// operations per backup run) and closes cleanly via the returned closer.
//
// Auth: password OR private key (both are fine as non-interactive, non-
// OAuth credentials — see remote.go's package comment for why that
// property matters here). Host key checking: if KnownHostsPath is set, it
// verifies strictly against that file (standard `ssh-keyscan` output — run
// that once against your NAS and mount the result in, same mounted-file
// pattern the compose file already uses for ComposeFile); if left blank,
// it accepts any host key. That default is deliberately permissive rather
// than silently insecure-by-surprise: this is documented plainly in the
// UI and in RemoteTarget's own field comment, and matches the trust model
// of a home LAN NAS target reachable only inside the user's own network —
// the same posture the "mount" kind already has (a bind-mounted share has
// no host-key concept at all). Security-conscious setups should set
// KnownHostsPath.

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const sftpDialTimeout = 15 * time.Second

// sftpDial opens an SSH connection and an SFTP client on top of it. The
// returned close func shuts down both the SFTP client and the underlying
// SSH connection — always call it when done, typically via defer.
func sftpDial(ctx context.Context, t RemoteTarget) (*sftp.Client, func() error, error) {
	if t.SFTPHost == "" {
		return nil, nil, fmt.Errorf("sftp_host is required")
	}
	if t.SFTPUser == "" {
		return nil, nil, fmt.Errorf("sftp_user is required")
	}
	port := t.SFTPPort
	if port == 0 {
		port = 22
	}

	var auths []ssh.AuthMethod
	if t.SFTPPrivateKeyPath != "" {
		keyData, err := os.ReadFile(t.SFTPPrivateKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read private key %q: %w", t.SFTPPrivateKeyPath, err)
		}
		var signer ssh.Signer
		if t.SFTPPrivateKeyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(t.SFTPPrivateKeyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("parse private key %q: %w", t.SFTPPrivateKeyPath, err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if t.SFTPPassword != "" {
		auths = append(auths, ssh.Password(t.SFTPPassword))
	}
	if len(auths) == 0 {
		return nil, nil, fmt.Errorf("either sftp_password or sftp_private_key_path is required")
	}

	hostKeyCallback, err := sftpHostKeyCallback(t.SFTPKnownHostsPath)
	if err != nil {
		return nil, nil, err
	}

	cfg := &ssh.ClientConfig{
		User:            t.SFTPUser,
		Auth:            auths,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sftpDialTimeout,
	}

	addr := fmt.Sprintf("%s:%d", t.SFTPHost, port)
	dialer := net.Dialer{Timeout: sftpDialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("start sftp session: %w", err)
	}

	closeFn := func() error {
		sftpClient.Close()
		return client.Close()
	}
	return sftpClient, closeFn, nil
}

// sftpHostKeyCallback builds a strict known_hosts verifier when path is
// set, or ssh.InsecureIgnoreHostKey() when it's blank — see this file's
// package comment for the reasoning.
func sftpHostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	if path == "" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read known_hosts %q: %w", path, err)
	}
	return parseKnownHosts(data)
}

// parseKnownHosts is a minimal known_hosts parser: exact "host key" line
// matches only (no wildcards, no hashed hostnames, no @revoked/@cert-
// authority markers). That's a deliberately narrow subset of the real
// format — enough to verify a single NAS entry produced by
// `ssh-keyscan your-nas >> known_hosts`, not a general-purpose
// known_hosts implementation. golang.org/x/crypto/ssh/knownhosts exists
// and handles the full format, but pulling it in for this one narrow use
// isn't worth the extra package surface; this covers the actual use case
// (one pinned host) directly.
func parseKnownHosts(data []byte) (ssh.HostKeyCallback, error) {
	type entry struct {
		host string
		key  ssh.PublicKey
	}
	var entries []entry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		keyBytes, err := parseAuthorizedKey(fields[1], fields[2])
		if err != nil {
			continue // skip unparsable lines rather than failing the whole file
		}
		entries = append(entries, entry{host: fields[0], key: keyBytes})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no usable entries found in known_hosts file")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		marshaled := key.Marshal()
		for _, e := range entries {
			if hostsMatch(e.host, hostname, remote) && string(e.key.Marshal()) == string(marshaled) {
				return nil
			}
		}
		return fmt.Errorf("host key for %s not found in known_hosts (or doesn't match) — run `ssh-keyscan %s >> known_hosts` to add it", hostname, hostname)
	}, nil
}

func parseAuthorizedKey(keyType, keyBase64 string) (ssh.PublicKey, error) {
	line := keyType + " " + keyBase64
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return key, err
}

func hostsMatch(entryHost, hostname string, remote net.Addr) bool {
	if entryHost == hostname {
		return true
	}
	// known_hosts commonly stores "host:port" or just the bare IP — accept
	// either against the dialed address too.
	if remote != nil && strings.HasPrefix(remote.String(), entryHost) {
		return true
	}
	return false
}

// sftpPut streams src (exactly size bytes, not buffered) to remotePath on
// the SFTP server, creating parent directories as needed.
func sftpPut(client *sftp.Client, remotePath string, src io.Reader) error {
	if err := sftpMkdirAll(client, sftpDir(remotePath)); err != nil {
		return err
	}
	tmp := remotePath + ".partial"
	f, err := client.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		_ = client.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = client.Remove(tmp)
		return err
	}
	// Atomic-ish rename over the final name, same "never expose a
	// half-written file at the real path" posture copyFileVerified uses
	// locally — SFTP's rename isn't guaranteed atomic on every server the
	// way os.Rename is on a local filesystem, but it's the closest
	// primitive SFTP offers and is what every SFTP-backed tool relies on.
	if err := client.Rename(tmp, remotePath); err != nil {
		_ = client.Remove(tmp)
		return err
	}
	return nil
}

func sftpDir(remotePath string) string {
	if idx := strings.LastIndex(remotePath, "/"); idx >= 0 {
		return remotePath[:idx]
	}
	return "."
}

func sftpMkdirAll(client *sftp.Client, dir string) error {
	if dir == "" || dir == "." || dir == "/" {
		return nil
	}
	if info, err := client.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%q exists on the SFTP server and is not a directory", dir)
		}
		return nil
	}
	if err := sftpMkdirAll(client, sftpDir(dir)); err != nil {
		return err
	}
	if err := client.Mkdir(dir); err != nil {
		// Race-safe: another push landing at the same time may have just
		// created it — only a real failure if it still isn't a directory.
		if info, statErr := client.Stat(dir); statErr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	return nil
}
