package backup

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/pi/prestoback/internal/config"
)

// TestRemoteConnection does a quick SSH echo to verify connectivity.
func TestRemoteConnection(remote config.RemoteTarget) error {
	args := []string{
		"-p", fmt.Sprintf("%d", remote.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", fmt.Sprintf("ConnectTimeout=%d", 8),
		"-o", "BatchMode=yes",
	}
	if remote.KeyFile != "" {
		args = append(args, "-i", remote.KeyFile)
	}
	args = append(args,
		fmt.Sprintf("%s@%s", remote.User, remote.Host),
		"echo prestoback-ok",
	)

	cmd := exec.Command("ssh", args...)
	done := make(chan error, 1)
	go func() { _, err := cmd.CombinedOutput(); done <- err }()

	select {
	case err := <-done:
		return err
	case <-time.After(12 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("connection timed out")
	}
}
