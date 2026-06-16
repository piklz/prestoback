package backup

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pi/prestoback/internal/config"
)

// PushToRemote copies a backup archive to a remote Pi via rsync over SSH.
func PushToRemote(archivePath string, remote config.RemoteTarget) error {
	if err := ensureRemoteDir(remote); err != nil {
		return fmt.Errorf("ensure remote dir: %w", err)
	}

	dest := fmt.Sprintf("%s@%s:%s/", remote.User, remote.Host, remote.Path)
	args := buildRsyncArgs(remote, archivePath, dest)
	log.Printf("rsync: %s", strings.Join(args, " "))

	cmd := exec.Command("rsync", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync failed: %w\n%s", err, out)
	}
	return nil
}

// PullFromRemote downloads all archives for appID from the remote.
func PullFromRemote(localDir string, remote config.RemoteTarget, appID string) error {
	if err := ensureLocalDir(localDir); err != nil {
		return err
	}
	remoteSrc := fmt.Sprintf("%s@%s:%s/%s/", remote.User, remote.Host, remote.Path, appID)
	args := buildRsyncArgs(remote, remoteSrc, filepath.Join(localDir, appID)+"/")
	log.Printf("rsync pull: %s", strings.Join(args, " "))

	cmd := exec.Command("rsync", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync pull failed: %w\n%s", err, out)
	}
	return nil
}

func buildRsyncArgs(remote config.RemoteTarget, src, dest string) []string {
	args := []string{"-avz", "--progress"}

	// NTFS destinations report 1-second timestamp granularity, which causes rsync
	// to see every file as "changed". --modify-window=1 suppresses that.
	if remote.ModifyWindow {
		args = append(args, "--modify-window=1")
	}

	sshOpts := fmt.Sprintf("ssh -p %d -o StrictHostKeyChecking=no -o ConnectTimeout=10", remote.Port)
	if remote.KeyFile != "" {
		sshOpts += " -i " + remote.KeyFile
	}
	args = append(args, "-e", sshOpts, src, dest)
	return args
}

func ensureRemoteDir(remote config.RemoteTarget) error {
	sshArgs := []string{
		"-p", fmt.Sprintf("%d", remote.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=10",
	}
	if remote.KeyFile != "" {
		sshArgs = append(sshArgs, "-i", remote.KeyFile)
	}
	sshArgs = append(sshArgs,
		fmt.Sprintf("%s@%s", remote.User, remote.Host),
		fmt.Sprintf("mkdir -p %s", remote.Path),
	)
	cmd := exec.Command("ssh", sshArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh mkdir: %w\n%s", err, out)
	}
	return nil
}

func ensureLocalDir(dir string) error {
	cmd := exec.Command("mkdir", "-p", dir)
	return cmd.Run()
}
