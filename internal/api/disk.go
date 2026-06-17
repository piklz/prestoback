//go:build linux
// +build linux

package api

import "syscall"

type diskStat struct {
	free  uint64
	total uint64
}

func diskUsage(path string) (diskStat, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return diskStat{}, err
	}
	return diskStat{
		free:  s.Bavail * uint64(s.Bsize),
		total: s.Blocks * uint64(s.Bsize),
	}, nil
}
