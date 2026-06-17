//go:build windows
// +build windows

package api

import "syscall"

type diskStat struct {
	free  uint64
	total uint64
}

func diskUsage(path string) (diskStat, error) {
	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return diskStat{}, err
	}
	if err := syscall.GetDiskFreeSpaceEx(p, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes); err != nil {
		return diskStat{}, err
	}
	return diskStat{
		free:  freeBytesAvailable,
		total: totalNumberOfBytes,
	}, nil
}
