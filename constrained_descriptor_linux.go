//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func validateConstrainedDescriptor(file *os.File, want constrainedFDMode) error {
	if file == nil {
		return errors.New("invalid descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("descriptor is not a pipe")
	}

	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFL, 0)
	if errno != 0 {
		return errno
	}
	accessMode := int(flags) & syscall.O_ACCMODE
	switch want {
	case constrainedFDRead:
		if accessMode != syscall.O_RDONLY && accessMode != syscall.O_RDWR {
			return fmt.Errorf("descriptor is not readable")
		}
		if err := setConstrainedReadDeadline(file, time.Now().Add(time.Second)); err != nil {
			return err
		}
		if err := setConstrainedReadDeadline(file, time.Time{}); err != nil {
			return err
		}
	case constrainedFDWrite:
		if accessMode != syscall.O_WRONLY && accessMode != syscall.O_RDWR {
			return fmt.Errorf("descriptor is not writable")
		}
		if err := setConstrainedWriteDeadline(file, time.Now().Add(time.Second)); err != nil {
			return err
		}
		if err := setConstrainedWriteDeadline(file, time.Time{}); err != nil {
			return err
		}
	default:
		return errors.New("invalid descriptor mode")
	}
	return nil
}
