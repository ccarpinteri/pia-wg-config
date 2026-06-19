//go:build !linux

package main

import (
	"errors"
	"os"
)

func validateConstrainedDescriptor(file *os.File, want constrainedFDMode) error {
	return errors.New("constrained generation requires linux pipe descriptors")
}
