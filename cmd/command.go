// File: cmd/command.go
package cmd

import (
	"os/exec"
)

// Commander interface for command execution
type Commander interface {
	Execute(name string, args ...string) ([]byte, error)
}

// RealCommander executes actual system commands
type RealCommander struct{}

func (c RealCommander) Execute(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

// Default commander instance
var cmdExecutor Commander = RealCommander{}

// SetCommander allows changing the commander for tests
func SetCommander(c Commander) {
	cmdExecutor = c
}
