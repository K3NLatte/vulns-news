//go:build !linux

package scanjob

import "os/exec"

// Other platforms use CommandContext's direct-child kill; descendants may survive.
func configureProcess(cmd *exec.Cmd) func() { return func() {} }
