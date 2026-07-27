//go:build linux

package isocapture

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
)

// runProcessGroup starts the command as a new process group and kills the whole
// group on cancellation. Pdeathsig also prevents provider descendants from
// surviving an unexpected helper-process death.
func runProcessGroup(ctx context.Context, command *exec.Cmd) error {
	if ctx == nil {
		return errors.New("command context is nil")
	}
	if command == nil {
		return errors.New("command is nil")
	}
	if err := ctx.Err(); err != nil {
		return contextCause(ctx, err)
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if command.Process != nil {
			// The leader remains waitable and its PID cannot be reused until Wait,
			// so the negative PID remains bound to this command's process group.
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return contextCause(ctx, ctx.Err())
	}
}
