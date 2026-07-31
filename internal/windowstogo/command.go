//go:build linux

package windowstogo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const bundledWIMExecutable = "/usr/lib/rufusarm64/wimlib-imagex"

// Tests may replace this with a private fixture. Production code never reads an
// environment variable or PATH entry for the destructive direct-NTFS engine.
var wimExecutableOverride string

func commandEnvironment() []string {
	return []string{
		"HOME=/nonexistent",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TZ=UTC",
	}
}

func resolveRequiredTools(plan Plan) (map[string]string, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}
	resolved := make(map[string]string, len(plan.RequiredTools))
	for _, name := range plan.RequiredTools {
		if name == "wimlib-imagex" {
			path, err := resolveWIMExecutable()
			if err != nil {
				return nil, err
			}
			resolved[name] = path
			continue
		}
		path, err := trustedexec.Resolve(name)
		if err != nil {
			return nil, fmt.Errorf("resolve required Windows To Go utility %s: %w", name, err)
		}
		resolved[name] = path
	}
	return resolved, nil
}

func resolveWIMExecutable() (string, error) {
	path := bundledWIMExecutable
	if wimExecutableOverride != "" {
		path = wimExecutableOverride
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("package-owned WIM executable path is not canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect package-owned WIM executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("package-owned WIM executable is not a real executable file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return "", errors.New("package-owned WIM executable must have exactly one link")
	}
	if wimExecutableOverride == "" {
		if stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return "", errors.New("package-owned WIM executable must be root-owned and not group/world writable")
		}
	}
	return path, nil
}

func runTool(ctx context.Context, executable string, args ...string) error {
	_, err := runToolOutput(ctx, executable, 256*1024, args...)
	return err
}

func runToolOutput(ctx context.Context, executable string, limit int, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("windows To Go command context is nil")
	}
	if strings.TrimSpace(executable) == "" || !filepath.IsAbs(executable) {
		return nil, errors.New("windows To Go command executable is not an absolute path")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = "/"
	command.Env = commandEnvironment()
	var stdout, stderr commandBuffer
	stdout.limit = limit
	stderr.limit = 256 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("%s: %w: %s", filepath.Base(executable), err, detail)
		}
		return nil, fmt.Errorf("%s: %w", filepath.Base(executable), err)
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

type commandBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (buffer *commandBuffer) Write(value []byte) (int, error) {
	if buffer.limit <= 0 || buffer.buffer.Len()+len(value) > buffer.limit {
		return 0, errors.New("windows To Go command output exceeds its safe limit")
	}
	return buffer.buffer.Write(value)
}

func (buffer *commandBuffer) Bytes() []byte  { return buffer.buffer.Bytes() }
func (buffer *commandBuffer) String() string { return buffer.buffer.String() }
