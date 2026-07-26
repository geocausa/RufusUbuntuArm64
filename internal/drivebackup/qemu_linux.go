//go:build linux

package drivebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const maxQEMUDiagnosticBytes = 64 * 1024

// ContainerMeasure is the conservative destination-space bound returned by the
// trusted qemu-img utility. FullyAllocatedBytes, not expected sparse savings, is
// used for destination preflight.
type ContainerMeasure struct {
	RequiredBytes       uint64 `json:"required_bytes"`
	FullyAllocatedBytes uint64 `json:"fully_allocated_bytes"`
}

var resolveQEMUImg = func() (string, error) {
	return trustedexec.Resolve("qemu-img")
}

// MeasureContainer asks qemu-img for a guaranteed capacity bound using only the
// selected source capacity. It does not open the source device and is therefore
// safe for dry-run planning.
func MeasureContainer(ctx context.Context, sourceSize uint64, format Format) (ContainerMeasure, error) {
	if ctx == nil {
		return ContainerMeasure{}, errors.New("container measurement context is nil")
	}
	if sourceSize == 0 {
		return ContainerMeasure{}, errors.New("container source size must be greater than zero")
	}
	if !format.Container() {
		return ContainerMeasure{}, fmt.Errorf("container measurement requires vhd or vhdx, not %q", format)
	}
	if err := ctx.Err(); err != nil {
		return ContainerMeasure{}, err
	}
	qemuFormat, err := format.QEMUFormat()
	if err != nil {
		return ContainerMeasure{}, err
	}
	options, err := format.QEMUOptions()
	if err != nil {
		return ContainerMeasure{}, err
	}
	executable, err := resolveQEMUImg()
	if err != nil {
		return ContainerMeasure{}, fmt.Errorf("resolve trusted qemu-img: %w", err)
	}
	args := []string{
		"measure",
		"--output=json",
		"-O", qemuFormat,
		"-o", options,
		"--size", strconv.FormatUint(sourceSize, 10),
	}
	stdout := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	stderr := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	if err := boundedCommandResult("measure backup container", stdout, stderr, runErr); err != nil {
		return ContainerMeasure{}, err
	}
	measure, err := parseContainerMeasure(stdout.Bytes())
	if err != nil {
		return ContainerMeasure{}, fmt.Errorf("parse qemu-img measure output: %w", err)
	}
	return measure, nil
}

func parseContainerMeasure(data []byte) (ContainerMeasure, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil {
		return ContainerMeasure{}, err
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return ContainerMeasure{}, errors.New("measure output must be one JSON object")
	}
	seen := make(map[string]struct{}, 3)
	var measure ContainerMeasure
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ContainerMeasure{}, err
		}
		name, ok := token.(string)
		if !ok {
			return ContainerMeasure{}, errors.New("measure output contains a non-string member name")
		}
		if _, duplicate := seen[name]; duplicate {
			return ContainerMeasure{}, fmt.Errorf("measure output contains duplicate member %q", name)
		}
		seen[name] = struct{}{}
		var number json.Number
		switch name {
		case "required":
			if err := decoder.Decode(&number); err != nil {
				return ContainerMeasure{}, fmt.Errorf("decode required size: %w", err)
			}
			measure.RequiredBytes, err = parseJSONUint(number, "required")
		case "fully-allocated":
			if err := decoder.Decode(&number); err != nil {
				return ContainerMeasure{}, fmt.Errorf("decode fully-allocated size: %w", err)
			}
			measure.FullyAllocatedBytes, err = parseJSONUint(number, "fully-allocated")
		case "bitmaps":
			if err := decoder.Decode(&number); err != nil {
				return ContainerMeasure{}, fmt.Errorf("decode bitmaps size: %w", err)
			}
			_, err = parseJSONUint(number, "bitmaps")
		default:
			return ContainerMeasure{}, fmt.Errorf("measure output contains unknown member %q", name)
		}
		if err != nil {
			return ContainerMeasure{}, err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return ContainerMeasure{}, err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return ContainerMeasure{}, errors.New("measure output has an invalid closing token")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return ContainerMeasure{}, fmt.Errorf("measure output contains trailing JSON token %v", token)
		}
		return ContainerMeasure{}, fmt.Errorf("measure output has trailing data: %w", err)
	}
	if measure.RequiredBytes == 0 || measure.FullyAllocatedBytes == 0 {
		return ContainerMeasure{}, errors.New("measure output reports a zero size")
	}
	if measure.FullyAllocatedBytes < measure.RequiredBytes {
		return ContainerMeasure{}, errors.New("fully allocated size is smaller than required size")
	}
	return measure, nil
}

func parseJSONUint(number json.Number, name string) (uint64, error) {
	text := number.String()
	if text == "" || strings.ContainsAny(text, ".eE+-") {
		return 0, fmt.Errorf("%s size is not an unsigned decimal integer", name)
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s size: %w", name, err)
	}
	return value, nil
}

type boundedCommandBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func newBoundedCommandBuffer(limit int) *boundedCommandBuffer {
	return &boundedCommandBuffer{limit: limit}
}

func (buffer *boundedCommandBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = buffer.exceeded || original > 0
		return original, nil
	}
	if len(data) > remaining {
		buffer.exceeded = true
		data = data[:remaining]
	}
	_, _ = buffer.buffer.Write(data)
	return original, nil
}

func (buffer *boundedCommandBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func boundedCommandResult(operation string, stdout, stderr *boundedCommandBuffer, runErr error) error {
	if stdout.exceeded || stderr.exceeded {
		return fmt.Errorf("%s produced output beyond the %d-byte safety limit", operation, maxQEMUDiagnosticBytes)
	}
	if runErr != nil {
		diagnostic := strings.TrimSpace(stderr.buffer.String())
		if diagnostic == "" {
			diagnostic = strings.TrimSpace(stdout.buffer.String())
		}
		if diagnostic == "" {
			return fmt.Errorf("%s: %w", operation, runErr)
		}
		return fmt.Errorf("%s: %w: %s", operation, runErr, diagnostic)
	}
	return nil
}
