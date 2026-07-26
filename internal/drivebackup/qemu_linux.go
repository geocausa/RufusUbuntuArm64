//go:build linux

package drivebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const (
	maxQEMUDiagnosticBytes = 64 * 1024
	containerReserveFloor  = 64 * 1024 * 1024
	containerReserveScale  = 8
)

// ContainerMeasure is the destination-space policy used before a container
// capture starts. FullyAllocatedBytes is the conservative admission bound.
// RequiredBytes is an optional independently measured sparse minimum and is zero
// when the selected output driver does not implement reliable measurement.
type ContainerMeasure struct {
	RequiredBytes       uint64 `json:"required_bytes"`
	FullyAllocatedBytes uint64 `json:"fully_allocated_bytes"`
}

var resolveQEMUImg = func() (string, error) {
	return trustedexec.Resolve("qemu-img")
}

// MeasureContainer validates the fixed converter policy and returns an explicit
// conservative allocation bound without opening the source device. Ubuntu's
// qemu-img VPC and VHDX output drivers do not implement `qemu-img measure`, so
// planning reserves the complete logical source plus 12.5%, with a minimum
// 64 MiB metadata margin. This is an admission policy, not a sparse-size promise.
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
	if _, err := format.QEMUFormat(); err != nil {
		return ContainerMeasure{}, err
	}
	if _, err := format.QEMUOptions(); err != nil {
		return ContainerMeasure{}, err
	}
	if _, err := resolveQEMUImg(); err != nil {
		return ContainerMeasure{}, fmt.Errorf("resolve trusted qemu-img: %w", err)
	}

	reserve := sourceSize / containerReserveScale
	if sourceSize%containerReserveScale != 0 {
		reserve++
	}
	if reserve < containerReserveFloor {
		reserve = containerReserveFloor
	}
	if sourceSize > math.MaxUint64-reserve {
		return ContainerMeasure{}, errors.New("container allocation bound overflows the supported byte range")
	}
	return ContainerMeasure{FullyAllocatedBytes: sourceSize + reserve}, nil
}

// parseContainerMeasure retains strict parsing for output drivers that may gain
// reliable qemu-img measurement support later. VHD and VHDX planning does not
// currently consume this parser because those Ubuntu QEMU drivers reject measure.
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
