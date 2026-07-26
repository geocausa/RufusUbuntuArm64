//go:build linux

package drivebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const (
	qemuSourceDescriptorPath = "/proc/self/fd/3"
	qemuOutputDescriptorPath = "/proc/self/fd/4"
	qemuCaptureLimitBytes     = 1024 * 1024
	qemuTerminationGrace     = 2 * time.Second
)

var qemuProgressPattern = regexp.MustCompile(`\(([0-9]+(?:\.[0-9]+)?)/100%\)`)

// SparseMeasure is the conservative destination allocation bound returned by
// qemu-img measure. RequiredBytes is sufficient for the selected sparse format;
// FullyAllocatedBytes is the corresponding non-sparse upper bound.
type SparseMeasure struct {
	RequiredBytes       uint64 `json:"required_bytes"`
	FullyAllocatedBytes uint64 `json:"fully_allocated_bytes"`
}

// ConsistencyState records whether the selected container received an explicit
// qemu-img structural check. QEMU supports this for VHDX but not VHD/vpc.
type ConsistencyState string

const (
	ConsistencyVerified    ConsistencyState = "verified"
	ConsistencyUnsupported ConsistencyState = "unsupported"
)

type qemuCommandResult struct {
	stdout []byte
	stderr []byte
}

type qemuCaptureResult struct {
	channel  string
	data     []byte
	err      error
	overflow bool
}

func resolveQEMUImage() (string, error) {
	return trustedexec.Resolve("qemu-img")
}

// MeasureSparseImage asks the trusted qemu-img binary for a conservative
// allocation bound without opening a source or destination path.
func MeasureSparseImage(ctx context.Context, virtualSize uint64, format ImageFormat) (SparseMeasure, error) {
	binary, err := resolveQEMUImage()
	if err != nil {
		return SparseMeasure{}, fmt.Errorf("resolve trusted qemu-img: %w", err)
	}
	return measureSparseImageWithBinary(ctx, binary, virtualSize, format)
}

func measureSparseImageWithBinary(ctx context.Context, binary string, virtualSize uint64, format ImageFormat) (SparseMeasure, error) {
	if virtualSize == 0 {
		return SparseMeasure{}, errors.New("sparse image virtual size must be positive")
	}
	qemuFormat, err := format.qemuName()
	if err != nil {
		return SparseMeasure{}, err
	}
	result, err := runQEMUCommand(ctx, binary, []string{
		"measure", "--output=json", "-O", qemuFormat, "--size", strconv.FormatUint(virtualSize, 10),
	}, nil)
	if err != nil {
		return SparseMeasure{}, fmt.Errorf("measure %s output: %w", format, err)
	}
	measure, err := parseQEMUMeasure(result.stdout)
	if err != nil {
		return SparseMeasure{}, fmt.Errorf("parse qemu-img measure output: %w", err)
	}
	return measure, nil
}

// ConvertSparseDescriptors converts one held raw source descriptor into one
// already-created empty output descriptor. qemu-img receives no source or
// destination pathname and cannot choose a backing chain or alternate target.
func ConvertSparseDescriptors(ctx context.Context, source, output *os.File, format ImageFormat) ([]float64, error) {
	binary, err := resolveQEMUImage()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted qemu-img: %w", err)
	}
	return convertSparseDescriptorsWithBinary(ctx, binary, source, output, format)
}

func convertSparseDescriptorsWithBinary(ctx context.Context, binary string, source, output *os.File, format ImageFormat) ([]float64, error) {
	if err := validateSparseDescriptors(source, output, true); err != nil {
		return nil, err
	}
	qemuFormat, err := format.qemuName()
	if err != nil {
		return nil, err
	}
	result, err := runQEMUCommand(ctx, binary, []string{
		"convert", "-p", "-f", "raw", "-O", qemuFormat,
		"-o", "subformat=dynamic", "-S", "4k",
		qemuSourceDescriptorPath, qemuOutputDescriptorPath,
	}, []*os.File{source, output})
	if err != nil {
		return nil, fmt.Errorf("convert raw source to %s: %w", format, err)
	}
	progress, err := ParseQEMUProgress(result.stderr)
	if err != nil {
		return nil, fmt.Errorf("parse qemu-img conversion progress: %w", err)
	}
	if progress[len(progress)-1] != 100 {
		return nil, fmt.Errorf("qemu-img conversion ended at %.2f%% instead of 100%%", progress[len(progress)-1])
	}
	return progress, nil
}

// CompareSparseDescriptors requires guest-visible equality between the held raw
// source and the held sparse output. Allocation differences are intentionally
// ignored; a qemu-img exit status other than equality fails closed.
func CompareSparseDescriptors(ctx context.Context, source, output *os.File, format ImageFormat) error {
	binary, err := resolveQEMUImage()
	if err != nil {
		return fmt.Errorf("resolve trusted qemu-img: %w", err)
	}
	return compareSparseDescriptorsWithBinary(ctx, binary, source, output, format)
}

func compareSparseDescriptorsWithBinary(ctx context.Context, binary string, source, output *os.File, format ImageFormat) error {
	if err := validateSparseDescriptors(source, output, false); err != nil {
		return err
	}
	qemuFormat, err := format.qemuName()
	if err != nil {
		return err
	}
	if _, err := runQEMUCommand(ctx, binary, []string{
		"compare", "-f", "raw", "-F", qemuFormat,
		qemuSourceDescriptorPath, qemuOutputDescriptorPath,
	}, []*os.File{source, output}); err != nil {
		return fmt.Errorf("compare raw source with %s output: %w", format, err)
	}
	return nil
}

// CheckSparseDescriptor performs an explicit consistency check when the output
// format supports one. VHD/vpc has no qemu-img check implementation and is
// recorded as unsupported rather than being presented as verified.
func CheckSparseDescriptor(ctx context.Context, output *os.File, format ImageFormat) (ConsistencyState, error) {
	binary, err := resolveQEMUImage()
	if err != nil {
		return "", fmt.Errorf("resolve trusted qemu-img: %w", err)
	}
	return checkSparseDescriptorWithBinary(ctx, binary, output, format)
}

func checkSparseDescriptorWithBinary(ctx context.Context, binary string, output *os.File, format ImageFormat) (ConsistencyState, error) {
	if output == nil {
		return "", errors.New("sparse output descriptor is nil")
	}
	if format == ImageFormatVHD {
		return ConsistencyUnsupported, nil
	}
	qemuFormat, err := format.qemuName()
	if err != nil {
		return "", err
	}
	if _, err := runQEMUCommand(ctx, binary, []string{
		"check", "-f", qemuFormat, qemuSourceDescriptorPath,
	}, []*os.File{output}); err != nil {
		return "", fmt.Errorf("check %s output consistency: %w", format, err)
	}
	return ConsistencyVerified, nil
}

// ParseQEMUProgress validates the carriage-return progress stream emitted by
// qemu-img -p. Values must be finite, monotonic, and inside [0,100].
func ParseQEMUProgress(data []byte) ([]float64, error) {
	matches := qemuProgressPattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil, errors.New("qemu-img did not emit a recognizable progress record")
	}
	progress := make([]float64, 0, len(matches))
	previous := -1.0
	for _, match := range matches {
		value, err := strconv.ParseFloat(string(match[1]), 64)
		if err != nil || value < 0 || value > 100 {
			return nil, fmt.Errorf("invalid qemu-img progress value %q", match[1])
		}
		if value < previous {
			return nil, fmt.Errorf("qemu-img progress moved backwards from %.2f to %.2f", previous, value)
		}
		if value != previous {
			progress = append(progress, value)
			previous = value
		}
	}
	return progress, nil
}

func parseQEMUMeasure(data []byte) (SparseMeasure, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return SparseMeasure{}, err
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return SparseMeasure{}, errors.New("qemu-img measure output is not an object")
	}
	seen := make(map[string]struct{})
	var required, fullyAllocated *uint64
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return SparseMeasure{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return SparseMeasure{}, errors.New("qemu-img measure object contains a non-string member name")
		}
		if _, duplicate := seen[key]; duplicate {
			return SparseMeasure{}, fmt.Errorf("duplicate qemu-img measure member %q", key)
		}
		seen[key] = struct{}{}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return SparseMeasure{}, err
		}
		switch key {
		case "required":
			parsed, err := parseQEMUUnsignedInteger(value, key)
			if err != nil {
				return SparseMeasure{}, err
			}
			required = &parsed
		case "fully-allocated":
			parsed, err := parseQEMUUnsignedInteger(value, key)
			if err != nil {
				return SparseMeasure{}, err
			}
			fullyAllocated = &parsed
		}
	}
	if _, err := decoder.Token(); err != nil {
		return SparseMeasure{}, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return SparseMeasure{}, fmt.Errorf("parse trailing qemu-img measure data: %w", err)
		}
		return SparseMeasure{}, fmt.Errorf("qemu-img measure output contains a trailing JSON value %v", token)
	}
	if required == nil || fullyAllocated == nil {
		return SparseMeasure{}, errors.New("qemu-img measure output is missing required allocation fields")
	}
	if *required == 0 || *fullyAllocated == 0 || *fullyAllocated < *required {
		return SparseMeasure{}, fmt.Errorf("invalid qemu-img allocation bounds: required=%d fully-allocated=%d", *required, *fullyAllocated)
	}
	return SparseMeasure{RequiredBytes: *required, FullyAllocatedBytes: *fullyAllocated}, nil
}

func parseQEMUUnsignedInteger(value any, label string) (uint64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("qemu-img measure member %s is not an integer", label)
	}
	text := number.String()
	if text == "" {
		return 0, fmt.Errorf("qemu-img measure member %s is empty", label)
	}
	for _, character := range text {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("qemu-img measure member %s is not an unsigned integer: %q", label, text)
		}
	}
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("qemu-img measure member %s is out of range: %w", label, err)
	}
	return parsed, nil
}

func validateSparseDescriptors(source, output *os.File, requireEmptyOutput bool) error {
	if source == nil || output == nil {
		return errors.New("sparse conversion requires held source and output descriptors")
	}
	if source.Fd() == output.Fd() {
		return errors.New("sparse source and output descriptors must be different")
	}
	outputInfo, err := output.Stat()
	if err != nil {
		return fmt.Errorf("stat sparse output descriptor: %w", err)
	}
	if !outputInfo.Mode().IsRegular() {
		return errors.New("sparse output descriptor is not a regular file")
	}
	if requireEmptyOutput && outputInfo.Size() != 0 {
		return fmt.Errorf("sparse output descriptor is not empty: %d bytes", outputInfo.Size())
	}
	return nil
}

func runQEMUCommand(ctx context.Context, binary string, args []string, extraFiles []*os.File) (qemuCommandResult, error) {
	if err := ctx.Err(); err != nil {
		return qemuCommandResult{}, err
	}
	binary = filepath.Clean(binary)
	if !filepath.IsAbs(binary) || filepath.Base(binary) != "qemu-img" {
		return qemuCommandResult{}, fmt.Errorf("qemu-img binary must be an absolute canonical path: %q", binary)
	}
	cmd := exec.Command(binary, args...)
	cmd.ExtraFiles = extraFiles
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return qemuCommandResult{}, fmt.Errorf("open qemu-img stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return qemuCommandResult{}, fmt.Errorf("open qemu-img stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return qemuCommandResult{}, fmt.Errorf("start qemu-img: %w", err)
	}

	captures := make(chan qemuCaptureResult, 2)
	go captureQEMUOutput("stdout", stdout, captures)
	go captureQEMUOutput("stderr", stderr, captures)
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()

	var result qemuCommandResult
	var waitErr error
	var terminalErr error
	var waitDone bool
	captureCount := 0
	contextDone := ctx.Done()
	var forceTimer *time.Timer
	var force <-chan time.Time

	requestStop := func(reason error) {
		if terminalErr != nil {
			return
		}
		terminalErr = reason
		contextDone = nil
		if killErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
			terminalErr = fmt.Errorf("%w; terminate qemu-img process group: %v", reason, killErr)
		}
		forceTimer = time.NewTimer(qemuTerminationGrace)
		force = forceTimer.C
	}

	for !waitDone || captureCount < 2 {
		select {
		case captured := <-captures:
			captureCount++
			if captured.channel == "stdout" {
				result.stdout = captured.data
			} else {
				result.stderr = captured.data
			}
			if captured.overflow {
				requestStop(fmt.Errorf("qemu-img %s exceeded the %d-byte capture limit", captured.channel, qemuCaptureLimitBytes))
			} else if captured.err != nil && terminalErr == nil {
				requestStop(fmt.Errorf("read qemu-img %s: %w", captured.channel, captured.err))
			}
		case waitErr = <-wait:
			waitDone = true
			wait = nil
			if forceTimer != nil {
				forceTimer.Stop()
				force = nil
			}
		case <-contextDone:
			requestStop(ctx.Err())
		case <-force:
			force = nil
			if !waitDone {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		}
	}
	if forceTimer != nil {
		forceTimer.Stop()
	}
	if terminalErr != nil {
		return qemuCommandResult{}, terminalErr
	}
	if waitErr != nil {
		diagnostic := strings.TrimSpace(string(result.stderr))
		if diagnostic == "" {
			return qemuCommandResult{}, fmt.Errorf("qemu-img failed: %w", waitErr)
		}
		return qemuCommandResult{}, fmt.Errorf("qemu-img failed: %w: %s", waitErr, diagnostic)
	}
	return result, nil
}

func captureQEMUOutput(channel string, reader io.Reader, result chan<- qemuCaptureResult) {
	data, err := io.ReadAll(io.LimitReader(reader, qemuCaptureLimitBytes+1))
	overflow := len(data) > qemuCaptureLimitBytes
	if overflow {
		data = data[:qemuCaptureLimitBytes]
	}
	result <- qemuCaptureResult{channel: channel, data: data, err: err, overflow: overflow}
}
