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
)

const (
	qemuSourceDescriptorPath = "/proc/self/fd/3"
	qemuOutputDescriptorPath = "/proc/self/fd/4"
)

type ConsistencyState string

const (
	ConsistencyPassed      ConsistencyState = "passed"
	ConsistencyUnsupported ConsistencyState = "unsupported"
)

// ConvertContainer converts a held raw source descriptor into an already-open
// private output descriptor. qemu-img receives no source device or destination
// pathname and cannot select alternate files.
func ConvertContainer(ctx context.Context, source, output *os.File, sourceSize uint64, format Format, progress ProgressFunc) error {
	if ctx == nil {
		return errors.New("container conversion context is nil")
	}
	if source == nil || output == nil {
		return errors.New("container conversion requires open source and output descriptors")
	}
	if sourceSize == 0 {
		return errors.New("container conversion source size must be greater than zero")
	}
	if !format.Container() {
		return fmt.Errorf("container conversion requires vhd or vhdx, not %q", format)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	outputInfo, err := output.Stat()
	if err != nil {
		return fmt.Errorf("inspect container output descriptor: %w", err)
	}
	if !outputInfo.Mode().IsRegular() {
		return errors.New("container output descriptor is not a regular file")
	}
	if err := output.Truncate(0); err != nil {
		return fmt.Errorf("reset container output descriptor: %w", err)
	}
	qemuFormat, options, executable, err := resolveContainerCommand(format)
	if err != nil {
		return err
	}
	args := []string{
		"convert",
		"-p",
		"-f", "raw",
		"-O", qemuFormat,
		"-o", options,
		"-S", "4k",
		qemuSourceDescriptorPath,
		qemuOutputDescriptorPath,
	}
	stdout := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	stderr := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	progressWriter := newQEMUProgressWriter(stderr, sourceSize, progress)
	command := exec.CommandContext(ctx, executable, args...)
	command.ExtraFiles = []*os.File{source, output}
	command.Stdout = stdout
	command.Stderr = progressWriter
	emit(progress, 0, sourceSize)
	runErr := command.Run()
	if err := contextCommandError(ctx, "convert backup container", stdout, stderr, runErr); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync converted backup container: %w", err)
	}
	convertedInfo, err := output.Stat()
	if err != nil {
		return fmt.Errorf("inspect converted backup container: %w", err)
	}
	if convertedInfo.Size() <= 0 {
		return errors.New("converted backup container is empty")
	}
	emit(progress, sourceSize, sourceSize)
	return nil
}

// CompareContainer requires guest-visible byte equality between the held raw
// source and the converted container. Explicit formats prevent probing.
func CompareContainer(ctx context.Context, source, container *os.File, format Format) error {
	if ctx == nil {
		return errors.New("container comparison context is nil")
	}
	if source == nil || container == nil {
		return errors.New("container comparison requires open source and container descriptors")
	}
	qemuFormat, _, executable, err := resolveContainerCommand(format)
	if err != nil {
		return err
	}
	args := []string{
		"compare",
		"-f", "raw",
		"-F", qemuFormat,
		qemuSourceDescriptorPath,
		qemuOutputDescriptorPath,
	}
	stdout := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	stderr := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	command := exec.CommandContext(ctx, executable, args...)
	command.ExtraFiles = []*os.File{source, container}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	return contextCommandError(ctx, "compare backup container with held source", stdout, stderr, runErr)
}

// CheckContainer runs the non-repairing consistency check supported by QEMU for
// VHDX. QEMU does not support this check for VHD/vpc, which is recorded rather
// than replaced with a weaker guessed validation.
func CheckContainer(ctx context.Context, container *os.File, format Format) (ConsistencyState, error) {
	if ctx == nil {
		return "", errors.New("container consistency context is nil")
	}
	if container == nil {
		return "", errors.New("container consistency check requires an open descriptor")
	}
	if format == FormatVHD {
		return ConsistencyUnsupported, nil
	}
	if format != FormatVHDX {
		return "", fmt.Errorf("container consistency check requires vhd or vhdx, not %q", format)
	}
	qemuFormat, _, executable, err := resolveContainerCommand(format)
	if err != nil {
		return "", err
	}
	args := []string{"check", "--output=json", "-f", qemuFormat, qemuSourceDescriptorPath}
	stdout := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	stderr := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	command := exec.CommandContext(ctx, executable, args...)
	command.ExtraFiles = []*os.File{container}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	if err := contextCommandError(ctx, "check backup container consistency", stdout, stderr, runErr); err != nil {
		return "", err
	}
	if err := validateQEMUJSONObject(stdout.Bytes()); err != nil {
		return "", fmt.Errorf("parse qemu-img check output: %w", err)
	}
	return ConsistencyPassed, nil
}

func resolveContainerCommand(format Format) (string, string, string, error) {
	qemuFormat, err := format.QEMUFormat()
	if err != nil {
		return "", "", "", err
	}
	options, err := format.QEMUOptions()
	if err != nil {
		return "", "", "", err
	}
	executable, err := resolveQEMUImg()
	if err != nil {
		return "", "", "", fmt.Errorf("resolve trusted qemu-img: %w", err)
	}
	return qemuFormat, options, executable, nil
}

func contextCommandError(ctx context.Context, operation string, stdout, stderr *boundedCommandBuffer, runErr error) error {
	if runErr != nil && ctx.Err() != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return ctx.Err()
	}
	return boundedCommandResult(operation, stdout, stderr, runErr)
}

func validateQEMUJSONObject(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return err
	}
	if object == nil {
		return errors.New("qemu output is not a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("qemu output contains trailing JSON value %v", trailing)
		}
		return fmt.Errorf("qemu output has trailing data: %w", err)
	}
	return nil
}
