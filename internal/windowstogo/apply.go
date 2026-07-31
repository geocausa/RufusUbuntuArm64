//go:build linux

package windowstogo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var errTargetIO = errors.New("windows To Go target I/O failure")

const (
	applyHealthPollInterval = time.Second
	applyOutputLimit        = 256 * 1024
)

var wimApplyPercentPattern = regexp.MustCompile(`^Extracting file data:.*\(([0-9]{1,3})%\) done$`)

type targetHealthMonitor interface {
	Check() error
}

type sysfsTargetHealth struct {
	devicePath       string
	expectedDeviceID uint64
	deviceLink       string
	counterPath      string
	statePath        string
	baselineErrors   uint64
}

func newTargetHealthMonitor(devicePath string, expectedDeviceID uint64) (targetHealthMonitor, error) {
	if !filepath.IsAbs(devicePath) || filepath.Dir(filepath.Clean(devicePath)) != "/dev" {
		return nil, errors.New("windows To Go health monitor requires a canonical whole-device path")
	}
	info, err := os.Stat(devicePath)
	if err != nil {
		return nil, fmt.Errorf("inspect Windows To Go health target: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return nil, errors.New("windows To Go health target is not a block device")
	}
	if expectedDeviceID == 0 || uint64(stat.Rdev) != expectedDeviceID {
		return nil, errors.New("windows To Go health target identity changed")
	}

	name := filepath.Base(devicePath)
	classPath := filepath.Join("/sys/class/block", name)
	deviceLink, err := filepath.EvalSymlinks(filepath.Join(classPath, "device"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Loop and virtual block devices do not necessarily expose a SCSI-style
			// device directory or I/O error counter. Their normal command failure
			// path remains authoritative.
			return nil, nil
		}
		return nil, fmt.Errorf("resolve Windows To Go target health path: %w", err)
	}
	if deviceLink != "/sys/devices" && !strings.HasPrefix(deviceLink, "/sys/devices/") {
		return nil, errors.New("windows To Go target health path escaped sysfs")
	}

	counterPath := filepath.Join(classPath, "device", "ioerr_cnt")
	baseline, err := readIOErrorCounter(counterPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read Windows To Go target I/O error baseline: %w", err)
	}
	statePath := filepath.Join(classPath, "device", "state")
	if _, err := os.Stat(statePath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect Windows To Go target state: %w", err)
		}
		statePath = ""
	}
	return &sysfsTargetHealth{
		devicePath:       devicePath,
		expectedDeviceID: expectedDeviceID,
		deviceLink:       deviceLink,
		counterPath:      counterPath,
		statePath:        statePath,
		baselineErrors:   baseline,
	}, nil
}

func (monitor *sysfsTargetHealth) Check() error {
	if monitor == nil {
		return nil
	}
	info, err := os.Stat(monitor.devicePath)
	if err != nil {
		return fmt.Errorf("%w: selected target disappeared: %v", errTargetIO, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&syscall.S_IFMT != syscall.S_IFBLK || uint64(stat.Rdev) != monitor.expectedDeviceID {
		return fmt.Errorf("%w: selected target path no longer identifies the reviewed block device", errTargetIO)
	}
	currentLink, err := filepath.EvalSymlinks(filepath.Join("/sys/class/block", filepath.Base(monitor.devicePath), "device"))
	if err != nil {
		return fmt.Errorf("%w: target sysfs identity disappeared: %v", errTargetIO, err)
	}
	if currentLink != monitor.deviceLink {
		return fmt.Errorf("%w: target sysfs identity changed", errTargetIO)
	}
	currentErrors, err := readIOErrorCounter(monitor.counterPath)
	if err != nil {
		return fmt.Errorf("%w: read target I/O error counter: %v", errTargetIO, err)
	}
	if err := evaluateTargetHealth(monitor.baselineErrors, currentErrors, monitor.readState()); err != nil {
		return err
	}
	return nil
}

func (monitor *sysfsTargetHealth) readState() string {
	if monitor.statePath == "" {
		return ""
	}
	value, err := os.ReadFile(monitor.statePath)
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(value))
}

func readIOErrorCounter(path string) (uint64, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(value))
	if text == "" {
		return 0, errors.New("empty kernel I/O error counter")
	}
	count, err := strconv.ParseUint(text, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid kernel I/O error counter %q", text)
	}
	return count, nil
}

func evaluateTargetHealth(baselineErrors, currentErrors uint64, state string) error {
	if currentErrors != baselineErrors {
		return fmt.Errorf("%w: kernel I/O error counter changed from %d to %d", errTargetIO, baselineErrors, currentErrors)
	}
	if state != "" && state != "running" {
		return fmt.Errorf("%w: kernel device state is %q", errTargetIO, state)
	}
	return nil
}

func splitCommandRecords(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for index, value := range data {
		if value != '\r' && value != '\n' {
			continue
		}
		advance = index + 1
		if value == '\r' && advance < len(data) && data[advance] == '\n' {
			advance++
		}
		return advance, data[:index], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func parseWIMApplyPercent(line string) (int, bool) {
	matches := wimApplyPercentPattern.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 2 {
		return 0, false
	}
	percent, err := strconv.Atoi(matches[1])
	if err != nil || percent < 0 || percent > 100 {
		return 0, false
	}
	return percent, true
}

func routineWIMApplyLine(line string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "Applying image ") || line == "Done applying WIM image."
}

type commandTranscript struct {
	mutex     sync.Mutex
	builder   strings.Builder
	limit     int
	truncated bool
}

func (transcript *commandTranscript) add(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	transcript.mutex.Lock()
	defer transcript.mutex.Unlock()
	if transcript.limit <= 0 || transcript.builder.Len()+len(line)+1 > transcript.limit {
		transcript.truncated = true
		return
	}
	if transcript.builder.Len() > 0 {
		transcript.builder.WriteByte('\n')
	}
	transcript.builder.WriteString(line)
}

func (transcript *commandTranscript) String() string {
	transcript.mutex.Lock()
	defer transcript.mutex.Unlock()
	value := transcript.builder.String()
	if transcript.truncated {
		if value != "" {
			value += "\n"
		}
		value += "[additional command output omitted]"
	}
	return value
}

func runWIMApply(
	ctx context.Context,
	executable string,
	args []string,
	message string,
	total uint64,
	health targetHealthMonitor,
	pollInterval time.Duration,
	emit EventFunc,
) error {
	if ctx == nil {
		return errors.New("windows To Go apply context is nil")
	}
	if strings.TrimSpace(executable) == "" || !filepath.IsAbs(executable) {
		return errors.New("windows To Go WIM executable is not an absolute path")
	}
	if len(args) == 0 || args[0] != "apply" || total == 0 {
		return errors.New("windows To Go WIM apply requires exact arguments and expanded size")
	}
	if pollInterval <= 0 {
		pollInterval = applyHealthPollInterval
	}

	applyCtx, cancelApply := context.WithCancelCause(ctx)
	defer cancelApply(nil)
	command := exec.CommandContext(applyCtx, executable, args...)
	command.Dir = "/"
	command.Env = commandEnvironment()
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open WIM apply output: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("open WIM apply error output: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start WIM apply: %w", err)
	}

	var emitMutex sync.Mutex
	safeEmit := func(event Event) {
		emitMutex.Lock()
		defer emitMutex.Unlock()
		sendEvent(emit, event)
	}
	started := time.Now()
	lastPercent := -1
	var progressMutex sync.Mutex
	reportProgress := func(percent int) {
		progressMutex.Lock()
		defer progressMutex.Unlock()
		if percent <= lastPercent {
			return
		}
		lastPercent = percent
		done := total * uint64(percent) / 100
		if percent == 100 {
			done = total
		}
		rate := float64(0)
		if elapsed := time.Since(started).Seconds(); elapsed > 0 && done > 0 {
			rate = float64(done) / elapsed
		}
		safeEmit(Event{Stage: "apply", Message: message, Done: done, Total: total, Rate: rate})
	}

	var transcript commandTranscript
	transcript.limit = applyOutputLimit
	streamResult := make(chan error, 2)
	relay := func(label string, reader io.Reader) {
		scanner := bufio.NewScanner(reader)
		scanner.Split(splitCommandRecords)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if percent, ok := parseWIMApplyPercent(line); ok {
				reportProgress(percent)
				continue
			}
			if routineWIMApplyLine(line) {
				continue
			}
			transcript.add(line)
			safeEmit(Event{Stage: "log", Message: line})
		}
		scanErr := scanner.Err()
		if scanErr != nil {
			cancelApply(fmt.Errorf("read WIM apply %s: %w", label, scanErr))
		}
		streamResult <- scanErr
	}
	go relay("output", stdout)
	go relay("error output", stderr)

	healthFailure := make(chan error, 1)
	if health != nil {
		go func() {
			ticker := time.NewTicker(pollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-applyCtx.Done():
					return
				case <-ticker.C:
					if err := health.Check(); err != nil {
						safeEmit(Event{
							Stage:   "target_io_error",
							Message: "The target reported a hardware I/O failure. Windows image application is being stopped; do not unplug it until RufusArm64 confirms that writing has stopped.",
						})
						healthFailure <- err
						cancelApply(err)
						return
					}
				}
			}
		}()
	}

	stdoutErr := <-streamResult
	stderrErr := <-streamResult
	waitErr := command.Wait()
	cancelApply(nil)

	if stdoutErr != nil {
		return fmt.Errorf("read WIM apply output: %w", stdoutErr)
	}
	if stderrErr != nil {
		return fmt.Errorf("read WIM apply output: %w", stderrErr)
	}
	select {
	case healthErr := <-healthFailure:
		return healthErr
	default:
	}
	if ctx.Err() != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return ctx.Err()
	}
	if waitErr != nil {
		detail := strings.TrimSpace(transcript.String())
		if detail != "" {
			return fmt.Errorf("%s: %w: %s", filepath.Base(executable), waitErr, detail)
		}
		return fmt.Errorf("%s: %w", filepath.Base(executable), waitErr)
	}
	reportProgress(100)
	return nil
}
