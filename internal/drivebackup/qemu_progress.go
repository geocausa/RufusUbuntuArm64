package drivebackup

import (
	"regexp"
	"strconv"
	"sync"
)

var qemuProgressPattern = regexp.MustCompile(`([0-9]{1,3}(\.[0-9]+)?)/100%`)

// qemuProgressWriter retains bounded diagnostics while translating qemu-img's
// percentage stream into monotonic source-byte progress. It never emits 100%;
// authenticated conversion completion does that after a successful process exit.
type qemuProgressWriter struct {
	diagnostics *boundedCommandBuffer
	total       uint64
	progress    ProgressFunc

	mu       sync.Mutex
	tail     string
	lastDone uint64
}

func newQEMUProgressWriter(diagnostics *boundedCommandBuffer, total uint64, progress ProgressFunc) *qemuProgressWriter {
	return &qemuProgressWriter{diagnostics: diagnostics, total: total, progress: progress}
}

func (writer *qemuProgressWriter) Write(data []byte) (int, error) {
	original := len(data)
	if _, err := writer.diagnostics.Write(data); err != nil {
		return 0, err
	}
	writer.mu.Lock()
	combined := writer.tail + string(data)
	matches := qemuProgressPattern.FindAllStringSubmatch(combined, -1)
	if len(combined) > 256 {
		writer.tail = combined[len(combined)-256:]
	} else {
		writer.tail = combined
	}
	var event *Progress
	for _, match := range matches {
		percentage, err := strconv.ParseFloat(match[1], 64)
		if err != nil || percentage < 0 || percentage > 100 || writer.total == 0 {
			continue
		}
		done := uint64(percentage * float64(writer.total) / 100)
		if done >= writer.total {
			done = writer.total - 1
		}
		if done <= writer.lastDone {
			continue
		}
		writer.lastDone = done
		value := Progress{Done: done, Total: writer.total}
		event = &value
	}
	writer.mu.Unlock()
	if event != nil && writer.progress != nil {
		writer.progress(*event)
	}
	return original, nil
}
