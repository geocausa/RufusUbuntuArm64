package imaging

import (
	"fmt"
	"io"
	"sync"
	"time"
)

const compressedContainerProgressInterval = 200 * time.Millisecond

// compressedContainerProgressReader reports consumption of the already
// identity-bound compressed container. This gives callers a trustworthy
// percentage without trusting format-specific expanded-size metadata such as
// gzip's modulo-2^32 footer or running a second decompression pass.
type compressedContainerProgressReader struct {
	reader   io.Reader
	total    uint64
	progress PrepareProgressFunc

	mu       sync.Mutex
	done     uint64
	lastEmit time.Time
	complete bool
}

func newCompressedContainerProgressReader(reader io.Reader, total uint64, progress PrepareProgressFunc) *compressedContainerProgressReader {
	return &compressedContainerProgressReader{
		reader:   reader,
		total:    total,
		progress: progress,
		lastEmit: time.Now().Add(-compressedContainerProgressInterval),
	}
}

func (r *compressedContainerProgressReader) Read(data []byte) (int, error) {
	n, readErr := r.reader.Read(data)
	if n <= 0 {
		return n, readErr
	}

	r.mu.Lock()
	next, addErr := checkedImageAdd("compressed container progress", r.done, uint64(n))
	if addErr == nil && r.total > 0 && next > r.total {
		addErr = fmt.Errorf("compressed image reader consumed %d bytes, beyond the identity-bound container size of %d", next, r.total)
	}
	if addErr != nil {
		r.mu.Unlock()
		return n, addErr
	}
	r.done = next
	now := time.Now()
	emit := now.Sub(r.lastEmit) >= compressedContainerProgressInterval
	// Even when the decoder consumes every byte, 100% is reserved for Complete,
	// after the caller has verified the pinned identity and source hold.
	if r.total > 0 && r.done == r.total {
		emit = false
	}
	var event PrepareProgress
	if emit {
		r.lastEmit = now
		event = r.eventLocked(r.done)
	}
	r.mu.Unlock()

	if emit {
		emitPrepare(r.progress, event)
	}
	return n, readErr
}

// Complete is called only after the complete container has been authenticated.
// A decoder may legitimately stop before trailing container bytes, so the final
// 100% event is bound to successful full-container authentication rather than to
// decoder consumption alone.
func (r *compressedContainerProgressReader) Complete() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.complete {
		r.mu.Unlock()
		return
	}
	r.complete = true
	if r.total > 0 {
		r.done = r.total
	}
	event := r.eventLocked(r.done)
	r.mu.Unlock()
	emitPrepare(r.progress, event)
}

func (r *compressedContainerProgressReader) eventLocked(done uint64) PrepareProgress {
	return PrepareProgress{
		Stage:   "prepare_container",
		Message: "Reading and authenticating the compressed image container…",
		Done:    done,
		Total:   r.total,
	}
}
