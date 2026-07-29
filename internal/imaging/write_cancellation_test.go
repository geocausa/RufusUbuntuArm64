package imaging

import (
	"context"
	"errors"
	"testing"
)

type cancelAfterPartialWriter struct {
	cancel context.CancelFunc
	calls  int
}

func (w *cancelAfterPartialWriter) Write(p []byte) (int, error) {
	w.calls++
	if len(p) == 0 {
		return 0, nil
	}
	w.cancel()
	return 1, nil
}

func TestWriteFullContextCancelsBetweenPartialWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	writer := &cancelAfterPartialWriter{cancel: cancel}
	written, err := writeFullContext(ctx, writer, []byte("partial-write"))
	if written != 1 {
		t.Fatalf("written=%d, want 1", written)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
	if writer.calls != 1 {
		t.Fatalf("writer calls=%d, want cancellation before retry", writer.calls)
	}
}

func TestWriteFullContextDoesNotWriteWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer := &cancelAfterPartialWriter{cancel: func() {}}
	written, err := writeFullContext(ctx, writer, []byte("no-write"))
	if written != 0 || writer.calls != 0 {
		t.Fatalf("cancelled write mutated output: written=%d calls=%d", written, writer.calls)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}

func TestWriteFullContextRejectsNilContext(t *testing.T) {
	written, err := writeFullContext(nil, &cancelAfterPartialWriter{cancel: func() {}}, []byte("data"))
	if written != 0 || err == nil {
		t.Fatalf("nil context result: written=%d error=%v", written, err)
	}
}
