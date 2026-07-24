package ffu

import "errors"

var (
	// ErrUnsupportedVersion reports a structurally recognizable FFU variant that
	// the current parser does not yet understand safely.
	ErrUnsupportedVersion = errors.New("unsupported FFU version")
	// ErrMalformed reports inconsistent or truncated FFU metadata.
	ErrMalformed = errors.New("malformed FFU image")
)

// Metadata is the read-only result required before any destructive restore plan
// can be considered. Fields will be added only when their bounds and meaning are
// validated against fixtures and the published format contract.
type Metadata struct {
	ImageSizeBytes       uint64
	MinimumDiskSizeBytes uint64
	ChunkSizeBytes       uint64
	PayloadBlockCount    uint64
}
