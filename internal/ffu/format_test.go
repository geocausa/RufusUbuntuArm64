package ffu

import (
	"errors"
	"testing"
)

func TestSentinelErrorsRemainDistinct(t *testing.T) {
	if errors.Is(ErrMalformed, ErrUnsupportedVersion) || errors.Is(ErrUnsupportedVersion, ErrMalformed) {
		t.Fatal("FFU malformed and unsupported-version errors must remain distinguishable")
	}
}

func TestMetadataZeroValueIsNotRestorable(t *testing.T) {
	var metadata Metadata
	if metadata.MinimumDiskSizeBytes != 0 || metadata.ChunkSizeBytes != 0 || metadata.PayloadBlockCount != 0 {
		t.Fatal("zero-value FFU metadata must not imply a restore plan")
	}
}
