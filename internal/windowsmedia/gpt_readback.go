//go:build linux

package windowsmedia

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
)

type gptMetadataRegion struct {
	offset uint64
	data   []byte
	name   string
}

func verifyGPTMetadata(target io.ReaderAt, regions []gptMetadataRegion) error {
	if target == nil {
		return errors.New("nil GPT verification target")
	}
	for _, region := range regions {
		actual := make([]byte, len(region.data))
		if err := readGPTMetadataAt(target, actual, region.offset); err != nil {
			return fmt.Errorf("read back %s: %w", region.name, err)
		}
		if !bytes.Equal(actual, region.data) {
			return fmt.Errorf("%s readback does not match the bytes written", region.name)
		}
	}
	return nil
}

func readGPTMetadataAt(target io.ReaderAt, destination []byte, offset uint64) error {
	if offset > uint64(math.MaxInt64) || uint64(len(destination)) > uint64(math.MaxInt64)-offset {
		return errors.New("GPT metadata read exceeds the supported signed file-offset range")
	}
	for done := 0; done < len(destination); {
		n, err := target.ReadAt(destination[done:], int64(offset)+int64(done))
		done += n
		if err != nil {
			if errors.Is(err, io.EOF) && done == len(destination) {
				break
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}
