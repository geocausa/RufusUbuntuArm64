//go:build linux

package windowstogo

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// GUID is stored in canonical RFC byte order. GPT and Windows BCD encode the
// first three fields little-endian; DiskBytes performs that exact conversion.
type GUID [16]byte

func RandomGUID(reader io.Reader) (GUID, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var value GUID
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return GUID{}, fmt.Errorf("generate GUID: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return value, nil
}

func ParseGUID(value string) (GUID, error) {
	text := strings.ToLower(strings.TrimSpace(value))
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return GUID{}, fmt.Errorf("invalid GUID %q", value)
	}
	hexText := strings.ReplaceAll(text, "-", "")
	decoded, err := hex.DecodeString(hexText)
	if err != nil || len(decoded) != 16 {
		return GUID{}, fmt.Errorf("invalid GUID %q", value)
	}
	var guid GUID
	copy(guid[:], decoded)
	return guid, nil
}

func GUIDFromDiskBytes(value []byte) (GUID, error) {
	if len(value) != 16 {
		return GUID{}, errors.New("on-disk GUID must contain exactly 16 bytes")
	}
	var guid GUID
	binary.BigEndian.PutUint32(guid[0:4], binary.LittleEndian.Uint32(value[0:4]))
	binary.BigEndian.PutUint16(guid[4:6], binary.LittleEndian.Uint16(value[4:6]))
	binary.BigEndian.PutUint16(guid[6:8], binary.LittleEndian.Uint16(value[6:8]))
	copy(guid[8:], value[8:])
	return guid, nil
}

func (guid GUID) DiskBytes() [16]byte {
	var value [16]byte
	binary.LittleEndian.PutUint32(value[0:4], binary.BigEndian.Uint32(guid[0:4]))
	binary.LittleEndian.PutUint16(value[4:6], binary.BigEndian.Uint16(guid[4:6]))
	binary.LittleEndian.PutUint16(value[6:8], binary.BigEndian.Uint16(guid[6:8]))
	copy(value[8:], guid[8:])
	return value
}

func (guid GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(guid[0:4]),
		binary.BigEndian.Uint16(guid[4:6]),
		binary.BigEndian.Uint16(guid[6:8]),
		binary.BigEndian.Uint16(guid[8:10]),
		guid[10:16],
	)
}
