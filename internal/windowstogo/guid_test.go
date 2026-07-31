//go:build linux

package windowstogo

import (
	"bytes"
	"testing"
)

func TestGUIDDiskEncodingMatchesGPTAndBCDByteOrder(t *testing.T) {
	guid, err := ParseGUID("44460D93-5036-46BA-AE83-358E05D8E0E7")
	if err != nil {
		t.Fatal(err)
	}
	if guid.String() != "44460d93-5036-46ba-ae83-358e05d8e0e7" {
		t.Fatalf("GUID string=%q", guid.String())
	}
	want := []byte{0x93, 0x0d, 0x46, 0x44, 0x36, 0x50, 0xba, 0x46, 0xae, 0x83, 0x35, 0x8e, 0x05, 0xd8, 0xe0, 0xe7}
	disk := guid.DiskBytes()
	if !bytes.Equal(disk[:], want) {
		t.Fatalf("disk GUID=%x, want %x", disk, want)
	}
	roundTrip, err := GUIDFromDiskBytes(disk[:])
	if err != nil || roundTrip != guid {
		t.Fatalf("round trip=%s, %v", roundTrip.String(), err)
	}
}

func TestRandomGUIDSetsRFCVersionAndVariant(t *testing.T) {
	guid, err := RandomGUID(bytes.NewReader(bytes.Repeat([]byte{0xff}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if guid[6]>>4 != 4 || guid[8]>>6 != 2 {
		t.Fatalf("version/variant not normalized: %x", guid)
	}
}

func TestGUIDRejectsMalformedInput(t *testing.T) {
	for _, value := range []string{"", "not-a-guid", "44460d93503646baae83358e05d8e0e7", "zzzzzzzz-5036-46ba-ae83-358e05d8e0e7"} {
		if _, err := ParseGUID(value); err == nil {
			t.Fatalf("accepted malformed GUID %q", value)
		}
	}
	if _, err := GUIDFromDiskBytes(make([]byte, 15)); err == nil {
		t.Fatal("accepted short disk GUID")
	}
}
