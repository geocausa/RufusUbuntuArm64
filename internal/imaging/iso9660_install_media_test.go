package imaging

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestInspectISO9660WindowsInstallationMarkers(t *testing.T) {
	complete := iso9660WindowsFixture(t, []string{"BOOT.WIM;1", "INSTALL.WIM;1"})
	info, err := InspectReaderAt(bytes.NewReader(complete), int64(len(complete)))
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasISO9660 || !info.HasWindowsBootWIM || !info.HasWindowsInstallPayload || !info.HasWindowsInstallMedia() {
		t.Fatalf("complete Windows markers were not detected: %#v", info)
	}

	missingPayload := iso9660WindowsFixture(t, []string{"BOOT.WIM;1"})
	info, err = InspectReaderAt(bytes.NewReader(missingPayload), int64(len(missingPayload)))
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasWindowsBootWIM || info.HasWindowsInstallPayload || info.HasWindowsInstallMedia() {
		t.Fatalf("boot.wim without an installation payload was accepted: %#v", info)
	}

	linux := iso9660WindowsFixture(t, []string{"GRUB.CFG;1", "VMLINUZ.;1"})
	info, err = InspectReaderAt(bytes.NewReader(linux), int64(len(linux)))
	if err != nil {
		t.Fatal(err)
	}
	if info.HasWindowsBootWIM || info.HasWindowsInstallPayload || info.HasWindowsInstallMedia() {
		t.Fatalf("Linux-style optical media was classified as Windows: %#v", info)
	}
}

func TestInspectMicrosoftUDFBridgeWindowsEvidence(t *testing.T) {
	data := make([]byte, 256*1024)
	pvd := data[16*int(opticalSectorSize) : 17*int(opticalSectorSize)]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	copy(pvd[318:446], "MICROSOFT CORPORATION")
	copy(pvd[446:574], "MICROSOFT CORPORATION, ONE MICROSOFT WAY")
	copy(pvd[574:702], "CDIMAGE 2.56 (01/01/2005 TM)")
	for sector, identifier := range map[int]string{17: "BEA01", 18: "NSR02", 19: "TEA01"} {
		descriptor := data[sector*int(opticalSectorSize) : (sector+1)*int(opticalSectorSize)]
		descriptor[0] = 0
		copy(descriptor[1:6], identifier)
		descriptor[6] = 1
	}
	info, err := InspectReaderAt(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasUDF || !info.HasMicrosoftUDFBridge || !info.HasWindowsInstallMedia() {
		t.Fatalf("Microsoft UDF bridge was not admitted as Windows evidence: %#v", info)
	}

	copy(pvd[318:446], "NOT MICROSOFT")
	info, err = InspectReaderAt(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if info.HasMicrosoftUDFBridge || info.HasWindowsInstallMedia() {
		t.Fatalf("non-Microsoft UDF bridge was accepted: %#v", info)
	}
}

func TestInspectISO9660WindowsMarkersAcceptSupportedPayloadFamilies(t *testing.T) {
	for _, payload := range []string{"INSTALL.WIM;1", "INSTALL.ESD;1", "INSTALL.SWM;1"} {
		t.Run(payload, func(t *testing.T) {
			fixture := iso9660WindowsFixture(t, []string{"BOOT.WIM;1", payload})
			info, err := InspectReaderAt(bytes.NewReader(fixture), int64(len(fixture)))
			if err != nil {
				t.Fatal(err)
			}
			if !info.HasWindowsInstallMedia() {
				t.Fatalf("payload %s was not admitted: %#v", payload, info)
			}
		})
	}
}

func TestInspectISO9660WindowsMarkersRejectAmbiguousSourcesDirectory(t *testing.T) {
	fixture := iso9660WindowsFixture(t, []string{"BOOT.WIM;1", "INSTALL.WIM;1"})
	data := fixture
	rootOffset := 20 * int(opticalSectorSize)
	first := int(data[rootOffset])
	second := int(data[rootOffset+first])
	third := int(data[rootOffset+first+second])
	cursor := rootOffset + first + second + third
	writeISO9660Record(data, cursor, 21, uint32(opticalSectorSize), iso9660DirectoryFlag, []byte("sources"))
	info, err := InspectReaderAt(bytes.NewReader(fixture), int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if info.HasWindowsInstallMedia() {
		t.Fatalf("ambiguous SOURCES directories were accepted: %#v", info)
	}
}

func iso9660WindowsFixture(t *testing.T, sourceNames []string) []byte {
	t.Helper()
	data := make([]byte, 128*1024)
	pvd := data[16*int(opticalSectorSize) : 17*int(opticalSectorSize)]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	binary.LittleEndian.PutUint32(pvd[80:84], uint32(len(data)/int(opticalSectorSize)))
	binary.LittleEndian.PutUint16(pvd[128:130], uint16(opticalSectorSize))
	writeISO9660Record(pvd, 156, 20, uint32(opticalSectorSize), iso9660DirectoryFlag, []byte{0})
	terminator := data[17*int(opticalSectorSize) : 18*int(opticalSectorSize)]
	terminator[0] = 255
	copy(terminator[1:6], "CD001")
	terminator[6] = 1

	root := data[20*int(opticalSectorSize) : 21*int(opticalSectorSize)]
	cursor := 0
	cursor += writeISO9660Record(root, cursor, 20, uint32(opticalSectorSize), iso9660DirectoryFlag, []byte{0})
	cursor += writeISO9660Record(root, cursor, 20, uint32(opticalSectorSize), iso9660DirectoryFlag, []byte{1})
	writeISO9660Record(root, cursor, 21, uint32(opticalSectorSize), iso9660DirectoryFlag, []byte("SOURCES"))

	sources := data[21*int(opticalSectorSize) : 22*int(opticalSectorSize)]
	cursor = 0
	cursor += writeISO9660Record(sources, cursor, 21, uint32(opticalSectorSize), iso9660DirectoryFlag, []byte{0})
	cursor += writeISO9660Record(sources, cursor, 20, uint32(opticalSectorSize), iso9660DirectoryFlag, []byte{1})
	for index, name := range sourceNames {
		cursor += writeISO9660Record(sources, cursor, uint32(30+index), 1, 0, []byte(name))
	}
	return data
}

func writeISO9660Record(data []byte, offset int, extent, size uint32, flags byte, identifier []byte) int {
	recordLength := 33 + len(identifier)
	if len(identifier)%2 == 0 {
		recordLength++
	}
	record := data[offset : offset+recordLength]
	record[0] = byte(recordLength)
	record[1] = 0
	binary.LittleEndian.PutUint32(record[2:6], extent)
	binary.BigEndian.PutUint32(record[6:10], extent)
	binary.LittleEndian.PutUint32(record[10:14], size)
	binary.BigEndian.PutUint32(record[14:18], size)
	record[25] = flags
	binary.LittleEndian.PutUint16(record[28:30], 1)
	binary.BigEndian.PutUint16(record[30:32], 1)
	record[32] = byte(len(identifier))
	copy(record[33:], identifier)
	return recordLength
}
