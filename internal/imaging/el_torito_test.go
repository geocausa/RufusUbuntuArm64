package imaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	testPVDLBA     = 16
	testBootLBA    = 17
	testEndLBA     = 18
	testCatalogLBA = 20
	testImageLBA   = 30
)

type elToritoFixtureOptions struct {
	validationPlatform byte
	sectionPlatform    bool
	mediaType          byte
	sectorCount        uint16
	imageLBA           uint32
	volumeSectors      uint32
	secondEFI          bool
	secondBootLBA      uint32
	badChecksum        bool
	badKey             bool
	catalogLBA         uint32
}

func elToritoFixture(t testing.TB, options elToritoFixtureOptions) ([]byte, []byte) {
	t.Helper()
	if options.validationPlatform == 0 && !options.sectionPlatform {
		options.validationPlatform = elToritoPlatformEFI
	}
	if options.sectorCount == 0 {
		options.sectorCount = 8
	}
	if options.imageLBA == 0 {
		options.imageLBA = testImageLBA
	}
	if options.volumeSectors == 0 {
		options.volumeSectors = 128
	}
	if options.catalogLBA == 0 {
		options.catalogLBA = testCatalogLBA
	}
	physicalSectors := options.volumeSectors
	if options.catalogLBA+1 > physicalSectors {
		physicalSectors = options.catalogLBA + 1
	}
	imageSectors := options.imageLBA + uint32((uint64(options.sectorCount)*elToritoVirtualSectorSize+uint64(opticalSectorSize)-1)/uint64(opticalSectorSize))
	if imageSectors > physicalSectors {
		physicalSectors = imageSectors
	}
	data := make([]byte, int(physicalSectors)*int(opticalSectorSize))

	pvd := data[testPVDLBA*int(opticalSectorSize) : (testPVDLBA+1)*int(opticalSectorSize)]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	binary.LittleEndian.PutUint32(pvd[80:84], options.volumeSectors)
	binary.BigEndian.PutUint32(pvd[84:88], options.volumeSectors)

	boot := data[testBootLBA*int(opticalSectorSize) : (testBootLBA+1)*int(opticalSectorSize)]
	boot[0] = 0
	copy(boot[1:6], "CD001")
	boot[6] = 1
	copy(boot[7:39], elToritoSystemID[:])
	binary.LittleEndian.PutUint32(boot[71:75], options.catalogLBA)

	end := data[testEndLBA*int(opticalSectorSize) : (testEndLBA+1)*int(opticalSectorSize)]
	end[0] = 255
	copy(end[1:6], "CD001")
	end[6] = 1

	catalog := data[int(options.catalogLBA)*int(opticalSectorSize) : (int(options.catalogLBA)+1)*int(opticalSectorSize)]
	validation := catalog[:32]
	validation[0] = 1
	validation[1] = options.validationPlatform
	copy(validation[4:28], "RufusArm64 El Torito")
	validation[30] = 0x55
	validation[31] = 0xaa
	setElToritoValidationChecksum(validation)
	if options.badChecksum {
		validation[4] ^= 1
	}
	if options.badKey {
		validation[30] = 0
	}

	entryIndex := 1
	if options.sectionPlatform {
		catalog[32] = elToritoNotBootable
		header := catalog[64:96]
		header[0] = elToritoFinalSectionHeader
		header[1] = elToritoPlatformEFI
		binary.LittleEndian.PutUint16(header[2:4], 1)
		entryIndex = 3
	}
	entry := catalog[entryIndex*32 : (entryIndex+1)*32]
	entry[0] = elToritoBootable
	entry[1] = options.mediaType
	binary.LittleEndian.PutUint16(entry[2:4], 0)
	entry[4] = 0
	binary.LittleEndian.PutUint16(entry[6:8], options.sectorCount)
	binary.LittleEndian.PutUint32(entry[8:12], options.imageLBA)

	if options.secondEFI {
		index := entryIndex + 1
		if options.sectionPlatform {
			// Expand the final section count to include the second entry.
			binary.LittleEndian.PutUint16(catalog[66:68], 2)
		} else {
			header := catalog[index*32 : (index+1)*32]
			header[0] = elToritoFinalSectionHeader
			header[1] = elToritoPlatformEFI
			binary.LittleEndian.PutUint16(header[2:4], 1)
			index++
		}
		second := catalog[index*32 : (index+1)*32]
		second[0] = elToritoBootable
		second[1] = elToritoMediaNoEmulation
		binary.LittleEndian.PutUint16(second[6:8], 4)
		secondLBA := options.secondBootLBA
		if secondLBA == 0 {
			secondLBA = options.imageLBA + 4
		}
		binary.LittleEndian.PutUint32(second[8:12], secondLBA)
	}

	declaredLength := uint64(options.sectorCount) * elToritoVirtualSectorSize
	if declaredLength == 0 {
		declaredLength = 1
	}
	if uint64(options.imageLBA)*uint64(opticalSectorSize)+declaredLength > uint64(len(data)) {
		return data, nil
	}
	image := data[uint64(options.imageLBA)*uint64(opticalSectorSize) : uint64(options.imageLBA)*uint64(opticalSectorSize)+declaredLength]
	for index := range image {
		image[index] = byte((index*17 + 23) % 251)
	}
	return data, append([]byte(nil), image...)
}

func setElToritoValidationChecksum(entry []byte) {
	entry[28] = 0
	entry[29] = 0
	var sum uint16
	for offset := 0; offset < 32; offset += 2 {
		sum += binary.LittleEndian.Uint16(entry[offset : offset+2])
	}
	binary.LittleEndian.PutUint16(entry[28:30], uint16(0-sum))
}

func TestPlanAndExtractElToritoUEFIImage(t *testing.T) {
	data, image := elToritoFixture(t, elToritoFixtureOptions{})
	plan, err := PlanElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if plan.EntryIndex != 1 || plan.PlatformID != elToritoPlatformEFI || plan.ImageLBA != testImageLBA {
		t.Fatalf("unexpected plan identity: %#v", plan)
	}
	if plan.ImageLength != uint64(len(image)) || plan.AutoExpandedSmallSectorCount {
		t.Fatalf("unexpected extent: %#v", plan)
	}
	wantDigest := sha256.Sum256(image)
	if plan.ImageSHA256 != hex.EncodeToString(wantDigest[:]) || plan.PlanSHA256 == "" {
		t.Fatalf("unexpected digest plan: %#v", plan)
	}
	second, err := PlanElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil || second.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("plan is not deterministic: first=%#v second=%#v err=%v", plan, second, err)
	}
	var extracted bytes.Buffer
	extractedPlan, err := ExtractElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)), &extracted)
	if err != nil {
		t.Fatal(err)
	}
	if extractedPlan.PlanSHA256 != plan.PlanSHA256 || !bytes.Equal(extracted.Bytes(), image) {
		t.Fatalf("extraction mismatch: plan=%#v bytes=%d", extractedPlan, extracted.Len())
	}
}

func TestPlanElToritoUEFISectionEntry(t *testing.T) {
	data, _ := elToritoFixture(t, elToritoFixtureOptions{
		validationPlatform: 0x00,
		sectionPlatform:    true,
	})
	plan, err := PlanElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if plan.EntryIndex != 3 || plan.PlatformID != elToritoPlatformEFI {
		t.Fatalf("unexpected section plan: %#v", plan)
	}
}

func TestPlanElToritoUEFIAutoExpandsSmallCounts(t *testing.T) {
	const nextLBA = testImageLBA + 0x1000
	volumeSectors := uint32(nextLBA + 16)
	data, _ := elToritoFixture(t, elToritoFixtureOptions{
		sectorCount:   1,
		volumeSectors: volumeSectors,
		secondEFI:     true,
		secondBootLBA: nextLBA,
	})
	// Make the second boot entry non-EFI while keeping its LBA as a boundary.
	catalog := data[testCatalogLBA*int(opticalSectorSize) : (testCatalogLBA+1)*int(opticalSectorSize)]
	catalog[64] = elToritoFinalSectionHeader
	catalog[65] = 0x00
	binary.LittleEndian.PutUint16(catalog[66:68], 1)
	second := catalog[96:128]
	second[0] = elToritoBootable
	second[1] = elToritoMediaNoEmulation
	binary.LittleEndian.PutUint16(second[6:8], 4)
	binary.LittleEndian.PutUint32(second[8:12], nextLBA)

	plan, err := PlanElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	wantLength := uint64(nextLBA-testImageLBA) * uint64(opticalSectorSize)
	if !plan.AutoExpandedSmallSectorCount || plan.ExpansionEndLBA != nextLBA || plan.ImageLength != wantLength {
		t.Fatalf("auto-expanded plan=%#v wantLength=%d", plan, wantLength)
	}
}

func TestPlanElToritoUEFIRejectsMalformedCatalogs(t *testing.T) {
	tests := []struct {
		name    string
		options elToritoFixtureOptions
		want    string
	}{
		{"checksum", elToritoFixtureOptions{badChecksum: true}, "checksum"},
		{"key", elToritoFixtureOptions{badKey: true}, "0x55AA"},
		{"unsupported emulation", elToritoFixtureOptions{mediaType: 4}, "unsupported emulation"},
		{"ambiguous", elToritoFixtureOptions{secondEFI: true}, "ambiguous"},
		{"catalog outside volume", elToritoFixtureOptions{catalogLBA: 200, volumeSectors: 128}, "outside volume"},
		{"image outside volume", elToritoFixtureOptions{imageLBA: 127, sectorCount: 8, volumeSectors: 128}, "outside the ISO volume"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := elToritoFixture(t, tc.options)
			_, err := PlanElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want substring %q", err, tc.want)
			}
		})
	}
}

func TestPlanElToritoUEFIRejectsZeroLengthWithoutExpansion(t *testing.T) {
	data, _ := elToritoFixture(t, elToritoFixtureOptions{sectorCount: 2})
	catalog := data[testCatalogLBA*int(opticalSectorSize) : (testCatalogLBA+1)*int(opticalSectorSize)]
	binary.LittleEndian.PutUint16(catalog[38:40], 0)
	_, err := PlanElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "zero length") {
		t.Fatalf("error=%v", err)
	}
}

func TestElToritoUEFIContextAndWriterErrors(t *testing.T) {
	data, _ := elToritoFixture(t, elToritoFixtureOptions{})
	var nilContext context.Context
	if _, err := PlanElToritoUEFIImage(nilContext, bytes.NewReader(data), int64(len(data))); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanElToritoUEFIImage(cancelled, bytes.NewReader(data), int64(len(data))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	if _, err := ExtractElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)), nil); err == nil || !strings.Contains(err.Error(), "writer is nil") {
		t.Fatalf("nil writer error=%v", err)
	}
	writer := &failingElToritoWriter{}
	if _, err := ExtractElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)), writer); err == nil || !strings.Contains(err.Error(), "forced write failure") {
		t.Fatalf("writer error=%v", err)
	}
}

type failingElToritoWriter struct{}

func (*failingElToritoWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced write failure")
}

type changingElToritoReader struct {
	data       []byte
	imageStart int64
	imageEnd   int64
	imageReads int
}

func (reader *changingElToritoReader) ReadAt(buffer []byte, offset int64) (int, error) {
	if offset >= reader.imageStart && offset < reader.imageEnd {
		reader.imageReads++
		if reader.imageReads > 1 {
			for index := range buffer {
				buffer[index] = 0xa5
			}
			return len(buffer), nil
		}
	}
	if offset >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	n := copy(buffer, reader.data[offset:])
	if n != len(buffer) {
		return n, io.EOF
	}
	return n, nil
}

func TestExtractElToritoUEFIDetectsSourceChange(t *testing.T) {
	data, image := elToritoFixture(t, elToritoFixtureOptions{})
	reader := &changingElToritoReader{
		data:       data,
		imageStart: int64(testImageLBA * int(opticalSectorSize)),
		imageEnd:   int64(testImageLBA*int(opticalSectorSize) + len(image)),
	}
	var output bytes.Buffer
	_, err := ExtractElToritoUEFIImage(context.Background(), reader, int64(len(data)), &output)
	if err == nil || !strings.Contains(err.Error(), "changed between planning and extraction") {
		t.Fatalf("source-change error=%v", err)
	}
}

type changingElToritoCatalogReader struct {
	data         []byte
	catalogStart int64
	catalogReads int
}

func (reader *changingElToritoCatalogReader) ReadAt(buffer []byte, offset int64) (int, error) {
	if offset == reader.catalogStart {
		reader.catalogReads++
		if reader.catalogReads > 1 {
			for index := range buffer {
				buffer[index] = 0x5a
			}
			return len(buffer), nil
		}
	}
	if offset >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	n := copy(buffer, reader.data[offset:])
	if n != len(buffer) {
		return n, io.EOF
	}
	return n, nil
}

func TestExtractElToritoUEFIDetectsCatalogChange(t *testing.T) {
	data, _ := elToritoFixture(t, elToritoFixtureOptions{})
	reader := &changingElToritoCatalogReader{
		data:         data,
		catalogStart: int64(testCatalogLBA * int(opticalSectorSize)),
	}
	var output bytes.Buffer
	_, err := ExtractElToritoUEFIImage(context.Background(), reader, int64(len(data)), &output)
	if err == nil || !strings.Contains(err.Error(), "boot catalog changed between planning and extraction") {
		t.Fatalf("catalog-change error=%v", err)
	}
}

func FuzzPlanElToritoUEFIImageNoPanic(f *testing.F) {
	seed, _ := elToritoFixture(f, elToritoFixtureOptions{})
	f.Add(seed)
	f.Add([]byte("not an ISO"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = PlanElToritoUEFIImage(context.Background(), bytes.NewReader(data), int64(len(data)))
	})
}
