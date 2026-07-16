package imaging

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func testRawImage() []byte {
	data := make([]byte, 2*1024*1024)
	data[510], data[511] = 0x55, 0xaa
	entry := data[446:462]
	entry[4] = 0x0c
	binary.LittleEndian.PutUint32(entry[8:12], 2048)
	binary.LittleEndian.PutUint32(entry[12:16], 1024)
	return data
}

func inspectIdentity(t *testing.T, path string) (string, sourcefile.Identity) {
	t.Helper()
	resolved, identity, err := sourcefile.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved, identity
}

func readPrepared(t *testing.T, prepared *PreparedInput) []byte {
	t.Helper()
	data, err := os.ReadFile(prepared.Path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestProbeAndPrepareGZIP(t *testing.T) {
	raw := testRawImage()
	path := filepath.Join(t.TempDir(), "disk.img.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	resolved, identity := inspectIdentity(t, path)
	source, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := ProbeInput(resolved, source)
	source.Close()
	if err != nil || probe.Kind != InputGZIP || !probe.Supported || !probe.NeedsPreparation {
		t.Fatalf("probe=%#v err=%v", probe, err)
	}
	prepared, err := PrepareInput(context.Background(), resolved, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !bytes.Equal(readPrepared(t, prepared), raw) {
		t.Fatal("prepared gzip content differs")
	}
	info, err := InspectImage(prepared.Path)
	if err != nil || !info.LooksLikeRawBootMedia() {
		t.Fatalf("info=%#v err=%v", info, err)
	}
}

func TestPrepareBZIP2UsingSystemEncoder(t *testing.T) {
	if _, err := exec.LookPath("bzip2"); err != nil {
		t.Skip("bzip2 encoder unavailable")
	}
	raw := testRawImage()
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "disk.img")
	path := rawPath + ".bz2"
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bzip2", "-c", rawPath)
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, output, 0o600); err != nil {
		t.Fatal(err)
	}
	// Confirm the standard-library decoder understands the generated stream.
	decoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	check, err := ioReadAll(bzip2.NewReader(bytes.NewReader(decoded)))
	if err != nil || !bytes.Equal(check, raw) {
		t.Fatalf("encoder/decoder precondition failed: %v", err)
	}
	resolved, identity := inspectIdentity(t, path)
	prepared, err := PrepareInput(context.Background(), resolved, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !bytes.Equal(readPrepared(t, prepared), raw) {
		t.Fatal("prepared bzip2 content differs")
	}
}

func TestPrepareZIPRequiresSingleRegularEntry(t *testing.T) {
	raw := testRawImage()
	path := filepath.Join(t.TempDir(), "disk.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	entry, err := archive.Create("disk.img")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(raw); err != nil {
		t.Fatal(err)
	}
	archive.Close()
	file.Close()
	resolved, identity := inspectIdentity(t, path)
	prepared, err := PrepareInput(context.Background(), resolved, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !bytes.Equal(readPrepared(t, prepared), raw) {
		t.Fatal("prepared zip content differs")
	}
}

func TestPrepareXZAndZSTD(t *testing.T) {
	raw := testRawImage()
	for _, tc := range []struct {
		name string
		tool string
		args []string
		ext  string
	}{
		{"xz", "xz", []string{"-c"}, ".xz"},
		{"zstd", "zstd", []string{"-q", "-c"}, ".zst"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.LookPath(tc.tool); err != nil {
				t.Skipf("%s unavailable", tc.tool)
			}
			dir := t.TempDir()
			rawPath := filepath.Join(dir, "disk.img")
			if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(tc.tool, append(tc.args, rawPath)...).Output()
			if err != nil {
				t.Fatal(err)
			}
			path := rawPath + tc.ext
			if err := os.WriteFile(path, output, 0o600); err != nil {
				t.Fatal(err)
			}
			resolved, identity := inspectIdentity(t, path)
			prepared, err := PrepareInput(context.Background(), resolved, identity, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			if !bytes.Equal(readPrepared(t, prepared), raw) {
				t.Fatalf("prepared %s content differs", tc.name)
			}
		})
	}
}

func TestProbeFFUIsExplicitlyUnsupported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.ffu")
	data := make([]byte, 4096)
	copy(data[4:], "SignedImage ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity := inspectIdentity(t, path)
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := ProbeInput(resolved, file)
	file.Close()
	if err != nil || probe.Kind != InputFFU || probe.Supported {
		t.Fatalf("probe=%#v err=%v", probe, err)
	}
	if prepared, err := PrepareInput(context.Background(), resolved, identity, nil); err == nil {
		prepared.Close()
		t.Fatal("FFU preparation unexpectedly succeeded")
	}
}

func TestPrepareVHDWithPinnedQemuConversion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses /proc/self/fd")
	}
	raw := testRawImage()
	dir := t.TempDir()
	expectedRaw := filepath.Join(dir, "expected.raw")
	if err := os.WriteFile(expectedRaw, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	vhd := make([]byte, 4096)
	copy(vhd[len(vhd)-512:], "conectix")
	vhdPath := filepath.Join(dir, "disk.vhd")
	if err := os.WriteFile(vhdPath, vhd, 0o600); err != nil {
		t.Fatal(err)
	}
	toolDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(toolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(toolDir, "qemu-img")
	body := `#!/bin/sh
set -eu
if [ "$1" = info ]; then
  printf '{"format":"vpc","virtual-size":%s,"encrypted":false}\n' "${TEST_VIRTUAL_SIZE}"
  exit 0
fi
if [ "$1" = convert ]; then
  for out do :; done
  cp "$TEST_EXPECTED_RAW" "$out"
  exit 0
fi
exit 2
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", toolDir+":"+oldPath)
	t.Setenv("TEST_EXPECTED_RAW", expectedRaw)
	t.Setenv("TEST_VIRTUAL_SIZE", fmtSprint(len(raw)))
	resolved, identity := inspectIdentity(t, vhdPath)
	prepared, err := PrepareInput(context.Background(), resolved, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !bytes.Equal(readPrepared(t, prepared), raw) {
		t.Fatal("prepared VHD content differs")
	}
}

func ioReadAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var out bytes.Buffer
	_, err := out.ReadFrom(readerAdapter{r})
	return out.Bytes(), err
}

type readerAdapter struct {
	r interface{ Read([]byte) (int, error) }
}

func (r readerAdapter) Read(p []byte) (int, error) { return r.r.Read(p) }

func fmtSprint(value int) string {
	return strconv.Itoa(value)
}

func testOpticalImage(hybrid bool) []byte {
	data := make([]byte, previewBytes)
	offset := 16 * 2048
	data[offset] = 1
	copy(data[offset+1:offset+6], "CD001")
	data[offset+6] = 1
	if hybrid {
		data[510], data[511] = 0x55, 0xaa
		entry := data[446:462]
		entry[4] = 0x17
		binary.LittleEndian.PutUint32(entry[8:12], 1)
		binary.LittleEndian.PutUint32(entry[12:16], 4096)
	}
	return data
}

func writeGZIP(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPreviewCompressedOpticalAndHybridImages(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hybrid      bool
		wantRaw     bool
		wantOptical bool
	}{
		{name: "optical-only", hybrid: false, wantRaw: false, wantOptical: true},
		{name: "isohybrid", hybrid: true, wantRaw: true, wantOptical: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name+".iso.gz")
			writeGZIP(t, path, testOpticalImage(tc.hybrid))
			resolved, identity := inspectIdentity(t, path)
			file, err := sourcefile.OpenRegular(resolved, identity)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			probe, err := ProbeInput(resolved, file)
			if err != nil {
				t.Fatal(err)
			}
			info, available, err := PreviewInput(context.Background(), resolved, file, probe)
			if err != nil || !available {
				t.Fatalf("available=%t info=%#v err=%v", available, info, err)
			}
			if info.HasOpticalFilesystem() != tc.wantOptical || info.LooksLikeRawBootMedia() != tc.wantRaw {
				t.Fatalf("info=%#v", info)
			}
		})
	}
}

func TestPreparationSizeLimit(t *testing.T) {
	raw := make([]byte, 1024*1024)
	path := filepath.Join(t.TempDir(), "large.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	prepared, err := PrepareInputWithOptions(context.Background(), resolved, identity, PrepareOptions{MaxPreparedSize: 512 * 1024}, nil)
	if prepared != nil {
		prepared.Close()
	}
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("exceeds")) {
		t.Fatalf("size limit was not enforced: %v", err)
	}
}
