//go:build linux

package isocapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMasterUsesDescriptorProviderAndReturnsEvidence(t *testing.T) {
	provider := writeProvider(t, `#!/bin/sh
[ -f /proc/self/fd/3/FILE ] || exit 9
printf 'ISO-DATA'
`)
	stubProvider(t, provider)
	sourcePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "FILE"), []byte("SOURCE"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := openDirectory(t, sourcePath)
	defer source.Close()
	output := createOutput(t)
	defer output.Close()

	var events []CaptureProgress
	report, err := Master(context.Background(), source, output, MasterOptions{
		VolumeID: "TEST_MEDIA",
		Progress: func(event CaptureProgress) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != CaptureReportSchema || report.Status != CapturePassed || report.Profile != ProfileISO9660JolietUDF || report.VolumeID != "TEST_MEDIA" {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if report.Provider != provider || report.Files != 1 || report.Directories != 0 || report.SourceBytes != uint64(len("SOURCE")) || !report.SourceStable {
		t.Fatalf("unexpected source evidence: %+v", report)
	}
	if len(report.SourceBindingSHA256) != 64 || len(report.SourceContentSHA256) != 64 || report.OutputBytes != uint64(len("ISO-DATA")) || report.OutputBytes > report.MaximumOutputBytes {
		t.Fatalf("incomplete evidence: %+v", report)
	}
	wantOutputHash := sha256.Sum256([]byte("ISO-DATA"))
	if report.OutputSHA256 != hex.EncodeToString(wantOutputHash[:]) {
		t.Fatalf("output digest = %s", report.OutputSHA256)
	}
	info, err := output.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || uint64(info.Size()) != report.OutputBytes {
		t.Fatalf("output info = %v report = %+v", info, report)
	}
	phases := make(map[string]bool)
	for _, event := range events {
		phases[event.Phase] = true
	}
	for _, phase := range []string{"inventory_source", "master", "revalidate_source"} {
		if !phases[phase] {
			t.Fatalf("missing phase %q in %+v", phase, events)
		}
	}
	last := events[len(events)-1]
	if last.Phase != "master" || last.Done == 0 || last.Done != last.Total {
		t.Fatalf("final progress is not authenticated completion: %+v", last)
	}
}

func TestMasterRejectsProviderSourceMutation(t *testing.T) {
	provider := writeProvider(t, `#!/bin/sh
printf 'CHANGED' > /proc/self/fd/3/FILE
printf 'ISO'
`)
	stubProvider(t, provider)
	sourcePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "FILE"), []byte("SOURCE"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := openDirectory(t, sourcePath)
	defer source.Close()
	output := createOutput(t)
	defer output.Close()

	report, err := Master(context.Background(), source, output, MasterOptions{})
	if err == nil || report.Status != CaptureFailed || report.FailureKind != "source_changed" {
		t.Fatalf("mutation result report=%+v err=%v", report, err)
	}
}

func TestMasterCancellationKillsProvider(t *testing.T) {
	provider := writeProvider(t, `#!/bin/sh
exec /bin/sleep 30
`)
	stubProvider(t, provider)
	sourcePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "FILE"), []byte("SOURCE"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := openDirectory(t, sourcePath)
	defer source.Close()
	output := createOutput(t)
	defer output.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	report, err := Master(ctx, source, output, MasterOptions{})
	if !errors.Is(err, context.DeadlineExceeded) || report.Status != CaptureCancelled || report.FailureKind != "cancelled" {
		t.Fatalf("cancellation report=%+v err=%v", report, err)
	}
}

func TestMasterBoundsProviderDiagnostics(t *testing.T) {
	provider := writeProvider(t, `#!/bin/sh
/usr/bin/head -c 70000 /dev/zero | /usr/bin/tr '\000' x >&2
exit 7
`)
	stubProvider(t, provider)
	sourcePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "FILE"), []byte("SOURCE"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := openDirectory(t, sourcePath)
	defer source.Close()
	output := createOutput(t)
	defer output.Close()

	report, err := Master(context.Background(), source, output, MasterOptions{})
	if err == nil || report.Status != CaptureFailed || report.FailureKind != "provider_execution" || !strings.Contains(err.Error(), "diagnostic truncated") {
		t.Fatalf("provider failure report=%+v err=%v", report, err)
	}
	if len(report.Failure) > maxProviderDiagnostic+1024 {
		t.Fatalf("provider failure was not bounded: %d bytes", len(report.Failure))
	}
}

func TestMasterRejectsEmptyProviderOutput(t *testing.T) {
	provider := writeProvider(t, "#!/bin/sh\nexit 0\n")
	stubProvider(t, provider)
	sourcePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourcePath, "FILE"), []byte("SOURCE"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := openDirectory(t, sourcePath)
	defer source.Close()
	output := createOutput(t)
	defer output.Close()

	report, err := Master(context.Background(), source, output, MasterOptions{})
	if err == nil || report.Status != CaptureFailed || report.FailureKind != "empty_output" {
		t.Fatalf("empty output report=%+v err=%v", report, err)
	}
}

func TestMasteringOutputLimitAndWriterFailClosed(t *testing.T) {
	limit, err := masteringOutputLimit(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(1024) + minimumMasteringReserve + 2*perEntryMasteringReserve
	if limit != want {
		t.Fatalf("limit = %d, want %d", limit, want)
	}
	if _, err := masteringOutputLimit(math.MaxUint64, 0); err == nil || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("source overflow error = %v", err)
	}
	if _, err := masteringOutputLimit(0, math.MaxUint64/perEntryMasteringReserve+1); err == nil || !strings.Contains(err.Error(), "entry reserve") {
		t.Fatalf("entry overflow error = %v", err)
	}

	output := createOutput(t)
	defer output.Close()
	writer := &boundedOutputWriter{output: output, maximum: 3}
	if _, err := writer.Write([]byte("123")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("4")); !errors.Is(err, errMasterOutputLimit) {
		t.Fatalf("writer limit error = %v", err)
	}
	info, err := output.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 3 {
		t.Fatalf("bounded output size = %d", info.Size())
	}
}

func TestMasterRejectsInvalidOutputAndDepth(t *testing.T) {
	if _, err := normalizeMasterLimits(Limits{MaxDepth: maximumMasteringDepth + 1}); err == nil || !strings.Contains(err.Error(), "supported maximum") {
		t.Fatalf("depth error = %v", err)
	}

	directory := openDirectory(t, t.TempDir())
	defer directory.Close()
	if err := validatePrivateOutput(directory); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory output error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "OUTPUT")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".LINK"); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validatePrivateOutput(file); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("linked output error = %v", err)
	}
}

func writeProvider(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "genisoimage")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func stubProvider(t *testing.T, path string) {
	t.Helper()
	previous := resolveGenISOImage
	resolveGenISOImage = func() (string, error) { return path, nil }
	t.Cleanup(func() { resolveGenISOImage = previous })
}

func openDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func createOutput(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "output-*.iso")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		t.Fatal(err)
	}
	return file
}
