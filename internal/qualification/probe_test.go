//go:build linux

package qualification

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeProbeEnvironment(t *testing.T, root, bootID string) ProbePaths {
	t.Helper()
	paths := ProbePaths{
		BootID:        filepath.Join(root, "boot_id"),
		Cmdline:       filepath.Join(root, "cmdline"),
		MountInfo:     filepath.Join(root, "mountinfo"),
		OSRelease:     filepath.Join(root, "os-release"),
		KernelRelease: filepath.Join(root, "kernel"),
		UEFIRoot:      filepath.Join(root, "efi"),
	}
	files := map[string]string{
		paths.BootID:        bootID + "\n",
		paths.Cmdline:       "quiet boot=casper persistent splash secret=value\n",
		paths.MountInfo:     "24 1 0:22 / / rw,relatime - overlay overlay rw,lowerdir=/ro,upperdir=/cow/upper\n",
		paths.OSRelease:     "NAME=Ubuntu\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
		paths.KernelRelease: "6.8.0-test\n",
	}
	for path, data := range files {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(paths.UEFIRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestQualificationStartAndVerifyAcrossBoots(t *testing.T) {
	root := t.TempDir()
	recordRoot := filepath.Join(root, "media")
	state := filepath.Join(root, "state")
	if err := os.Mkdir(recordRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	record := validRecord()
	record.Architecture = runtime.GOARCH
	stored, err := WriteRecord(recordRoot, record)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(recordRoot, filepath.FromSlash(stored.Path))
	paths := writeProbeEnvironment(t, root, "11111111-1111-4111-8111-111111111111")
	now := time.Date(2026, 7, 16, 13, 0, 0, 0, time.UTC)
	initial, err := Start(recordPath, ProbeOptions{
		StateDirectory: state,
		Paths:          paths,
		Now:            func() time.Time { return now },
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if initial.Phase != "initial" || initial.RebootSurvivalConfirmed || !initial.RootOverlay || !initial.PersistenceParameter {
		t.Fatalf("initial = %#v", initial)
	}
	if _, err := Verify(recordPath, ProbeOptions{StateDirectory: state, Paths: paths, Now: func() time.Time { return now }}); err == nil || !strings.Contains(err.Error(), "requires a reboot") {
		t.Fatalf("same boot error = %v", err)
	}
	if err := os.WriteFile(paths.BootID, []byte("22222222-2222-4222-8222-222222222222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(recordPath, ProbeOptions{StateDirectory: state, Paths: paths, Now: func() time.Time { return now.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.BootIDChanged || !verified.RebootSurvivalConfirmed || verified.InitialBootIDSHA256 == verified.CurrentBootIDSHA256 {
		t.Fatalf("verified = %#v", verified)
	}
	output := filepath.Join(root, "qualification.json")
	digest, err := WriteEvidence(output, verified)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatalf("digest = %q", digest)
	}
	if _, err := os.Stat(output + ".sha256"); err != nil {
		t.Fatal(err)
	}
}

func TestQualificationRejectsMissingPersistenceParameter(t *testing.T) {
	root := t.TempDir()
	media := filepath.Join(root, "media")
	if err := os.Mkdir(media, 0o700); err != nil {
		t.Fatal(err)
	}
	stored, err := WriteRecord(media, validRecord())
	if err != nil {
		t.Fatal(err)
	}
	paths := writeProbeEnvironment(t, root, "33333333-3333-4333-8333-333333333333")
	if err := os.WriteFile(paths.Cmdline, []byte("boot=casper quiet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Start(filepath.Join(media, filepath.FromSlash(stored.Path)), ProbeOptions{StateDirectory: filepath.Join(root, "state"), Paths: paths})
	if err == nil || !strings.Contains(err.Error(), "persistence kernel parameter") {
		t.Fatalf("error = %v", err)
	}
}

func TestQualificationRejectsNonOverlayRoot(t *testing.T) {
	root := t.TempDir()
	media := filepath.Join(root, "media")
	if err := os.Mkdir(media, 0o700); err != nil {
		t.Fatal(err)
	}
	stored, err := WriteRecord(media, validRecord())
	if err != nil {
		t.Fatal(err)
	}
	paths := writeProbeEnvironment(t, root, "44444444-4444-4444-8444-444444444444")
	if err := os.WriteFile(paths.MountInfo, []byte("24 1 8:2 / / rw - ext4 /dev/sda2 rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Start(filepath.Join(media, filepath.FromSlash(stored.Path)), ProbeOptions{StateDirectory: filepath.Join(root, "state"), Paths: paths})
	if err == nil || !strings.Contains(err.Error(), "rather than an overlay") {
		t.Fatalf("error = %v", err)
	}
}
