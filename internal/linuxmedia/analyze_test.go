//go:build linux

package linuxmedia

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestAnalyzePersistentMountsReadOnlyAndCleansUp(t *testing.T) {
	imagePath := makeAnalysisISOHybrid(t)
	_, identity, err := sourcefile.Inspect(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	workRoot := t.TempDir()
	var commands [][]string
	var workspace string
	runner := func(ctx context.Context, name string, args ...string) error {
		commands = append(commands, append([]string{name}, args...))
		if name == "mount" {
			if got := strings.Join(args, " "); !strings.Contains(got, "loop,ro,nosuid,nodev,noexec") || !strings.Contains(got, "/proc/") {
				t.Fatalf("unsafe mount command: %s", got)
			}
			workspace = filepath.Dir(args[len(args)-1])
			populateUbuntuAnalysisRoot(t, args[len(args)-1])
		}
		return nil
	}
	result, err := analyzePersistentWithRunner(context.Background(), imagePath, PersistentAnalysisOptions{
		ExpectedSource:  identity,
		TargetSize:      4 * 1024 * 1024 * 1024,
		PersistenceSize: 1024 * 1024 * 1024,
		WorkDirectory:   workRoot,
	}, nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	if result.Detection.FilesystemLabel != "casper-rw" || result.Plan.SizeBytes != 1024*1024*1024 {
		t.Fatalf("unexpected analysis result: %#v", result)
	}
	if len(commands) != 2 || commands[0][0] != "mount" || commands[1][0] != "umount" {
		t.Fatalf("commands = %#v", commands)
	}
	if _, err := os.Stat(workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace was not removed: %v", err)
	}
}

func TestAnalyzePersistentRejectsSourceMutationAndStillUnmounts(t *testing.T) {
	imagePath := makeAnalysisISOHybrid(t)
	_, identity, err := sourcefile.Inspect(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	var unmounted bool
	runner := func(ctx context.Context, name string, args ...string) error {
		if name == "mount" {
			populateUbuntuAnalysisRoot(t, args[len(args)-1])
			file, err := os.OpenFile(imagePath, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte{0x7f}, 4096); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			future := time.Now().Add(2 * time.Second)
			if err := os.Chtimes(imagePath, future, future); err != nil {
				t.Fatal(err)
			}
		}
		if name == "umount" {
			unmounted = true
		}
		return nil
	}
	_, err = analyzePersistentWithRunner(context.Background(), imagePath, PersistentAnalysisOptions{
		ExpectedSource: identity,
		TargetSize:     4 * 1024 * 1024 * 1024,
		WorkDirectory:  t.TempDir(),
	}, nil, runner)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("source mutation was not rejected: %v", err)
	}
	if !unmounted {
		t.Fatal("analysis mount was not cleaned up after source mutation")
	}
}

func TestAnalyzePersistentCancellationCleansMount(t *testing.T) {
	imagePath := makeAnalysisISOHybrid(t)
	_, identity, err := sourcefile.Inspect(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var commands []string
	runner := func(commandCtx context.Context, name string, args ...string) error {
		commands = append(commands, name)
		if name == "mount" {
			populateUbuntuAnalysisRoot(t, args[len(args)-1])
			cancel()
		}
		return nil
	}
	_, err = analyzePersistentWithRunner(ctx, imagePath, PersistentAnalysisOptions{
		ExpectedSource: identity,
		TargetSize:     4 * 1024 * 1024 * 1024,
		WorkDirectory:  t.TempDir(),
	}, nil, runner)
	if err == nil {
		t.Fatal("cancelled analysis succeeded")
	}
	if !reflect.DeepEqual(commands, []string{"mount", "umount"}) {
		t.Fatalf("commands = %v", commands)
	}
}

func makeAnalysisISOHybrid(t *testing.T) string {
	t.Helper()
	const imageSize = int64(64 * 1024 * 1024)
	path := filepath.Join(t.TempDir(), "linux.iso")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(imageSize); err != nil {
		file.Close()
		t.Fatal(err)
	}
	mbr := make([]byte, 512)
	mbr[510], mbr[511] = 0x55, 0xaa
	mbr[446+4] = 0x17
	binary.LittleEndian.PutUint32(mbr[446+8:], 64)
	binary.LittleEndian.PutUint32(mbr[446+12:], uint32(imageSize/512-64))
	if _, err := file.WriteAt(mbr, 0); err != nil {
		file.Close()
		t.Fatal(err)
	}
	descriptor := make([]byte, 2048)
	descriptor[0] = 1
	copy(descriptor[1:6], "CD001")
	descriptor[6] = 1
	if _, err := file.WriteAt(descriptor, 16*2048); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func populateUbuntuAnalysisRoot(t *testing.T, root string) {
	t.Helper()
	writeLinuxTestFile(t, filepath.Join(root, ".disk", "info"), "Ubuntu 24.04.2 LTS arm64\n")
	writeLinuxTestFile(t, filepath.Join(root, "casper", "vmlinuz"), "kernel")
	writeLinuxTestFile(t, filepath.Join(root, "casper", "initrd"), "initrd")
	writeLinuxTestFile(t, filepath.Join(root, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")
}
