package persistence

import (
	"testing"
	"testing/fstest"
)

func TestDetectModernUbuntuCasper(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("Ubuntu 24.04.2 LTS arm64\n")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte("linux /casper/vmlinuz boot=casper quiet splash ---\n")},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Ready() || detection.Family != FamilyUbuntuCasper || detection.FilesystemLabel != "casper-rw" || detection.BootParameter != "persistent" {
		t.Fatalf("unexpected detection: %#v", detection)
	}
	if len(detection.PatchPaths) != 1 || detection.PatchPaths[0] != "boot/grub/grub.cfg" {
		t.Fatalf("unexpected patch paths: %#v", detection.PatchPaths)
	}
}

func TestDetectUbuntuAlreadyPersistent(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("Ubuntu 22.04.5 LTS amd64\n")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte("linux /casper/vmlinuz boot=casper persistent quiet\n")},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if len(detection.AlreadyEnabledPaths) != 1 || len(detection.PatchPaths) != 0 {
		t.Fatalf("unexpected config classification: %#v", detection)
	}
}

func TestDetectRefusesLegacyUbuntuContract(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("Ubuntu 18.04.6 LTS amd64\n")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte("linux /casper/vmlinuz boot=casper\n")},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if detection.Ready() || detection.FilesystemLabel != "" {
		t.Fatalf("legacy release unexpectedly ready: %#v", detection)
	}
}

func TestDetectDebianLiveBoot(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":               {Data: []byte("Debian GNU/Linux 13.0.0 Live arm64\n")},
		"live/vmlinuz":             {Data: []byte("kernel")},
		"live/initrd.img":          {Data: []byte("initrd")},
		"isolinux/live.cfg":        {Data: []byte("append boot=live components quiet\n")},
		"loader/entries/live.conf": {Data: []byte("options boot=live components persistence\n")},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Ready() || detection.Family != FamilyDebianLive || detection.FilesystemLabel != "persistence" || detection.PersistenceConfig != "/ union\n" {
		t.Fatalf("unexpected detection: %#v", detection)
	}
	if len(detection.PatchPaths) != 1 || len(detection.AlreadyEnabledPaths) != 1 {
		t.Fatalf("unexpected config classification: %#v", detection)
	}
}

func TestDetectRejectsAmbiguousMedia(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("test")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"live/vmlinuz":       {Data: []byte("kernel")},
		"live/initrd":        {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte("linux boot=casper\nlinux boot=live\n")},
	}
	if _, err := Detect(media); err == nil {
		t.Fatal("ambiguous media accepted")
	}
}

func TestDetectRejectsOversizedConfig(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("Ubuntu 24.04 LTS")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: make([]byte, maxConfigBytes+1)},
	}
	if _, err := Detect(media); err == nil {
		t.Fatal("oversized config accepted")
	}
}

func TestDetectionIgnoresMenuTextContainingPersistenceWord(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("Ubuntu 24.04 LTS arm64\n")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte("menuentry 'persistent tools' {\n linux /casper/vmlinuz boot=casper quiet\n}\n")},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if len(detection.AlreadyEnabledPaths) != 0 || len(detection.PatchPaths) != 1 {
		t.Fatalf("menu text was mistaken for a kernel parameter: %#v", detection)
	}
}
