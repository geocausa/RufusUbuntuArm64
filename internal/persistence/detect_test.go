package persistence

import (
	"strings"
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

func TestDetectResoluteCmdlineCasperLayout(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":                  {Data: []byte(`Ubuntu "Resolute Raccoon" - Daily arm64+x1e (20260326-014937)` + "\n")},
		"casper/vmlinuz":              {Data: []byte("kernel")},
		"casper/initrd":               {Data: []byte("initrd")},
		"casper/install-sources.yaml": {Data: []byte("sources: []\n")},
		"boot/grub/grub.cfg":          {Data: []byte("linux /casper/vmlinuz $cmdline --- quiet splash console=tty0\ninitrd /casper/initrd\n")},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Ready() || detection.Family != FamilyUbuntuCasper || detection.FilesystemLabel != "casper-rw" {
		t.Fatalf("unexpected detection: %#v", detection)
	}
	if detection.Version != "" {
		t.Fatalf("unexpected inferred version: %q", detection.Version)
	}
	if len(detection.PatchPaths) != 1 || detection.PatchPaths[0] != "boot/grub/grub.cfg" {
		t.Fatalf("unexpected patch paths: %#v", detection.PatchPaths)
	}
	if !strings.Contains(strings.Join(detection.Evidence, "\n"), "install-sources.yaml") {
		t.Fatalf("modern metadata evidence missing: %#v", detection.Evidence)
	}
}

func TestDetectUnversionedCasperRequiresModernMetadata(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("Custom casper image\n")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte("linux /casper/vmlinuz $cmdline ---\n")},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if detection.Ready() || detection.FilesystemLabel != "" {
		t.Fatalf("unversioned media without modern metadata unexpectedly ready: %#v", detection)
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

func TestDetectMixedCasperEntriesRemainPatchable(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":     {Data: []byte("Ubuntu 24.04 LTS arm64\n")},
		"casper/vmlinuz": {Data: []byte("kernel")},
		"casper/initrd":  {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte(
			"linux /casper/vmlinuz boot=casper persistent quiet\n" +
				"linux /casper/vmlinuz $cmdline --- quiet\n",
		)},
	}
	detection, err := Detect(media)
	if err != nil {
		t.Fatal(err)
	}
	if len(detection.PatchPaths) != 1 || len(detection.AlreadyEnabledPaths) != 0 {
		t.Fatalf("mixed entries were misclassified: %#v", detection)
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
		".disk/info":                  {Data: []byte("test")},
		"casper/vmlinuz":              {Data: []byte("kernel")},
		"casper/initrd":               {Data: []byte("initrd")},
		"casper/install-sources.yaml": {Data: []byte("sources: []\n")},
		"live/vmlinuz":                {Data: []byte("kernel")},
		"live/initrd":                 {Data: []byte("initrd")},
		"boot/grub/grub.cfg":          {Data: []byte("linux /casper/vmlinuz $cmdline\nlinux boot=live\n")},
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

func TestDetectReportsCasperConfigurationMismatch(t *testing.T) {
	media := fstest.MapFS{
		".disk/info":         {Data: []byte("Ubuntu 24.04 LTS arm64\n")},
		"casper/vmlinuz":     {Data: []byte("kernel")},
		"casper/initrd":      {Data: []byte("initrd")},
		"boot/grub/grub.cfg": {Data: []byte("linux /other/vmlinuz quiet\n")},
	}
	_, err := Detect(media)
	if err == nil || !strings.Contains(err.Error(), "casper kernel and initrd were found") {
		t.Fatalf("unexpected error: %v", err)
	}
}
