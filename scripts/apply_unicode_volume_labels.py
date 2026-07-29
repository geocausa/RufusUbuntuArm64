#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one guarded match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_region(path, start_marker, end_marker, replacement):
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    start = text.find(start_marker)
    if start < 0:
        raise SystemExit(f"{path}: missing start marker {start_marker!r}")
    end = text.find(end_marker, start)
    if end < 0:
        raise SystemExit(f"{path}: missing end marker {end_marker!r}")
    if text.find(start_marker, start + len(start_marker)) >= 0:
        raise SystemExit(f"{path}: start marker is ambiguous")
    target.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '\t"github.com/geocausa/RufusArm64/internal/uefintfs"\n\t"github.com/geocausa/RufusArm64/internal/windowsconfig"\n',
    '\t"github.com/geocausa/RufusArm64/internal/uefintfs"\n\t"github.com/geocausa/RufusArm64/internal/volumelabel"\n\t"github.com/geocausa/RufusArm64/internal/windowsconfig"\n',
)
replace_region(
    "internal/windowsmedia/windowsmedia.go",
    "func normalizeVolumeLabel(value, filesystem string) (string, error) {",
    "\nvar wimPercentPattern",
    '''func normalizeVolumeLabel(value, filesystem string) (string, error) {
\tswitch strings.ToLower(strings.TrimSpace(filesystem)) {
\tcase "fat32":
\t\treturn volumelabel.FAT32(value, "RUFUSARM64")
\tcase "ntfs":
\t\treturn volumelabel.NTFS(value, "RUFUSARM64")
\tdefault:
\t\treturn "", fmt.Errorf("unsupported filesystem %q for volume label", filesystem)
\t}
}
''',
)
replace_region(
    "internal/windowsmedia/windowsmedia_test.go",
    "func TestNormalizeVolumeLabel(t *testing.T) {",
    "\nfunc TestRelayToolLineCompactsWimProgress",
    '''func TestNormalizeVolumeLabel(t *testing.T) {
\tfat, err := normalizeVolumeLabel("win 11", "fat32")
\tif err != nil || fat != "WIN 11" {
\t\tt.Fatalf("FAT32 label=%q err=%v", fat, err)
\t}
\tntfs := "Rufus_日本"
\tgot, err := normalizeVolumeLabel(ntfs, "ntfs")
\tif err != nil || got != ntfs {
\t\tt.Fatalf("NTFS label=%q err=%v", got, err)
\t}
\tif got, err := normalizeVolumeLabel(strings.Repeat("😀", 16), "ntfs"); err != nil || got != strings.Repeat("😀", 16) {
\t\tt.Fatalf("32-unit NTFS label=%q err=%v", got, err)
\t}
\tfor _, test := range []struct {
\t\tfilesystem string
\t\tlabel      string
\t}{
\t\t{filesystem: "fat32", label: "this-label-is-too-long"},
\t\t{filesystem: "fat32", label: "BAD/NAME"},
\t\t{filesystem: "fat32", label: "Rufus_日本"},
\t\t{filesystem: "ntfs", label: " leading"},
\t\t{filesystem: "ntfs", label: strings.Repeat("😀", 17)},
\t} {
\t\tif _, err := normalizeVolumeLabel(test.label, test.filesystem); err == nil {
\t\t\tt.Fatalf("accepted invalid %s label %q", test.filesystem, test.label)
\t\t}
\t}
}
''',
)

replace_once(
    "internal/linuxmedia/extracted_plan.go",
    '''import (
\t"errors"
\t"fmt"
\t"strings"

\t"github.com/geocausa/RufusArm64/internal/uefintfs"
)
''',
    '''import (
\t"errors"
\t"fmt"

\t"github.com/geocausa/RufusArm64/internal/uefintfs"
\t"github.com/geocausa/RufusArm64/internal/volumelabel"
)
''',
)
replace_region(
    "internal/linuxmedia/extracted_plan.go",
    "func normalizeExtractedNTFSLabel(value string) (string, error) {",
    "\nfunc estimateExtractedNTFSBytes",
    '''func normalizeExtractedNTFSLabel(value string) (string, error) {
\treturn volumelabel.NTFS(value, "RUFUSARM64")
}
''',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '\t\tplan, err := PlanExtractedMedia(manifest, "auto", scheme, "linux media", 8192, 8*1024*1024*1024, 512)\n',
    '\t\tplan, err := PlanExtractedMedia(manifest, "auto", scheme, "Linux_日本", 8192, 8*1024*1024*1024, 512)\n',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '\t\tif plan.VolumeLabel != "LINUX MEDIA" || plan.ClusterSize != 8192 {\n',
    '\t\tif plan.VolumeLabel != "Linux_日本" || plan.ClusterSize != 8192 {\n',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("x", 33), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 ASCII") {\n',
    '\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("x", 33), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 UTF-16") {\n',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", "LINUX", 65536, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "4096, 8192, 16384, or 32768") {\n',
    '''\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("😀", 17), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 UTF-16") {
\t\tt.Fatalf("NTFS surrogate-pair label error = %v", err)
\t}
\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", "LINUX", 65536, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "4096, 8192, 16384, or 32768") {
''',
)

replace_once(
    "internal/linuxmedia/create.go",
    '\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n)\n',
    '\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n\t"github.com/geocausa/RufusArm64/internal/volumelabel"\n)\n',
)
replace_region(
    "internal/linuxmedia/create.go",
    "func normalizePersistentLabel(value string) (string, error) {",
    "\nfunc persistentBlockDeviceSize",
    '''func normalizePersistentLabel(value string) (string, error) {
\treturn volumelabel.FAT32(value, "RUFUS-LIVE")
}
''',
)

replace_once(
    "internal/nonbootable/plan.go",
    '\t"unicode/utf8"\n)\n',
    '\t"unicode/utf8"\n\n\t"github.com/geocausa/RufusArm64/internal/volumelabel"\n)\n',
)
replace_once("internal/nonbootable/plan.go", "\tfatLabel      bool\n", "")
replace_once("internal/nonbootable/plan.go", "\t\tfatLabel:      true,\n", "")
replace_once(
    "internal/nonbootable/plan.go",
    "\tlabel, err := normalizeLabel(request.Label, contract)\n",
    "\tlabel, err := normalizeLabel(request.Label, filesystem, contract)\n",
)
replace_once(
    "internal/nonbootable/plan.go",
    "\tlabel, err := normalizeLabel(plan.Label, contract)\n",
    "\tlabel, err := normalizeLabel(plan.Label, plan.Filesystem, contract)\n",
)
replace_region(
    "internal/nonbootable/plan.go",
    "func normalizeLabel(value string, contract filesystemContract) (string, error) {",
    "\nfunc alignUp",
    '''func normalizeLabel(value, filesystem string, contract filesystemContract) (string, error) {
\tswitch filesystem {
\tcase FilesystemFAT32:
\t\treturn volumelabel.FAT32(value, "")
\tcase FilesystemNTFS:
\t\treturn volumelabel.NTFS(value, "")
\t}
\tif !utf8.ValidString(value) {
\t\treturn "", errors.New("filesystem label is not valid UTF-8")
\t}
\tif strings.TrimSpace(value) != value {
\t\treturn "", errors.New("filesystem label must not have leading or trailing whitespace")
\t}
\tfor _, character := range value {
\t\tif unicode.IsControl(character) {
\t\t\treturn "", errors.New("filesystem label must not contain control characters")
\t\t}
\t}
\tif contract.maxLabelBytes != 0 && len([]byte(value)) > contract.maxLabelBytes {
\t\treturn "", fmt.Errorf("%s label exceeds %d bytes", contract.display, contract.maxLabelBytes)
\t}
\tif contract.maxLabelUTF16 != 0 && len(utf16.Encode([]rune(value))) > contract.maxLabelUTF16 {
\t\treturn "", fmt.Errorf("%s label exceeds %d UTF-16 code units", contract.display, contract.maxLabelUTF16)
\t}
\treturn value, nil
}
''',
)
replace_once(
    "internal/nonbootable/plan_test.go",
    "func TestPlanJSONIsStableAndExplicitlyNonBootable(t *testing.T) {\n",
    '''func TestNTFSLabelPreservesUnicodeAndCase(t *testing.T) {
\trequest := baseRequest()
\trequest.Filesystem = FilesystemNTFS
\trequest.Label = "Rufus_日本"
\tplan, err := BuildPlan(request)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tif plan.Label != request.Label {
\t\tt.Fatalf("NTFS label = %q, want exact %q", plan.Label, request.Label)
\t}
\tphrase, err := ConfirmationPhrase(plan)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tif !strings.HasSuffix(phrase, " LABEL "+request.Label) {
\t\tt.Fatalf("confirmation phrase lost NTFS label: %q", phrase)
\t}
}

func TestPlanJSONIsStableAndExplicitlyNonBootable(t *testing.T) {
''',
)
replace_once(
    "internal/nonbootable/backend_loop_test.go",
    '\t\t{name: "gpt-ntfs", scheme: SchemeGPT, filesystem: FilesystemNTFS, label: "RUFUS-NTFS"},\n',
    '\t\t{name: "gpt-ntfs", scheme: SchemeGPT, filesystem: FilesystemNTFS, label: "Rufus-Été"},\n',
)
replace_once(
    "internal/linuxmedia/extracted_loop_test.go",
    '\ttestCreateExtractedNTFSOnRealLoopDevice(t, "mbr", "RUFUS-NTFS-MBR")\n',
    '\ttestCreateExtractedNTFSOnRealLoopDevice(t, "mbr", "Rufus-Été-MBR")\n',
)
replace_once(
    "internal/linuxmedia/extracted_loop_test.go",
    '\ttestCreateExtractedNTFSOnRealLoopDevice(t, "gpt", "RUFUS-NTFS-GPT")\n',
    '\ttestCreateExtractedNTFSOnRealLoopDevice(t, "gpt", "Rufus-Été-GPT")\n',
)

replace_once("gui/rufusarm64_logic.py", "import tempfile\n", "import tempfile\nimport unicodedata\n")
replace_region(
    "gui/rufusarm64_logic.py",
    'def normalize_volume_label(value, filesystem="fat32"):',
    "\ndef normalize_filesystem(value):",
    '''def _utf16_code_units(value):
    return len(value.encode("utf-16-le")) // 2


def normalize_volume_label(value, filesystem="fat32"):
    filesystem = normalize_filesystem(filesystem)
    raw = "" if value is None else str(value)
    label = raw if raw != "" else "RUFUSARM64"
    if label.strip() != label:
        raise ValueError("The volume label must not have leading or trailing whitespace.")
    if any(unicodedata.category(char) == "Cc" for char in label):
        raise ValueError("The volume label must not contain control characters.")
    if filesystem == "fat32":
        label = label.upper()
        if any(not ("A" <= char <= "Z" or "0" <= char <= "9" or char in " _-") for char in label):
            raise ValueError("The FAT32 volume label may contain only ASCII letters, digits, spaces, underscore, or hyphen.")
        if len(label.encode("ascii")) > 11:
            raise ValueError("The FAT32 volume label must be 11 ASCII bytes or fewer.")
        return label
    if any(char in '"*/:<>?\\\\|' for char in label):
        raise ValueError("The NTFS volume label contains an unsupported character.")
    if _utf16_code_units(label) > 32:
        raise ValueError("The NTFS volume label must be 32 UTF-16 code units or fewer.")
    return label

''',
)
replace_region(
    "gui/test_logic.py",
    "    def test_volume_label(self):",
    "\n    def test_success_message_matches_verification_mode",
    '''    def test_volume_label(self):
        self.assertEqual(normalize_volume_label("Win 11"), "WIN 11")
        self.assertEqual(normalize_volume_label("Rufus_日本", "ntfs"), "Rufus_日本")
        self.assertEqual(normalize_volume_label("Rufus_日本", "auto"), "Rufus_日本")
        self.assertEqual(normalize_volume_label("😀" * 16, "ntfs"), "😀" * 16)
        for value, filesystem in (
            ("way-too-long-label", "fat32"),
            ("Rufus_日本", "fat32"),
            (" leading", "ntfs"),
            ("😀" * 17, "ntfs"),
            ("😀" * 17, "auto"),
        ):
            with self.subTest(value=value, filesystem=filesystem):
                with self.assertRaises(ValueError):
                    normalize_volume_label(value, filesystem)

''',
)
replace_once(
    "gui/rufusarm64_iso_write_mode.py",
    '    label_filesystem = "ntfs" if filesystem == "ntfs" else "fat32"\n',
    "    label_filesystem = filesystem\n",
)
replace_once(
    "gui/test_iso_write_mode.py",
    "    def test_build_iso_write_command_rejects_missing_identity(self):\n",
    '''    def test_auto_label_preserves_unicode_until_helper_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "linux.iso"
            image.write_bytes(b"identity-bound-test-image")
            command = build_iso_write_command(
                "pkexec",
                "helper",
                str(image),
                "/dev/sdz",
                "target-identity",
                str(Path(directory) / "cancel"),
                "Rufus_日本",
                filesystem="auto",
            )
        self.assertEqual(command[command.index("--volume-label") + 1], "Rufus_日本")
        self.assertEqual(command[command.index("--filesystem") + 1], "auto")

    def test_build_iso_write_command_rejects_missing_identity(self):
''',
)

print("Unicode volume-label wiring applied successfully")
