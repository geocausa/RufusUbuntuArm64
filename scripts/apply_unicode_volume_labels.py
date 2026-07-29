#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one guarded match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\t"github.com/geocausa/RufusArm64/internal/uefintfs"\n\t"github.com/geocausa/RufusArm64/internal/windowsconfig"\n''',
    '''\t"github.com/geocausa/RufusArm64/internal/uefintfs"\n\t"github.com/geocausa/RufusArm64/internal/volumelabel"\n\t"github.com/geocausa/RufusArm64/internal/windowsconfig"\n''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''func normalizeVolumeLabel(value, filesystem string) (string, error) {\n\tlabel := strings.ToUpper(strings.TrimSpace(value))\n\tif label == "" {\n\t\tlabel = "RUFUSARM64"\n\t}\n\tlimit := 11\n\tif filesystem == "ntfs" {\n\t\tlimit = 32\n\t}\n\tif len(label) > limit {\n\t\treturn "", fmt.Errorf("%s volume label must contain at most %d ASCII characters", strings.ToUpper(filesystem), limit)\n\t}\n\tfor _, r := range label {\n\t\tif r < 0x20 || r > 0x7e || strings.ContainsRune(`"*/:<>?\\|`, r) {\n\t\t\treturn "", fmt.Errorf("%s volume label contains an unsupported character", strings.ToUpper(filesystem))\n\t\t}\n\t\tif filesystem == "fat32" && strings.ContainsRune(`+,.;=[]`, r) {\n\t\t\treturn "", errors.New("FAT32 volume label contains an unsupported character")\n\t\t}\n\t}\n\treturn label, nil\n}\n''',
    '''func normalizeVolumeLabel(value, filesystem string) (string, error) {\n\tswitch strings.ToLower(strings.TrimSpace(filesystem)) {\n\tcase "fat32":\n\t\treturn volumelabel.FAT32(value, "RUFUSARM64")\n\tcase "ntfs":\n\t\treturn volumelabel.NTFS(value, "RUFUSARM64")\n\tdefault:\n\t\treturn "", fmt.Errorf("unsupported filesystem %q for volume label", filesystem)\n\t}\n}\n''',
)
replace_once(
    "internal/windowsmedia/windowsmedia_test.go",
    '''func TestNormalizeVolumeLabel(t *testing.T) {\n\tlabel, err := normalizeVolumeLabel("win 11", "fat32")\n\tif err != nil || label != "WIN 11" {\n\t\tt.Fatalf("label=%q err=%v", label, err)\n\t}\n\tfor _, bad := range []string{"this-label-is-too-long", "BAD/NAME"} {\n\t\tif _, err := normalizeVolumeLabel(bad, "fat32"); err == nil {\n\t\t\tt.Fatalf("accepted invalid label %q", bad)\n\t\t}\n\t}\n}\n''',
    '''func TestNormalizeVolumeLabel(t *testing.T) {\n\tfat, err := normalizeVolumeLabel("win 11", "fat32")\n\tif err != nil || fat != "WIN 11" {\n\t\tt.Fatalf("FAT32 label=%q err=%v", fat, err)\n\t}\n\tntfs := "Rufus_日本"\n\tgot, err := normalizeVolumeLabel(ntfs, "ntfs")\n\tif err != nil || got != ntfs {\n\t\tt.Fatalf("NTFS label=%q err=%v", got, err)\n\t}\n\tif got, err := normalizeVolumeLabel(strings.Repeat("😀", 16), "ntfs"); err != nil || got != strings.Repeat("😀", 16) {\n\t\tt.Fatalf("32-unit NTFS label=%q err=%v", got, err)\n\t}\n\tfor _, test := range []struct {\n\t\tfilesystem string\n\t\tlabel      string\n\t}{\n\t\t{filesystem: "fat32", label: "this-label-is-too-long"},\n\t\t{filesystem: "fat32", label: "BAD/NAME"},\n\t\t{filesystem: "fat32", label: "Rufus_日本"},\n\t\t{filesystem: "ntfs", label: " leading"},\n\t\t{filesystem: "ntfs", label: strings.Repeat("😀", 17)},\n\t} {\n\t\tif _, err := normalizeVolumeLabel(test.label, test.filesystem); err == nil {\n\t\t\tt.Fatalf("accepted invalid %s label %q", test.filesystem, test.label)\n\t\t}\n\t}\n}\n''',
)

replace_once(
    "internal/linuxmedia/extracted_plan.go",
    '''import (\n\t"errors"\n\t"fmt"\n\t"strings"\n\n\t"github.com/geocausa/RufusArm64/internal/uefintfs"\n)\n''',
    '''import (\n\t"errors"\n\t"fmt"\n\n\t"github.com/geocausa/RufusArm64/internal/uefintfs"\n\t"github.com/geocausa/RufusArm64/internal/volumelabel"\n)\n''',
)
replace_once(
    "internal/linuxmedia/extracted_plan.go",
    '''func normalizeExtractedNTFSLabel(value string) (string, error) {\n\tlabel := strings.ToUpper(strings.TrimSpace(value))\n\tif label == "" {\n\t\tlabel = "RUFUSARM64"\n\t}\n\tif len(label) > 32 {\n\t\treturn "", errors.New("NTFS volume label must contain at most 32 ASCII characters")\n\t}\n\tfor _, r := range label {\n\t\tif r < 0x20 || r > 0x7e || strings.ContainsRune(`"*/:<>?\\|`, r) {\n\t\t\treturn "", errors.New("NTFS volume label contains an unsupported character")\n\t\t}\n\t}\n\treturn label, nil\n}\n''',
    '''func normalizeExtractedNTFSLabel(value string) (string, error) {\n\treturn volumelabel.NTFS(value, "RUFUSARM64")\n}\n''',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '''\t\tplan, err := PlanExtractedMedia(manifest, "auto", scheme, "linux media", 8192, 8*1024*1024*1024, 512)\n''',
    '''\t\tplan, err := PlanExtractedMedia(manifest, "auto", scheme, "Linux_日本", 8192, 8*1024*1024*1024, 512)\n''',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '''\t\tif plan.VolumeLabel != "LINUX MEDIA" || plan.ClusterSize != 8192 {\n''',
    '''\t\tif plan.VolumeLabel != "Linux_日本" || plan.ClusterSize != 8192 {\n''',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '''\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("x", 33), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 ASCII") {\n''',
    '''\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("x", 33), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 UTF-16") {\n''',
)
replace_once(
    "internal/linuxmedia/extracted_plan_test.go",
    '''\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", "LINUX", 65536, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "4096, 8192, 16384, or 32768") {\n''',
    '''\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("😀", 17), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 UTF-16") {\n\t\tt.Fatalf("NTFS surrogate-pair label error = %v", err)\n\t}\n\tif _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", "LINUX", 65536, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "4096, 8192, 16384, or 32768") {\n''',
)

replace_once(
    "internal/linuxmedia/create.go",
    '''\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n)\n''',
    '''\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n\t"github.com/geocausa/RufusArm64/internal/volumelabel"\n)\n''',
)
replace_once(
    "internal/linuxmedia/create.go",
    '''func normalizePersistentLabel(value string) (string, error) {\n\tvalue = strings.ToUpper(strings.TrimSpace(value))\n\tif value == "" {\n\t\tvalue = "RUFUS-LIVE"\n\t}\n\tif len(value) > 11 {\n\t\treturn "", errors.New("FAT32 boot volume label must be at most 11 characters")\n\t}\n\tfor _, character := range []byte(value) {\n\t\tif character < 0x20 || character > 0x7e {\n\t\t\treturn "", errors.New("FAT32 boot volume label must use printable ASCII")\n\t\t}\n\t}\n\tif strings.ContainsAny(value, `"*+,./:;<=>?[\\]|`) {\n\t\treturn "", errors.New("FAT32 boot volume label contains an invalid character")\n\t}\n\treturn value, nil\n}\n''',
    '''func normalizePersistentLabel(value string) (string, error) {\n\treturn volumelabel.FAT32(value, "RUFUS-LIVE")\n}\n''',
)

replace_once(
    "internal/nonbootable/plan.go",
    '''\t"unicode/utf8"\n)\n''',
    '''\t"unicode/utf8"\n\n\t"github.com/geocausa/RufusArm64/internal/volumelabel"\n)\n''',
)
replace_once(
    "internal/nonbootable/plan.go",
    '''\tfatLabel      bool\n''',
    '''''',
)
replace_once(
    "internal/nonbootable/plan.go",
    '''\t\tfatLabel:      true,\n''',
    '''''',
)
replace_once(
    "internal/nonbootable/plan.go",
    '''\tlabel, err := normalizeLabel(request.Label, contract)\n''',
    '''\tlabel, err := normalizeLabel(request.Label, filesystem, contract)\n''',
)
replace_once(
    "internal/nonbootable/plan.go",
    '''\tlabel, err := normalizeLabel(plan.Label, contract)\n''',
    '''\tlabel, err := normalizeLabel(plan.Label, plan.Filesystem, contract)\n''',
)
replace_once(
    "internal/nonbootable/plan.go",
    '''func normalizeLabel(value string, contract filesystemContract) (string, error) {\n\tif !utf8.ValidString(value) {\n\t\treturn "", errors.New("filesystem label is not valid UTF-8")\n\t}\n\tif strings.TrimSpace(value) != value {\n\t\treturn "", errors.New("filesystem label must not have leading or trailing whitespace")\n\t}\n\tfor _, character := range value {\n\t\tif unicode.IsControl(character) {\n\t\t\treturn "", errors.New("filesystem label must not contain control characters")\n\t\t}\n\t}\n\tif contract.fatLabel {\n\t\tvalue = strings.ToUpper(value)\n\t\tfor _, character := range value {\n\t\t\tif !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != ' ' && character != '_' && character != '-' {\n\t\t\t\treturn "", errors.New("FAT32 label may contain only ASCII letters, digits, spaces, underscore, or hyphen")\n\t\t\t}\n\t\t}\n\t}\n\tif contract.maxLabelBytes != 0 && len([]byte(value)) > contract.maxLabelBytes {\n\t\treturn "", fmt.Errorf("%s label exceeds %d bytes", contract.display, contract.maxLabelBytes)\n\t}\n\tif contract.maxLabelUTF16 != 0 && len(utf16.Encode([]rune(value))) > contract.maxLabelUTF16 {\n\t\treturn "", fmt.Errorf("%s label exceeds %d UTF-16 code units", contract.display, contract.maxLabelUTF16)\n\t}\n\treturn value, nil\n}\n''',
    '''func normalizeLabel(value, filesystem string, contract filesystemContract) (string, error) {\n\tswitch filesystem {\n\tcase FilesystemFAT32:\n\t\treturn volumelabel.FAT32(value, "")\n\tcase FilesystemNTFS:\n\t\treturn volumelabel.NTFS(value, "")\n\t}\n\tif !utf8.ValidString(value) {\n\t\treturn "", errors.New("filesystem label is not valid UTF-8")\n\t}\n\tif strings.TrimSpace(value) != value {\n\t\treturn "", errors.New("filesystem label must not have leading or trailing whitespace")\n\t}\n\tfor _, character := range value {\n\t\tif unicode.IsControl(character) {\n\t\t\treturn "", errors.New("filesystem label must not contain control characters")\n\t\t}\n\t}\n\tif contract.maxLabelBytes != 0 && len([]byte(value)) > contract.maxLabelBytes {\n\t\treturn "", fmt.Errorf("%s label exceeds %d bytes", contract.display, contract.maxLabelBytes)\n\t}\n\tif contract.maxLabelUTF16 != 0 && len(utf16.Encode([]rune(value))) > contract.maxLabelUTF16 {\n\t\treturn "", fmt.Errorf("%s label exceeds %d UTF-16 code units", contract.display, contract.maxLabelUTF16)\n\t}\n\treturn value, nil\n}\n''',
)
replace_once(
    "internal/nonbootable/plan_test.go",
    '''func TestPlanJSONIsStableAndExplicitlyNonBootable(t *testing.T) {\n''',
    '''func TestNTFSLabelPreservesUnicodeAndCase(t *testing.T) {\n\trequest := baseRequest()\n\trequest.Filesystem = FilesystemNTFS\n\trequest.Label = "Rufus_日本"\n\tplan, err := BuildPlan(request)\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif plan.Label != request.Label {\n\t\tt.Fatalf("NTFS label = %q, want exact %q", plan.Label, request.Label)\n\t}\n\tphrase, err := ConfirmationPhrase(plan)\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif !strings.HasSuffix(phrase, " LABEL "+request.Label) {\n\t\tt.Fatalf("confirmation phrase lost NTFS label: %q", phrase)\n\t}\n}\n\nfunc TestPlanJSONIsStableAndExplicitlyNonBootable(t *testing.T) {\n''',
)
replace_once(
    "internal/nonbootable/backend_loop_test.go",
    '''\t\t{name: "gpt-ntfs", scheme: SchemeGPT, filesystem: FilesystemNTFS, label: "RUFUS-NTFS"},\n''',
    '''\t\t{name: "gpt-ntfs", scheme: SchemeGPT, filesystem: FilesystemNTFS, label: "Rufus-Été"},\n''',
)
replace_once(
    "internal/linuxmedia/extracted_loop_test.go",
    '''\ttestCreateExtractedNTFSOnRealLoopDevice(t, "mbr", "RUFUS-NTFS-MBR")\n''',
    '''\ttestCreateExtractedNTFSOnRealLoopDevice(t, "mbr", "Rufus-Été-MBR")\n''',
)
replace_once(
    "internal/linuxmedia/extracted_loop_test.go",
    '''\ttestCreateExtractedNTFSOnRealLoopDevice(t, "gpt", "RUFUS-NTFS-GPT")\n''',
    '''\ttestCreateExtractedNTFSOnRealLoopDevice(t, "gpt", "Rufus-Été-GPT")\n''',
)

replace_once(
    "gui/rufusarm64_logic.py",
    '''import tempfile\n''',
    '''import tempfile\nimport unicodedata\n''',
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''def normalize_volume_label(value, filesystem="fat32"):\n    filesystem = normalize_filesystem(filesystem)\n    label = (value or "RUFUSARM64").strip().upper() or "RUFUSARM64"\n    limit = 32 if filesystem == "ntfs" else 11\n    if len(label) > limit:\n        raise ValueError(f"The {filesystem.upper()} volume label must be {limit} characters or fewer.")\n    forbidden = '"*/:<>?\\\\|'\n    if filesystem != "ntfs":\n        forbidden += "+,.;=[]"\n    if any(ord(char) < 0x20 or ord(char) > 0x7E or char in forbidden for char in label):\n        raise ValueError(f"The volume label contains a character that {filesystem.upper()} does not support.")\n    return label\n''',
    '''def _utf16_code_units(value):\n    return len(value.encode("utf-16-le")) // 2\n\n\ndef normalize_volume_label(value, filesystem="fat32"):\n    filesystem = normalize_filesystem(filesystem)\n    raw = "" if value is None else str(value)\n    label = raw if raw != "" else "RUFUSARM64"\n    if label.strip() != label:\n        raise ValueError("The volume label must not have leading or trailing whitespace.")\n    if any(unicodedata.category(char) == "Cc" for char in label):\n        raise ValueError("The volume label must not contain control characters.")\n    if filesystem == "fat32":\n        label = label.upper()\n        if any(not ("A" <= char <= "Z" or "0" <= char <= "9" or char in " _-") for char in label):\n            raise ValueError("The FAT32 volume label may contain only ASCII letters, digits, spaces, underscore, or hyphen.")\n        if len(label.encode("ascii")) > 11:\n            raise ValueError("The FAT32 volume label must be 11 ASCII bytes or fewer.")\n        return label\n    if any(char in '"*/:<>?\\\\|' for char in label):\n        raise ValueError("The NTFS volume label contains an unsupported character.")\n    if _utf16_code_units(label) > 32:\n        raise ValueError("The NTFS volume label must be 32 UTF-16 code units or fewer.")\n    return label\n''',
)
replace_once(
    "gui/test_logic.py",
    '''    def test_volume_label(self):\n        self.assertEqual(normalize_volume_label("Win 11"), "WIN 11")\n        with self.assertRaises(ValueError):\n            normalize_volume_label("way-too-long-label")\n\n''',
    '''    def test_volume_label(self):\n        self.assertEqual(normalize_volume_label("Win 11"), "WIN 11")\n        self.assertEqual(normalize_volume_label("Rufus_日本", "ntfs"), "Rufus_日本")\n        self.assertEqual(normalize_volume_label("Rufus_日本", "auto"), "Rufus_日本")\n        self.assertEqual(normalize_volume_label("😀" * 16, "ntfs"), "😀" * 16)\n        for value, filesystem in (\n            ("way-too-long-label", "fat32"),\n            ("Rufus_日本", "fat32"),\n            (" leading", "ntfs"),\n            ("😀" * 17, "ntfs"),\n            ("😀" * 17, "auto"),\n        ):\n            with self.subTest(value=value, filesystem=filesystem):\n                with self.assertRaises(ValueError):\n                    normalize_volume_label(value, filesystem)\n\n''',
)
replace_once(
    "gui/rufusarm64_iso_write_mode.py",
    '''    label_filesystem = "ntfs" if filesystem == "ntfs" else "fat32"\n''',
    '''    label_filesystem = filesystem\n''',
)
replace_once(
    "gui/test_iso_write_mode.py",
    '''    def test_build_iso_write_command_rejects_missing_identity(self):\n''',
    '''    def test_auto_label_preserves_unicode_until_helper_resolution(self):\n        with tempfile.TemporaryDirectory() as directory:\n            image = Path(directory) / "linux.iso"\n            image.write_bytes(b"identity-bound-test-image")\n            command = build_iso_write_command(\n                "pkexec",\n                "helper",\n                str(image),\n                "/dev/sdz",\n                "target-identity",\n                str(Path(directory) / "cancel"),\n                "Rufus_日本",\n                filesystem="auto",\n            )\n        self.assertEqual(command[command.index("--volume-label") + 1], "Rufus_日本")\n        self.assertEqual(command[command.index("--filesystem") + 1], "auto")\n\n    def test_build_iso_write_command_rejects_missing_identity(self):\n''',
)

print("Unicode volume-label wiring applied successfully")
