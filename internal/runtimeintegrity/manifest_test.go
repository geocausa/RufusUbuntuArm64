package runtimeintegrity

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func digest(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestManifestMarshalParseRoundTrip(t *testing.T) {
	manifest := Manifest{TotalBytes: 5, Entries: []Entry{
		{Path: "./z file", MD5: digest("zz"), Size: 2},
		{Path: "./a/file", MD5: strings.ToUpper(digest("abc")), Size: 3},
	}}
	data, err := manifest.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "# md5sum_totalbytes = 0x5\n") || strings.Index(text, "./a/file") > strings.Index(text, "./z file") {
		t.Fatalf("manifest is not deterministic:\n%s", text)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TotalBytes != 5 || len(parsed.Entries) != 2 || parsed.Entries[0].MD5 != digest("abc") {
		t.Fatalf("unexpected parsed manifest: %#v", parsed)
	}
}

func TestParseRejectsUnsafeAndDuplicatePaths(t *testing.T) {
	cases := []string{
		"# md5sum_totalbytes = 0x1\n" + digest("x") + "  ../x\n",
		"# md5sum_totalbytes = 0x1\n" + digest("x") + "  ./a\\b\n",
		"# md5sum_totalbytes = 0x2\n" + digest("x") + "  ./A\n" + digest("y") + "  ./a\n",
		"# md5sum_totalbytes = 0x1\n" + digest("x") + "  ./md5sum.txt\n",
	}
	for _, data := range cases {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("unsafe manifest was accepted: %q", data)
		}
	}
}

func TestGenerateAndVerifyDeterministically(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "b.txt", "beta")
	writeFile(t, root, "dir/a file.txt", "alpha")
	manifest, err := Generate(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TotalBytes != 9 || len(manifest.Entries) != 2 || manifest.Entries[0].Path != "./b.txt" && manifest.Entries[0].Path != "./dir/a file.txt" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	data, err := manifest.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ManifestName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.ActualTotalBytes != 9 || len(result.Files) != 2 {
		t.Fatalf("unexpected verification: %#v", result)
	}
}

func TestVerifyReportsChangedMissingAndUnexpectedFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "one", "1")
	writeFile(t, root, "two", "22")
	manifest, err := Generate(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := manifest.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ManifestName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "one", "changed")
	if err := os.Remove(filepath.Join(root, "two")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "three", "333")
	result, err := Verify(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Unexpected) != 1 || len(result.Errors) < 3 {
		t.Fatalf("changes were not fully reported: %#v", result)
	}
	statuses := map[string]string{}
	for _, file := range result.Files {
		statuses[file.Path] = file.Status
	}
	if statuses["./one"] != "changed" || statuses["./two"] != "missing" {
		t.Fatalf("unexpected statuses: %#v", statuses)
	}
}

func TestGenerateRejectsSymlinkAndSubstitution(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "real", "data")
	if err := os.Symlink("real", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), root, Options{}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink was not rejected: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	replaced := false
	_, err := generate(context.Background(), root, Options{}, func(stage, relative string) {
		if stage != "file-before-open" || relative != "real" || replaced {
			return
		}
		replaced = true
		if renameErr := os.Rename(filepath.Join(root, "real"), filepath.Join(root, "old")); renameErr != nil {
			t.Fatal(renameErr)
		}
		writeFile(t, root, "real", "replacement")
	})
	if err == nil || !strings.Contains(err.Error(), "changed between enumeration") {
		t.Fatalf("substitution was not rejected: %v", err)
	}
}

func TestGenerateHonorsCancellationAndBounds(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "one", strings.Repeat("x", 1024))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Generate(ctx, root, Options{}); err == nil {
		t.Fatal("cancelled generation succeeded")
	}
	writeFile(t, root, "two", "2")
	if _, err := Generate(context.Background(), root, Options{MaxFiles: 1}); err == nil || !strings.Contains(err.Error(), "file safety limit") {
		t.Fatalf("file bound was not enforced: %v", err)
	}
}
