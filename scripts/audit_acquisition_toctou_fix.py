#!/usr/bin/env python3
from pathlib import Path


def replace_once(path_name, old, new):
    path = Path(path_name)
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "internal/acquisition/download.go",
    '\t"strings"\n\t"time"\n',
    '\t"strings"\n\t"syscall"\n\t"time"\n',
)

replace_once(
    "internal/acquisition/download.go",
    '''\tif uint64(info.Size()) == image.Size {
\t\tdigest, hashErr := hashFile(path)
\t\tif hashErr != nil {
\t\t\treturn DownloadResult{}, true, hashErr
\t\t}
\t\tif digest == image.SHA256 {
\t\t\treturn DownloadResult{Path: path, URL: image.URL, SHA256: digest, Size: image.Size, Reused: true}, true, nil
\t\t}
\t}
''',
    '''\tif uint64(info.Size()) == image.Size {
\t\tdigest, hashErr := hashExistingDownload(path, info)
\t\tif hashErr != nil {
\t\t\treturn DownloadResult{}, true, hashErr
\t\t}
\t\tif digest == image.SHA256 {
\t\t\treturn DownloadResult{Path: path, URL: image.URL, SHA256: digest, Size: image.Size, Reused: true}, true, nil
\t\t}
\t}
''',
)

replace_once(
    "internal/acquisition/download.go",
    '''func hashFile(path string) (string, error) {
\tfile, err := os.Open(path)
\tif err != nil {
\t\treturn "", fmt.Errorf("open existing download: %w", err)
\t}
\tdefer file.Close()
\tdigest := sha256.New()
\tif _, err := io.CopyBuffer(digest, file, make([]byte, downloadBufferSize)); err != nil {
\t\treturn "", fmt.Errorf("hash existing download: %w", err)
\t}
\treturn hex.EncodeToString(digest.Sum(nil)), nil
}
''',
    '''func hashExistingDownload(path string, expected os.FileInfo) (string, error) {
\tfd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
\tif err != nil {
\t\treturn "", fmt.Errorf("open existing download without following links: %w", err)
\t}
\tfile := os.NewFile(uintptr(fd), path)
\tif file == nil {
\t\t_ = syscall.Close(fd)
\t\treturn "", errors.New("open existing download returned an invalid file handle")
\t}
\tdefer file.Close()

\tbefore, err := file.Stat()
\tif err != nil {
\t\treturn "", fmt.Errorf("inspect opened existing download: %w", err)
\t}
\tif !before.Mode().IsRegular() || !os.SameFile(expected, before) {
\t\treturn "", errors.New("existing download changed before it could be verified")
\t}
\tdigest := sha256.New()
\tif _, err := io.CopyBuffer(digest, file, make([]byte, downloadBufferSize)); err != nil {
\t\treturn "", fmt.Errorf("hash existing download: %w", err)
\t}
\tafter, err := file.Stat()
\tif err != nil {
\t\treturn "", fmt.Errorf("reinspect opened existing download: %w", err)
\t}
\tif before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
\t\treturn "", errors.New("existing download changed while it was being verified")
\t}
\tcurrent, err := os.Lstat(path)
\tif err != nil {
\t\treturn "", fmt.Errorf("reinspect existing download path: %w", err)
\t}
\tif !current.Mode().IsRegular() || !os.SameFile(after, current) {
\t\treturn "", errors.New("existing download path changed while it was being verified")
\t}
\treturn hex.EncodeToString(digest.Sum(nil)), nil
}
''',
)

path = Path("internal/acquisition/download_test.go")
text = path.read_text(encoding="utf-8")
marker = "func TestDownloadRejectsUnsignedRedirectHost(t *testing.T) {"
addition = '''func TestHashExistingDownloadRejectsPathReplacement(t *testing.T) {
\tdirectory := t.TempDir()
\tpath := filepath.Join(directory, "image.iso")
\tif err := os.WriteFile(path, []byte("signed image"), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\texpected, err := os.Lstat(path)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tif err := os.Rename(path, filepath.Join(directory, "original.iso")); err != nil {
\t\tt.Fatal(err)
\t}
\tif err := os.WriteFile(path, []byte("replacement"), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\tif _, err := hashExistingDownload(path, expected); err == nil || !strings.Contains(err.Error(), "changed") {
\t\tt.Fatalf("replacement error = %v", err)
\t}
}

func TestHashExistingDownloadRejectsSymlinkSwap(t *testing.T) {
\tdirectory := t.TempDir()
\tpath := filepath.Join(directory, "image.iso")
\ttarget := filepath.Join(directory, "target.iso")
\tif err := os.WriteFile(path, []byte("signed image"), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\tif err := os.WriteFile(target, []byte("signed image"), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\texpected, err := os.Lstat(path)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tif err := os.Remove(path); err != nil {
\t\tt.Fatal(err)
\t}
\tif err := os.Symlink(target, path); err != nil {
\t\tt.Fatal(err)
\t}
\tif _, err := hashExistingDownload(path, expected); err == nil {
\t\tt.Fatal("symlink replacement was accepted")
\t}
}

'''
if text.count(marker) != 1:
    raise SystemExit(f"download test insertion marker count = {text.count(marker)}")
path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")
