#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]

resume = root / "internal/acquisition/resume.go"
text = resume.read_text()
old = 'return filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+"."+image.SHA256[:16]+".rufus.part")'
new = 'return filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+"."+image.SHA256+".rufus.part")'
if text.count(old) != 1:
    raise SystemExit(f"resume.go partial-key anchor count={text.count(old)}")
resume.write_text(text.replace(old, new, 1))

download = root / "internal/acquisition/download.go"
text = download.read_text()
old = '''\tactual := hex.EncodeToString(digest.Sum(nil))\n\tif actual != image.SHA256 {\n'''
new = '''\tcurrentPartial, err := os.Lstat(partialPath)\n\tif err != nil || !currentPartial.Mode().IsRegular() || !os.SameFile(info, currentPartial) {\n\t\tkeepPartial = false\n\t\tcleanup(true)\n\t\tif err != nil {\n\t\t\treturn DownloadResult{}, fmt.Errorf("reinspect completed partial path: %w", err)\n\t\t}\n\t\treturn DownloadResult{}, errors.New("resumable partial path changed before atomic installation")\n\t}\n\tactual := hex.EncodeToString(digest.Sum(nil))\n\tif actual != image.SHA256 {\n'''
if text.count(old) != 1:
    raise SystemExit(f"download.go final-identity anchor count={text.count(old)}")
download.write_text(text.replace(old, new, 1))

test = root / "internal/acquisition/resume_test.go"
text = test.read_text()
append = r'''

func TestResumableDownloadRejectsPartialPathReplacement(t *testing.T) {
	data := []byte("signed resumable content")
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write(data)
	}))
	defer server.Close()
	image := testImage(server.URL, data)
	destination := filepath.Join(t.TempDir(), image.Filename)
	partial := resumePartialPath(destination, image)
	done := make(chan error, 1)
	go func() {
		_, err := Download(context.Background(), image, DownloadOptions{Destination: destination, Resume: true, AllowHTTP: true})
		done <- err
	}()
	<-started
	moved := partial + ".moved"
	if err := os.Rename(partial, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partial, data, 0o600); err != nil {
		t.Fatal(err)
	}
	close(release)
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "partial path changed") {
		t.Fatalf("replacement error=%v", err)
	}
	if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination installed after partial replacement: %v", statErr)
	}
}
'''
if "TestResumableDownloadRejectsPartialPathReplacement" in text:
    raise SystemExit("replacement test already exists")
test.write_text(text + append)
