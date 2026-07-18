#!/usr/bin/env python3
import pathlib

path = pathlib.Path(__file__).with_name("apply-acquisition-resume.py")
text = path.read_text()

old = '''# Human output reports resumed bytes when applicable.\nreplace_once("cmd/rufus-linux/main.go", 'fmt.Printf("%s: %s\\\\nSource: %s\\\\nSize: %s\\\\nSHA-256: %s\\\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)', 'if result.Resumed > 0 {\\n\\t\\tfmt.Printf("Resumed from: %s\\\\n", humanBytes(result.Resumed))\\n\\t}\\n\\tfmt.Printf("%s: %s\\\\nSource: %s\\\\nSize: %s\\\\nSHA-256: %s\\\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)')\n# second occurrence\nreplace_once("cmd/rufus-linux/main.go", 'fmt.Printf("%s: %s\\\\nSource: %s\\\\nSize: %s\\\\nSHA-256: %s\\\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)', 'if result.Resumed > 0 {\\n\\t\\tfmt.Printf("Resumed from: %s\\\\n", humanBytes(result.Resumed))\\n\\t}\\n\\tfmt.Printf("%s: %s\\\\nSource: %s\\\\nSize: %s\\\\nSHA-256: %s\\\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)')\n'''
new = '''# Human output reports resumed bytes when applicable.\np = root / "cmd/rufus-linux/main.go"\ntext = p.read_text()\nold_output = 'fmt.Printf("%s: %s\\\\nSource: %s\\\\nSize: %s\\\\nSHA-256: %s\\\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)'\nnew_output = 'if result.Resumed > 0 {\\n\\t\\tfmt.Printf("Resumed from: %s\\\\n", humanBytes(result.Resumed))\\n\\t}\\n\\tfmt.Printf("%s: %s\\\\nSource: %s\\\\nSize: %s\\\\nSHA-256: %s\\\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)'\nif text.count(old_output) != 2:\n    raise SystemExit(f"main.go: expected two human output anchors, found {text.count(old_output)}")\np.write_text(text.replace(old_output, new_output))\n'''
if old not in text:
    raise SystemExit("human output applicator block not found")
text = text.replace(old, new, 1)

text = text.replace('''\tif err := installDownloadedFile(partialPath, destination, options.Replace); err != nil {\n\t\treturn DownloadResult{}, fmt.Errorf("install downloaded image: %w", err)\n\t}\n\tkeepPartial = true\n''', '''\tif err := installDownloadedFile(partialPath, destination, options.Replace); err != nil {\n\t\treturn DownloadResult{}, fmt.Errorf("install downloaded image: %w", err)\n\t}\n\t_ = os.Remove(partialPath)\n\tkeepPartial = true\n''', 1)

text = text.replace('''\t"strings"\n\t"testing"\n)\n''', '''\t"strings"\n\t"testing"\n\t"time"\n)\n''', 1)
text = text.replace('''\t\t\t_, _ = w.Write(data[i:end]); if flusher != nil { flusher.Flush() }\n''', '''\t\t\t_, _ = w.Write(data[i:end]); if flusher != nil { flusher.Flush() }; time.Sleep(5 * time.Millisecond)\n''', 1)

path.write_text(text)
