#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]


def replace(path, old, new):
    file = root / path
    text = file.read_text(encoding="utf-8")
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"{path}: expected test block not found")
    file.write_text(text.replace(old, new, 1), encoding="utf-8")


replace(
    "internal/windowsmedia/windowsmedia_test.go",
    '''func TestWimlibExecutablePrefersEnvironmentOverride(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "wimlib-imagex")
	writeExecutable(t, fake, "#!/bin/sh\\nexit 0\\n")
	t.Setenv("RUFUSARM64_WIMLIB", fake)
	path, err := wimlibExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if path != fake {
		t.Fatalf("wimlibExecutable()=%q want %q", path, fake)
	}
}
''',
    '''func TestWimlibExecutableIgnoresEnvironmentOverride(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "wimlib-imagex")
	writeExecutable(t, fake, "#!/bin/sh\\nexit 0\\n")
	t.Setenv("RUFUSARM64_WIMLIB", fake)
	path, err := wimlibExecutable()
	if err == nil && path == fake {
		t.Fatalf("privileged WIM executable followed environment override %q", path)
	}
}
''',
)

replace(
    "gui/test_logic.py",
    '        self.assertIn("command-line only", summary)\n',
    '        self.assertIn("guarded persistent USB creator", summary)\n',
)
