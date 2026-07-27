package freedos

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPackagedCommandShipsCompleteSourceWithoutSeparatePayloadFiles(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	buildScript, err := os.ReadFile(filepath.Join(root, "scripts", "build-deb.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("cmd/rufus-freedos-format"),
		[]byte("usr/lib/rufusarm64/rufusarm64-freedos-format"),
		[]byte("vendor/freedos/source/${file}"),
		[]byte("usr/share/doc/rufusarm64/freedos/source/${file}"),
		[]byte("vendor/freedos/metadata/${file}"),
		[]byte("usr/share/doc/rufusarm64/freedos/metadata/${file}"),
		[]byte("PAYLOADS.json RELEASE-CONTRACT.json"),
	} {
		if !bytes.Contains(buildScript, required) {
			t.Fatalf("packaged FreeDOS command is missing required release material: %s", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("usr/lib/rufusarm64/COMMAND.COM"),
		[]byte("usr/lib/rufusarm64/KERNEL.SYS"),
		[]byte("usr/bin/COMMAND.COM"),
		[]byte("usr/bin/KERNEL.SYS"),
	} {
		if bytes.Contains(buildScript, forbidden) {
			t.Fatalf("FreeDOS payload was installed as a separately executable file: %s", forbidden)
		}
	}
}
