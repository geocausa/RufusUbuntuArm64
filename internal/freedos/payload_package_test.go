package freedos

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPayloadCheckpointIsNotInstalledAtRuntime(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	buildScript, err := os.ReadFile(filepath.Join(root, "scripts", "build-deb.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("internal/freedos/payload"),
		[]byte("vendor/freedos/source"),
		[]byte("rufusarm64-freedos"),
	} {
		if bytes.Contains(buildScript, forbidden) {
			t.Fatalf("payload checkpoint was prematurely installed by the Debian package: %s", forbidden)
		}
	}
}
