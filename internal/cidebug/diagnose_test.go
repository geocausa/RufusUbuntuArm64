package cidebug

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnoseRepositoryGo122Failure(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	listed, err := exec.Command("go", "list", "./...").Output()
	if err != nil {
		t.Fatalf("list packages: %v", err)
	}
	packages := strings.Fields(string(listed))
	filtered := packages[:0]
	for _, pkg := range packages {
		if !strings.HasSuffix(pkg, "/internal/cidebug") {
			filtered = append(filtered, pkg)
		}
	}
	command := exec.Command("go", append([]string{"test"}, filtered...)...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err == nil {
		return
	}
	lines := bytes.Split(output, []byte("\n"))
	if len(lines) > 100 {
		lines = lines[len(lines)-100:]
	}
	tail := string(bytes.Join(lines, []byte("\n")))
	escaped := strings.ReplaceAll(tail, "%", "%25")
	escaped = strings.ReplaceAll(escaped, "\r", "%0D")
	escaped = strings.ReplaceAll(escaped, "\n", "%0A")
	fmt.Printf("::error title=Nested Go 1.22 test failure::%s\n", escaped)
	t.Fatalf("nested repository tests failed: %v", err)
}
