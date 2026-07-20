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
	listCommand := exec.Command("go", "list", "./...")
	listCommand.Dir = root
	listed, err := listCommand.Output()
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
	var important [][]byte
	for _, line := range bytes.Split(output, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || bytes.HasPrefix(trimmed, []byte("ok\t")) || bytes.HasPrefix(trimmed, []byte("?\t")) {
			continue
		}
		important = append(important, line)
	}
	if len(important) > 80 {
		important = important[:80]
	}
	detail := string(bytes.Join(important, []byte("\n")))
	escaped := strings.ReplaceAll(detail, "%", "%25")
	escaped = strings.ReplaceAll(escaped, "\r", "%0D")
	escaped = strings.ReplaceAll(escaped, "\n", "%0A")
	fmt.Printf("::error title=Nested Go 1.22 test failure::%s\n", escaped)
	t.Fatalf("nested repository tests failed: %v", err)
}
