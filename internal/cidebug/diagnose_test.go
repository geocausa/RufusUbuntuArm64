package cidebug

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnoseRepositoryGoFailure(t *testing.T) {
	if os.Getenv("RUFUS_CI_DIAG_NESTED") == "1" {
		t.Skip("nested diagnostic invocation")
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	listCommand := exec.Command("go", "list", "./...")
	listCommand.Dir = root
	listed, err := listCommand.Output()
	if err != nil {
		t.Fatalf("list repository packages: %v", err)
	}
	packages := make([]string, 0)
	for _, packageName := range strings.Fields(string(listed)) {
		if strings.HasSuffix(packageName, "/internal/cidebug") {
			continue
		}
		packages = append(packages, packageName)
	}
	arguments := append([]string{"test"}, packages...)
	command := exec.Command("go", arguments...)
	command.Dir = root
	command.Env = append(os.Environ(), "RUFUS_CI_DIAG_NESTED=1")
	output, err := command.CombinedOutput()
	if err == nil {
		return
	}
	snippet := diagnosticFailureSnippet(string(output))
	fmt.Printf("::error title=Nested Go test failure::%s\n", escapeWorkflowCommand(snippet))
	t.Fatalf("nested repository tests failed: %v", err)
}

func diagnosticFailureSnippet(output string) string {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	start := -1
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--- FAIL:") || strings.HasPrefix(trimmed, "# ") {
			start = index
			break
		}
	}
	if start < 0 {
		if len(lines) > 40 {
			lines = lines[len(lines)-40:]
		}
		return strings.Join(lines, "\n")
	}
	if start > 1 {
		start -= 2
	}
	end := start
	for end < len(lines) && end-start < 50 {
		trimmed := strings.TrimSpace(lines[end])
		end++
		if trimmed == "FAIL" || strings.HasPrefix(trimmed, "FAIL\t") {
			if end < len(lines) {
				end++
			}
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func escapeWorkflowCommand(value string) string {
	value = strings.ReplaceAll(value, "%", "%25")
	value = strings.ReplaceAll(value, "\r", "%0D")
	return strings.ReplaceAll(value, "\n", "%0A")
}
