//go:build linux

package ffu

import (
	"os"
	"strings"
	"testing"
)

func TestFullFlashValidationProductionSourceKeepsProviderOut(t *testing.T) {
	data, err := os.ReadFile("restore_full_flash_validation_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"BindAuthenticatedSingleStoreV1Target",
		"fullFlashUpdateType",
		"partial FFU update type 1 is unsupported",
		"full-flash FFU contains validation descriptors",
		"ValidationChecksResolved:         true",
		"ExecutionSupported:               false",
		"RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("full-flash validation source is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Open(",
		"os.OpenFile(",
		"os.WriteFile(",
		"ReadAt(",
		"WriteAt(",
		"unix.Open(",
		"syscall.Open(",
		"net/http",
		"http.Get",
		"ExecutionSupported:               true",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("full-flash validation source contains forbidden provider or I/O primitive %q", forbidden)
		}
	}
}
