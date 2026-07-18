//go:build linux

package secureboot

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticSBATLevelPayload() []byte {
	return []byte("sbat,1,2025051000\nshim,4\ngrub,5\n")
}

func writeSyntheticEFIVariable(t *testing.T, root, name string, attributes uint32, payload []byte) string {
	t.Helper()
	path := filepath.Join(root, name+"-"+shimLockVariableGUID)
	data := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(data[:4], attributes)
	copy(data[4:], payload)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFirmwareSBATLevelPrefersRuntimeMirror(t *testing.T) {
	root := t.TempDir()
	payload := syntheticSBATLevelPayload()
	writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, payload)
	writeSyntheticEFIVariable(t, root, "SbatLevel", efiVariableNonVolatile|efiVariableBootServiceAccess, payload)
	level, err := loadFirmwareSBATLevel(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if level.Datestamp != "2025051000" || !strings.Contains(level.Source, "SbatLevelRT") || !strings.Contains(level.Source, "0x00000006") {
		t.Fatalf("unexpected firmware SBAT source: %#v", level)
	}
}

func TestFirmwareSBATLevelFallsBackToPersistentVariable(t *testing.T) {
	root := t.TempDir()
	attributes := efiVariableNonVolatile | efiVariableBootServiceAccess | efiVariableTimeBasedAuthenticatedWrite
	writeSyntheticEFIVariable(t, root, "SbatLevel", attributes, syntheticSBATLevelPayload())
	level, err := loadFirmwareSBATLevel(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(level.Source, "SbatLevel") || strings.Contains(level.Source, "SbatLevelRT") || !strings.Contains(level.Source, "0x00000023") {
		t.Fatalf("unexpected persistent firmware source: %q", level.Source)
	}
}

func TestFirmwareSBATLevelRejectsDivergentCopies(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, syntheticSBATLevelPayload())
	writeSyntheticEFIVariable(t, root, "SbatLevel", efiVariableNonVolatile|efiVariableBootServiceAccess, []byte("sbat,1,2025051000\nshim,5\n"))
	if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "payloads differ") {
		t.Fatalf("divergent firmware variables error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsInvalidAttributes(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableNonVolatile|efiVariableBootServiceAccess|efiVariableRuntimeAccess, syntheticSBATLevelPayload())
	if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "expected exactly") {
		t.Fatalf("runtime attribute error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	data := make([]byte, 4+len(syntheticSBATLevelPayload()))
	binary.LittleEndian.PutUint32(data[:4], efiVariableBootServiceAccess|efiVariableRuntimeAccess)
	copy(data[4:], syntheticSBATLevelPayload())
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "SbatLevelRT-"+shimLockVariableGUID)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsTruncatedAndMalformedPayloads(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		root := t.TempDir()
		writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, nil)
		if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "non-empty payload") {
			t.Fatalf("truncated variable error = %v", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		root := t.TempDir()
		writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, []byte("shim,4\n"))
		if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "must start with sbat") {
			t.Fatalf("malformed payload error = %v", err)
		}
	})
}

func TestFirmwareSBATLevelRejectsAbsence(t *testing.T) {
	if _, err := loadFirmwareSBATLevel(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("absence error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsSubstitutionBeforeOpen(t *testing.T) {
	root := t.TempDir()
	path := writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, syntheticSBATLevelPayload())
	replacement := filepath.Join(root, "replacement")
	data := make([]byte, 4+len(syntheticSBATLevelPayload()))
	binary.LittleEndian.PutUint32(data[:4], efiVariableBootServiceAccess|efiVariableRuntimeAccess)
	copy(data[4:], syntheticSBATLevelPayload())
	if err := os.WriteFile(replacement, data, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := false
	hook := func(stage, candidate string) {
		if changed || stage != "before-open" || candidate != path {
			return
		}
		changed = true
		if err := os.Rename(candidate, candidate+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, candidate); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadFirmwareSBATLevel(root, hook); err == nil || !strings.Contains(err.Error(), "changed before it was opened") {
		t.Fatalf("substitution error = %v", err)
	}
}
