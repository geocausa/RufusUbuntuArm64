package drivebackup

import "testing"

func TestValidateQEMUJSONObjectRejectsDuplicateMembers(t *testing.T) {
	if err := validateQEMUJSONObject([]byte(`{"check-errors":0,"check-errors":1}`)); err == nil {
		t.Fatal("duplicate qemu consistency member was accepted")
	}
}
