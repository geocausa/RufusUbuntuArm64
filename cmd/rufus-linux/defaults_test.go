package main

import "testing"

func TestPublicWriterDefaultsMatchParityContract(t *testing.T) {
	if defaultWriteVerify {
		t.Fatal("post-write verification must remain opt-in")
	}
	if defaultWindowsPartitionScheme != "auto" || defaultWindowsTargetSystem != "auto" {
		t.Fatalf("Windows layout defaults=%q/%q, want auto/auto", defaultWindowsPartitionScheme, defaultWindowsTargetSystem)
	}
	if defaultWindowsFilesystem != "auto" || defaultWindowsClusterSize != "auto" {
		t.Fatalf("Windows filesystem defaults=%q/%q, want auto/auto", defaultWindowsFilesystem, defaultWindowsClusterSize)
	}
	if defaultWindowsFullFormat || defaultWindowsBadBlockCheck {
		t.Fatal("full formatting and bad-block qualification must remain opt-in")
	}
}
