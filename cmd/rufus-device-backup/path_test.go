package main

import (
	"os"
	"testing"
)

func TestSetTrustedSystemPath(t *testing.T) {
	t.Setenv("PATH", "/tmp/untrusted-tools")
	setTrustedSystemPath()
	if got, want := os.Getenv("PATH"), "/usr/sbin:/usr/bin:/sbin:/bin"; got != want {
		t.Fatalf("PATH = %q, want %q", got, want)
	}
}
