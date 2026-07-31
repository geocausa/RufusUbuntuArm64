//go:build linux

package windowstogo

import (
	"bytes"
	"testing"
)

func TestWindowsToGoOfflinePolicyIsNarrowAndDeterministic(t *testing.T) {
	first, err := WindowsToGoOfflinePolicy()
	if err != nil {
		t.Fatal(err)
	}
	second, err := WindowsToGoOfflinePolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("offline policy is not deterministic")
	}
	for _, want := range [][]byte{
		[]byte(`pass="offlineServicing"`),
		[]byte(`processorArchitecture="arm64"`),
		[]byte(`<SanPolicy>4</SanPolicy>`),
	} {
		if !bytes.Contains(first, want) {
			t.Fatalf("offline policy missing %q", want)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("windowsPE"), []byte("oobeSystem"), []byte("DiskConfiguration"),
		[]byte("LocalAccount"), []byte("ProductKey"),
	} {
		if bytes.Contains(first, forbidden) {
			t.Fatalf("offline policy contains unrelated setting %q", forbidden)
		}
	}
}
