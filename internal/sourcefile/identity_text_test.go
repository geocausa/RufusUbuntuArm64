//go:build linux

package sourcefile

import "testing"

func TestIdentityTextRoundTrip(t *testing.T) {
	want := Identity{Device: 2049, Inode: 12345, Size: 987654321, ModifiedNS: 1234567890123, ChangedNS: 1234567890456}
	text, err := FormatIdentity(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIdentity(text)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("identity round trip = %#v, want %#v", got, want)
	}
}

func TestIdentityTextAcceptsEpochTimestamps(t *testing.T) {
	want := Identity{Device: 1, Inode: 2, Size: 3, ModifiedNS: 0, ChangedNS: 0}
	text, err := FormatIdentity(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIdentity(text)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("identity round trip = %#v, want %#v", got, want)
	}
}

func TestIdentityTextRejectsIncompleteOrMalformedValues(t *testing.T) {
	for _, value := range []string{"", "1:2:3:4", "a:2:3:4:5", "1:2:0:4:5", "0:2:3:4:5", "1:2:3:-1:5"} {
		if _, err := ParseIdentity(value); err == nil {
			t.Fatalf("accepted identity %q", value)
		}
	}
}
