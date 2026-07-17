package windowsconfig

import (
	"strings"
	"testing"
)

// Windows Setup uses this counterintuitive encoded value with PlainText=false
// for an initially empty local-account password. It is the same sentinel used
// by upstream Rufus; it must not be interpreted or replaced as a universal
// literal login password. The first-logon command requires the user to choose a
// password after the account is created.
func TestLocalAccountUsesEmptyPasswordSentinelAndChangeRequirement(t *testing.T) {
	data, err := Generate("ARM64 UEFI", Options{LocalAccount: "geoca"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		`<Password><Value>UABhAHMAcwB3AG8AcgBkAA==</Value><PlainText>false</PlainText></Password>`,
		`net user &quot;geoca&quot; /logonpasswordchg:yes`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated answer file is missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, `<PlainText>true</PlainText>`) {
		t.Fatalf("generated answer file exposed a plaintext password:\n%s", text)
	}
}
