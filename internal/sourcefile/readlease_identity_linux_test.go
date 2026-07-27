//go:build linux

package sourcefile

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReadLeaseRejectsMetadataChangeBeforeAcquisition(t *testing.T) {
	path, identity := writeLeaseTestFile(t)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	// Change only inode metadata after the descriptor was opened. The lease
	// boundary must still compare the complete originally selected identity;
	// later lease checks may ignore ctime once content writes are excluded.
	time.Sleep(time.Millisecond)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	actual, err := IdentityOf(reader)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Size != identity.Size || actual.ModifiedNS != identity.ModifiedNS {
		t.Fatalf("chmod unexpectedly changed content metadata: before=%#v after=%#v", identity, actual)
	}
	if actual.ChangedNS == identity.ChangedNS {
		t.Fatalf("chmod did not advance ctime: before=%#v after=%#v", identity, actual)
	}

	lease, err := AcquireReadLease(context.Background(), reader, identity)
	if lease != nil {
		lease.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("metadata-changed source lease error = %v", err)
	}
}
