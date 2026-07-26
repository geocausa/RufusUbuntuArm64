//go:build linux

package isocapture

import "testing"

func TestPortableContentSHA256IgnoresDirectoryAllocationSize(t *testing.T) {
	base := Inventory{
		Schema:      InventorySchema,
		Profile:     ProfileISO9660JolietUDF,
		Files:       1,
		Directories: 1,
		TotalBytes:  4,
		Entries: []Entry{
			{Path: "EFI", Kind: EntryDirectory, Size: 4096},
			{Path: "EFI/BOOTAA64.EFI", Kind: EntryFile, Size: 4, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	}
	remastered := base
	remastered.Entries = append([]Entry(nil), base.Entries...)
	remastered.Entries[0].Size = 88

	baseDigest, err := portableContentSHA256(base)
	if err != nil {
		t.Fatal(err)
	}
	remasteredDigest, err := portableContentSHA256(remastered)
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest != remasteredDigest {
		t.Fatalf("directory allocation size changed portable digest: %s != %s", baseDigest, remasteredDigest)
	}

	changedFile := remastered
	changedFile.Entries = append([]Entry(nil), remastered.Entries...)
	changedFile.Entries[1].Size++
	changedDigest, err := portableContentSHA256(changedFile)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == baseDigest {
		t.Fatal("regular-file size did not change portable digest")
	}
}
