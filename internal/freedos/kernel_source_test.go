package freedos

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type kernelSourcePin struct {
	Schema     int    `json:"schema"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Sources    []struct {
		Path        string `json:"path"`
		GitBlobSHA1 string `json:"git_blob_sha1"`
	} `json:"sources"`
	Layout struct {
		ShortJumpOpcode       byte   `json:"short_jump_opcode"`
		ConfigSignature       string `json:"config_signature"`
		ConfigSignatureOffset int    `json:"config_signature_offset"`
		ConfigSizeOffset      int    `json:"config_size_offset"`
		ConfigFieldsOffset    int    `json:"config_fields_offset"`
		ForceLBAFieldIndex    int    `json:"force_lba_field_index"`
		ForceLBAOffset        int    `json:"force_lba_offset"`
		RufusForceLBAValue    byte   `json:"rufus_force_lba_value"`
	} `json:"layout"`
}

func TestPinnedKernelConfigurationSource(t *testing.T) {
	path := filepath.Join("..", "..", "vendor", "freedos-kernel", "KERNEL-CONFIG.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read kernel source pin: %v", err)
	}
	var pin kernelSourcePin
	if err := json.Unmarshal(data, &pin); err != nil {
		t.Fatalf("decode kernel source pin: %v", err)
	}
	if pin.Schema != 1 || pin.Repository != "https://github.com/FDOS/kernel" {
		t.Fatalf("unexpected kernel source envelope: %+v", pin)
	}
	if pin.Commit != PinnedManifest().KernelSourceCommit {
		t.Fatalf("kernel source commit %s does not match the feasibility manifest", pin.Commit)
	}
	wantSources := map[string]string{
		"kernel/kernel.asm": "657dfbd827e47d332ec82167553112bfda60005e",
		"hdr/kconfig.h":     "02c340ada2634152c74c1e0d2533b5681d84827f",
		"sys/fdkrncfg.c":    "c35a0afa4f505a810966f52870f5ec7f6dbb1460",
		"docs/sys.txt":      "d47bb1d1719b1cbe5b2bbf35f9441c0ad946cec1",
	}
	gotSources := make(map[string]string, len(pin.Sources))
	for _, source := range pin.Sources {
		if !validHex(source.GitBlobSHA1, 40) {
			t.Fatalf("invalid Git blob SHA-1 for %s", source.Path)
		}
		gotSources[source.Path] = source.GitBlobSHA1
	}
	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Fatalf("kernel source pins changed: got %#v; want %#v", gotSources, wantSources)
	}
	layout := pin.Layout
	if layout.ShortJumpOpcode != kernelShortJumpOpcode ||
		layout.ConfigSignature != string(kernelConfigSignature) ||
		layout.ConfigSignatureOffset != kernelConfigSignatureOffset ||
		layout.ConfigSizeOffset != kernelConfigSizeOffset ||
		layout.ConfigFieldsOffset != kernelConfigFieldsOffset ||
		layout.ForceLBAFieldIndex != kernelForceLBAFieldIndex ||
		layout.ForceLBAOffset != int(PinnedManifest().KernelForceLBAOffset) ||
		layout.RufusForceLBAValue != PinnedManifest().KernelForceLBAValue {
		t.Fatalf("kernel configuration layout does not match code and manifest: %+v", layout)
	}
}
