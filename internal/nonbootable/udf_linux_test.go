//go:build linux

package nonbootable

import (
	"context"
	"strings"
	"testing"
)

func udfTestPlan(t *testing.T, label string) Plan {
	t.Helper()
	plan, err := BuildPlan(Request{
		DevicePath:        "/dev/sdb",
		ExpectedIdentity:  strings.Repeat("a", 64),
		DeviceSizeBytes:   256 * 1024 * 1024,
		LogicalSectorSize: 512,
		Scheme:            SchemeGPT,
		Filesystem:        FilesystemUDF,
		Label:             label,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func validUDFInfo(plan Plan) map[string]string {
	return map[string]string{
		"label":            plan.Label,
		"uuid":             "0123456789abcdef",
		"lvid":             plan.Label,
		"blocksize":        "512",
		"blocks":           "520192",
		"behindblocks":     "0",
		"numfiles":         "0",
		"numdirs":          "1",
		"udfrev":           udfRevision,
		"udfwriterev":      udfRevision,
		"integrity":        "closed",
		"accesstype":       "overwritable",
		"softwriteprotect": "no",
		"hardwriteprotect": "no",
	}
}

func TestParseAndValidateUDFInfo(t *testing.T) {
	plan := udfTestPlan(t, "Rufus_日本")
	output := strings.Join([]string{
		"filename=/dev/sdb1",
		"label=" + plan.Label,
		"uuid=0123456789abcdef",
		"lvid=" + plan.Label,
		"blocksize=512",
		"blocks=520192",
		"behindblocks=0",
		"numfiles=0",
		"numdirs=1",
		"udfrev=2.01",
		"udfwriterev=2.01",
		"integrity=closed",
		"accesstype=overwritable",
		"softwriteprotect=no",
		"hardwriteprotect=no",
		"start=64, blocks=12, type=VRS",
		"start=256, blocks=1, type=ANCHOR",
	}, "\n")
	values, err := parseUDFInfo([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateUDFInfo(values, plan); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(map[string]string){
		"label":         func(v map[string]string) { v["label"] = "OTHER" },
		"uuid":          func(v map[string]string) { v["uuid"] = "ABC" },
		"block size":    func(v map[string]string) { v["blocksize"] = "4096" },
		"blocks":        func(v map[string]string) { v["blocks"] = "1" },
		"files":         func(v map[string]string) { v["numfiles"] = "1" },
		"directories":   func(v map[string]string) { v["numdirs"] = "2" },
		"revision":      func(v map[string]string) { v["udfrev"] = "2.60" },
		"integrity":     func(v map[string]string) { v["integrity"] = "opened" },
		"access type":   func(v map[string]string) { v["accesstype"] = "readonly" },
		"write protect": func(v map[string]string) { v["softwriteprotect"] = "yes" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := make(map[string]string, len(values))
			for key, value := range values {
				copy[key] = value
			}
			mutate(copy)
			if err := validateUDFInfo(copy, plan); err == nil {
				t.Fatal("altered UDF metadata was accepted")
			}
		})
	}
}

func TestParseUDFInfoRejectsMissingAndDuplicateMetadata(t *testing.T) {
	if _, err := parseUDFInfo([]byte("label=DATA\nlabel=OTHER\n")); err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("duplicate error=%v", err)
	}
	if _, err := parseUDFInfo([]byte("label=DATA\n")); err == nil || !strings.Contains(err.Error(), "omitted") {
		t.Fatalf("missing error=%v", err)
	}
}

func TestValidateUDFBlkidRequiresIndependentAgreement(t *testing.T) {
	plan := udfTestPlan(t, "Rufus_日本")
	udf := validUDFInfo(plan)
	blkid := map[string]string{
		"TYPE":              "udf",
		"VERSION":           udfRevision,
		"LABEL":             plan.Label,
		"LOGICAL_VOLUME_ID": plan.Label,
		"UUID":              udf["uuid"],
		"BLOCK_SIZE":        "512",
		"FSBLOCKSIZE":       "512",
	}
	if err := validateUDFBlkid(blkid, udf, plan); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{
		"type": "TYPE", "revision": "VERSION", "label": "LABEL", "logical label": "LOGICAL_VOLUME_ID",
		"uuid": "UUID", "block size": "BLOCK_SIZE", "filesystem block size": "FSBLOCKSIZE",
	} {
		t.Run(name, func(t *testing.T) {
			copy := make(map[string]string, len(blkid))
			for item, value := range blkid {
				copy[item] = value
			}
			copy[key] = "wrong"
			if err := validateUDFBlkid(copy, udf, plan); err == nil {
				t.Fatal("altered blkid metadata was accepted")
			}
		})
	}
}

func TestInspectUDFReportsProviderFailure(t *testing.T) {
	plan := udfTestPlan(t, "DATA")
	if _, err := inspectUDF(context.Background(), plan, "/definitely/not/a/device"); err == nil || !strings.Contains(err.Error(), "inspect UDF descriptors") {
		t.Fatalf("provider error=%v", err)
	}
}
