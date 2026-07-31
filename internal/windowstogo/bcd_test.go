//go:build linux

package windowstogo

import (
	"strings"
	"testing"
)

func TestBuildBCDScriptBindsPartitionsAndDisablesRecovery(t *testing.T) {
	disk, _ := ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	esp, _ := ParseGUID("11112222-3333-4444-8555-666677778888")
	osGUID, _ := ParseGUID("9999aaaa-bbbb-4ccc-8ddd-eeeeffffffff")
	boot := &hiveNode{Name: "{" + bootManagerGUIDText + "}", Nodes: []hiveNode{{Name: "Elements"}}}
	loader := &hiveNode{Name: "{" + loaderGUIDText + "}", Nodes: []hiveNode{{Name: "Elements"}}}
	script, err := buildBCDScript(BCDOptions{
		OutputPath: "/proc/1/fd/2/BCD", DiskGUID: disk, ESPGUID: esp, OSGUID: osGUID,
		Locale: "en-GB", Description: "Windows 11",
	}, boot, loader)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`\Objects\{` + bootManagerGUIDText + `}\Elements\11000001`,
		`\Objects\{` + loaderGUIDText + `}\Elements\11000001`,
		`\Objects\{` + loaderGUIDText + `}\Elements\21000001`,
		`\Objects\{` + loaderGUIDText + `}\Elements\16000009`,
		"hex:3:00",
		"commit /proc/1/fd/2/BCD",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "bcdedit") || strings.Contains(script, "bcdboot") {
		t.Fatalf("script escaped the offline hive transaction: %s", script)
	}
}

func TestGPTDeviceRecordContainsExactDiskAndPartitionGUIDs(t *testing.T) {
	disk, _ := ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	partition, _ := ParseGUID("11112222-3333-4444-8555-666677778888")
	record := GPTDeviceRecord(partition, disk)
	partitionDisk := partition.DiskBytes()
	diskDisk := disk.DiskBytes()
	if string(record[32:48]) != string(partitionDisk[:]) || string(record[56:72]) != string(diskDisk[:]) {
		t.Fatalf("record does not bind exact GPT GUID bytes: %x", record)
	}
}

func TestParseHiveAcceptsCanonicalSystemWrapper(t *testing.T) {
	xml := []byte(`<hive><node name="System" root="1"><node name="Description"/><node name="Objects"><node name="{test}"/></node></node></hive>`)
	objects, err := parseHive(xml)
	if err != nil {
		t.Fatal(err)
	}
	if objects.Name != "Objects" || objects.child("{test}") == nil {
		t.Fatalf("objects=%#v", objects)
	}
}

func TestParseHiveRejectsMultipleObjectsRoots(t *testing.T) {
	xml := []byte(`<hive><node name="Objects"/><node name="System"><node name="Objects"/></node></hive>`)
	if _, err := parseHive(xml); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("error=%v", err)
	}
}
