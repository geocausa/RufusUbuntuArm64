package device

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRawDeviceJSONPreservesLargeIntegerExactly(t *testing.T) {
	const exact = uint64(9007199254740993) // 2^53 + 1; float64 would round this.
	data := []byte(`{"blockdevices":[{"name":"sdz","path":"/dev/sdz","type":"disk","size":9007199254740993,"rm":1,"ro":0,"hotplug":1,"log-sec":512,"phy-sec":4096,"mountpoints":[null]}]}`)
	var raw rawList
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.BlockDevices) != 1 {
		t.Fatalf("device count = %d", len(raw.BlockDevices))
	}
	converted, err := convert(raw.BlockDevices[0])
	if err != nil {
		t.Fatal(err)
	}
	if converted.Size != exact {
		t.Fatalf("size = %d, want %d", converted.Size, exact)
	}
	if converted.LogicalSectorSize != 512 || converted.PhysicalSectorSize != 4096 {
		t.Fatalf("geometry = %d/%d", converted.LogicalSectorSize, converted.PhysicalSectorSize)
	}
}

func TestRawDeviceJSONAcceptsStringAndBooleanScalars(t *testing.T) {
	data := []byte(`{"blockdevices":[{"name":"sdz","path":"/dev/sdz","type":"disk","size":"4096","rm":true,"ro":false,"hotplug":"1","log-sec":"512","phy-sec":4096,"mountpoints":null}]}`)
	var raw rawList
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	converted, err := convert(raw.BlockDevices[0])
	if err != nil {
		t.Fatal(err)
	}
	if converted.Size != 4096 || !converted.Removable || converted.ReadOnly || !converted.Hotplug {
		t.Fatalf("unexpected converted device: %#v", converted)
	}
}

func TestRawDeviceJSONRejectsInexactNumericSyntax(t *testing.T) {
	for _, scalar := range []string{"1.5", "1e3", "-1"} {
		t.Run(strings.NewReplacer("-", "negative", ".", "point").Replace(scalar), func(t *testing.T) {
			data := []byte(`{"blockdevices":[{"name":"sdz","path":"/dev/sdz","type":"disk","size":` + scalar + `}]}`)
			var raw rawList
			if err := json.Unmarshal(data, &raw); err == nil {
				t.Fatalf("scalar %s was accepted", scalar)
			}
		})
	}
}

func TestRawDeviceJSONAllowsFutureLSBLKFields(t *testing.T) {
	data := []byte(`{"blockdevices":[{"name":"sdz","path":"/dev/sdz","type":"disk","size":4096,"future-field":"ignored"}]}`)
	var raw rawList
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
}
