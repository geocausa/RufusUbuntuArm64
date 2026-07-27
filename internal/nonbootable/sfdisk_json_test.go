//go:build linux

package nonbootable

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCustomSfdiskDecoderAcceptsOptionalUtilLinuxFields(t *testing.T) {
	payload := []byte(`{
		"partitiontable": {
			"label": "gpt",
			"id": "01234567-89AB-CDEF-0123-456789ABCDEF",
			"device": "/dev/sdb",
			"unit": "sectors",
			"firstlba": 2048,
			"lastlba": 16775134,
			"sectorsize": 512,
			"partitions": [{
				"node": "/dev/sdb1",
				"start": 2048,
				"size": 16773120,
				"type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
				"uuid": "11111111-2222-3333-4444-555555555555",
				"name": "RUFUSARM64-DATA",
				"attrs": ""
			}]
		}
	}`)
	var document sfdiskDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("optional util-linux fields were rejected: %v", err)
	}
	if document.PartitionTable.Device != "/dev/sdb" || len(document.PartitionTable.Partitions) != 1 {
		t.Fatalf("required sfdisk fields were not retained: %+v", document)
	}
}
