#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} anchor count is {count}, expected 1")
    return text.replace(old, new, 1)


device = Path("internal/device/device.go")
text = device.read_text()
text = replace_once(
    text,
    '''\tDiskSequence string        `json:"disk_sequence"`\n\tIdentity     string        `json:"identity"`\n''',
    '''\tDiskSequence       string        `json:"disk_sequence"`\n\tLogicalSectorSize  uint64        `json:"logical_sector_size"`\n\tPhysicalSectorSize uint64        `json:"physical_sector_size"`\n\tIdentity           string        `json:"identity"`\n''',
    "normalized sector geometry fields",
)
text = replace_once(
    text,
    '''\tWWN         string      `json:"wwn"`\n\tMountpoints any         `json:"mountpoints"`\n''',
    '''\tWWN                string      `json:"wwn"`\n\tLogicalSectorSize  any         `json:"log-sec"`\n\tPhysicalSectorSize any         `json:"phy-sec"`\n\tMountpoints        any         `json:"mountpoints"`\n''',
    "raw sector geometry fields",
)
text = replace_once(
    text,
    '''\t\t"NAME,PATH,TYPE,SIZE,MODEL,VENDOR,TRAN,RM,RO,HOTPLUG,MOUNTPOINTS,PKNAME,MAJ:MIN,SERIAL,WWN",\n''',
    '''\t\t"NAME,PATH,TYPE,SIZE,MODEL,VENDOR,TRAN,RM,RO,HOTPLUG,MOUNTPOINTS,PKNAME,MAJ:MIN,SERIAL,WWN,LOG-SEC,PHY-SEC",\n''',
    "lsblk sector geometry columns",
)
text = replace_once(
    text,
    '''\thotplug, err := parseBool(in.Hotplug)\n\tif err != nil {\n\t\treturn BlockDevice{}, fmt.Errorf("parse hotplug flag for %s: %w", in.Path, err)\n\t}\n\tmounts, err := parseMountpoints(in.Mountpoints)\n''',
    '''\thotplug, err := parseBool(in.Hotplug)\n\tif err != nil {\n\t\treturn BlockDevice{}, fmt.Errorf("parse hotplug flag for %s: %w", in.Path, err)\n\t}\n\tlogicalSectorSize, err := parseUint(in.LogicalSectorSize)\n\tif err != nil {\n\t\treturn BlockDevice{}, fmt.Errorf("parse logical sector size for %s: %w", in.Path, err)\n\t}\n\tphysicalSectorSize, err := parseUint(in.PhysicalSectorSize)\n\tif err != nil {\n\t\treturn BlockDevice{}, fmt.Errorf("parse physical sector size for %s: %w", in.Path, err)\n\t}\n\tmounts, err := parseMountpoints(in.Mountpoints)\n''',
    "sector geometry parsing",
)
text = replace_once(
    text,
    '''\t\tDiskSequence: readDiskSequence(strings.TrimSpace(in.Name)),\n\t\tMountpoints:  mounts,\n''',
    '''\t\tDiskSequence:       readDiskSequence(strings.TrimSpace(in.Name)),\n\t\tLogicalSectorSize:  logicalSectorSize,\n\t\tPhysicalSectorSize: physicalSectorSize,\n\t\tMountpoints:        mounts,\n''',
    "sector geometry assignment",
)
device.write_text(text)


test = Path("internal/device/device_test.go")
text = test.read_text()
text = replace_once(
    text,
    '''{"blockdevices":[{"name":"sda","path":"/dev/sda","type":"disk","size":16000000000,"model":"Flash","vendor":"Acme","tran":"usb","rm":0,"ro":0,"hotplug":1,"mountpoints":[null],"pkname":null,"maj:min":"8:0","serial":"SER123","wwn":"WWN123"}]}\n''',
    '''{"blockdevices":[{"name":"sda","path":"/dev/sda","type":"disk","size":16000000000,"model":"Flash","vendor":"Acme","tran":"usb","rm":0,"ro":0,"hotplug":1,"mountpoints":[null],"pkname":null,"maj:min":"8:0","serial":"SER123","wwn":"WWN123","log-sec":512,"phy-sec":4096}]}\n''',
    "device fixture sector geometry",
)
text = replace_once(
    text,
    '''\tif dev.MajorMinor != "8:0" || dev.Serial != "SER123" || dev.WWN != "WWN123" || dev.Identity == "" {\n\t\tt.Fatalf("identity fields missing: %#v", dev)\n\t}\n''',
    '''\tif dev.MajorMinor != "8:0" || dev.Serial != "SER123" || dev.WWN != "WWN123" || dev.Identity == "" {\n\t\tt.Fatalf("identity fields missing: %#v", dev)\n\t}\n\tif dev.LogicalSectorSize != 512 || dev.PhysicalSectorSize != 4096 {\n\t\tt.Fatalf("sector geometry missing: %#v", dev)\n\t}\n''',
    "device sector geometry assertion",
)
test.write_text(text)


workflow = Path(".github/workflows/ffu-loop-qualification.yml")
text = workflow.read_text()
text = text.replace(
    "      - 'internal/ffu/**'\n",
    "      - 'internal/ffu/**'\n      - 'internal/device/**'\n      - 'internal/safety/**'\n",
)
if text.count("      - 'internal/device/**'\n") != 2 or text.count("      - 'internal/safety/**'\n") != 2:
    raise SystemExit("FFU workflow device/safety path filters were not added to both triggers")
workflow.write_text(text)
