//go:build linux

package uefintfs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/geocausa/RufusArm64/internal/secureboot"
)

const (
	architectureReportSchema   = 1
	ArchitectureManifestSHA256 = "b4256f87b23bf0ef70870857eac2dfdc71053f1fbf3dd47e36f708908930ed16"
)

// FileEvidence binds one architecture-specific file inside the pinned FAT image.
type FileEvidence struct {
	Role          string `json:"role"`
	Path          string `json:"path"`
	Size          uint64 `json:"size"`
	SHA256        string `json:"sha256"`
	Machine       uint16 `json:"machine"`
	MachineName   string `json:"machine_name"`
	Subsystem     uint16 `json:"subsystem"`
	SubsystemName string `json:"subsystem_name"`
}

// ArchitectureEvidence proves one complete fallback/NTFS/exFAT loader triplet.
type ArchitectureEvidence struct {
	Name     string       `json:"name"`
	Fallback FileEvidence `json:"fallback"`
	NTFS     FileEvidence `json:"ntfs_driver"`
	ExFAT    FileEvidence `json:"exfat_driver"`
}

// ArchitectureReport is the bounded structural report for the pinned image.
type ArchitectureReport struct {
	Schema         int                    `json:"schema"`
	Filesystem     string                 `json:"filesystem"`
	VolumeLabel    string                 `json:"volume_label"`
	ImageSize      uint64                 `json:"image_size"`
	ImageSHA256    string                 `json:"image_sha256"`
	Architectures  []ArchitectureEvidence `json:"architectures"`
	ManifestSHA256 string                 `json:"manifest_sha256"`
}

type expectedArchitectureFile struct {
	architecture string
	role         string
	path         string
	size         uint64
	sha256       string
	machine      uint16
	subsystem    uint16
}

var expectedArchitectureFiles = []expectedArchitectureFile{
	{"arm", "fallback", "EFI/Boot/bootarm.efi", 18656, "990acb5c432dcbc91f6b77f62a7578a20874f4ac636b64d0952c6c29ad1b92d9", secureboot.MachineThumb, secureboot.SubsystemEFIApplication},
	{"arm", "ntfs", "EFI/Rufus/ntfs_arm.efi", 40544, "822cd007caa4bbacd692797e3cba9ec1f9e28b7be3eb30c61ffac4725bb5cc1e", secureboot.MachineThumb, secureboot.SubsystemEFIBootServiceDriver},
	{"arm", "exfat", "EFI/Rufus/exfat_arm.efi", 33216, "c53fc4e59a6b71be191830ae37b7096850abef7235902f96afb4ee5b26b7924f", secureboot.MachineThumb, secureboot.SubsystemEFIBootServiceDriver},
	{"arm64", "fallback", "EFI/Boot/bootaa64.efi", 42512, "2a991a37ddfccd8152b043c3cc507bf578708ffb9f8f4c84c72a919d6c4457e3", secureboot.MachineARM64, secureboot.SubsystemEFIApplication},
	{"arm64", "ntfs", "EFI/Rufus/ntfs_aa64.efi", 169488, "887a7c62414fc1584e199fe43e12d134829a56f8d3a91db67cdddd5b98864b85", secureboot.MachineARM64, secureboot.SubsystemEFIBootServiceDriver},
	{"arm64", "exfat", "EFI/Rufus/exfat_aa64.efi", 53248, "629e567847ba028cb6ba1f75af12b1ace2094a6b1e70cddbfe1a99a82cdd0511", secureboot.MachineARM64, secureboot.SubsystemEFIBootServiceDriver},
	{"ia32", "fallback", "EFI/Boot/bootia32.efi", 30288, "32f7c8cb505ce7b32f560a9c51fe6abe14361823a46cb1541039cb52164769c1", secureboot.MachineI386, secureboot.SubsystemEFIApplication},
	{"ia32", "ntfs", "EFI/Rufus/ntfs_ia32.efi", 163152, "a5c02c3774c71620f4d6582495ee2d1c4df4f3cd6bd9986209f4b1f5a90933cf", secureboot.MachineI386, secureboot.SubsystemEFIBootServiceDriver},
	{"ia32", "exfat", "EFI/Rufus/exfat_ia32.efi", 37248, "2cf3e47edd53540c052c2620451e68e6fab2554b10b89dab9d578f3f7ba7816a", secureboot.MachineI386, secureboot.SubsystemEFIBootServiceDriver},
	{"riscv64", "fallback", "EFI/Boot/bootriscv64.efi", 28416, "f314d864e5d9e54a7b1e4d981d6cd9b6ef70a9ff55f7f0913c0b25e55fc13846", secureboot.MachineRISCV64, secureboot.SubsystemEFIApplication},
	{"riscv64", "ntfs", "EFI/Rufus/ntfs_riscv64.efi", 58560, "54befd00ed303abf1ebe38904097336a052e2e82333e319d6ef0fdc3b8f24afc", secureboot.MachineRISCV64, secureboot.SubsystemEFIBootServiceDriver},
	{"riscv64", "exfat", "EFI/Rufus/exfat_riscv64.efi", 48768, "ff036f92211e375d21658bd4fe16f7dc4c3efbb98ced93dd68abef590f2c2613", secureboot.MachineRISCV64, secureboot.SubsystemEFIBootServiceDriver},
	{"x64", "fallback", "EFI/Boot/bootx64.efi", 31888, "5e22e6209ea557fce49cdbab7d06be4fc99e65d45c4fba01da928e763776bb94", secureboot.MachineAMD64, secureboot.SubsystemEFIApplication},
	{"x64", "ntfs", "EFI/Rufus/ntfs_x64.efi", 173584, "d77e7f1c317a42467d3f7ade7b3e0a20996b9bf541492fbc15d6245d8d46dcac", secureboot.MachineAMD64, secureboot.SubsystemEFIBootServiceDriver},
	{"x64", "exfat", "EFI/Rufus/exfat_x64.efi", 41728, "21a5969dcd7b6c149b1dc9408c591749ba9c62fb264e2852cc70061fe3defff6", secureboot.MachineAMD64, secureboot.SubsystemEFIBootServiceDriver},
}

type fat12Image struct {
	data              []byte
	bytesPerSector    uint32
	sectorsPerCluster uint32
	clusterBytes      uint32
	rootOffset        uint32
	rootBytes         uint32
	dataOffset        uint32
	clusterCount      uint32
	fat               []byte
	volumeLabel       string
}

type fat12Entry struct {
	path string
	data []byte
}

func inspectPinnedArchitectureManifest(reader io.Reader, imageDigest string) (ArchitectureReport, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(ImageSize)+1))
	if err != nil {
		return ArchitectureReport{}, fmt.Errorf("read pinned UEFI:NTFS image for architecture inspection: %w", err)
	}
	if uint64(len(data)) != ImageSize {
		return ArchitectureReport{}, fmt.Errorf("architecture inspection read %d bytes, expected %d", len(data), ImageSize)
	}
	filesystem, err := parseFAT12Image(data)
	if err != nil {
		return ArchitectureReport{}, err
	}
	entries, err := filesystem.files()
	if err != nil {
		return ArchitectureReport{}, err
	}
	expectedPaths := make(map[string]expectedArchitectureFile, len(expectedArchitectureFiles))
	for _, expected := range expectedArchitectureFiles {
		key := strings.ToLower(expected.path)
		if _, duplicate := expectedPaths[key]; duplicate {
			return ArchitectureReport{}, fmt.Errorf("duplicate expected UEFI:NTFS path %q", expected.path)
		}
		expectedPaths[key] = expected
	}
	actualEFIPaths := make(map[string]struct{})
	fileEvidence := make(map[string]FileEvidence, len(expectedArchitectureFiles))
	for _, entry := range entries {
		key := strings.ToLower(entry.path)
		if strings.HasPrefix(key, "efi/") && strings.HasSuffix(key, ".efi") {
			actualEFIPaths[key] = struct{}{}
		}
		expected, wanted := expectedPaths[key]
		if !wanted {
			continue
		}
		if uint64(len(entry.data)) != expected.size {
			return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS file %s is %d bytes, expected %d", entry.path, len(entry.data), expected.size)
		}
		digest := sha256.Sum256(entry.data)
		actualDigest := hex.EncodeToString(digest[:])
		if actualDigest != expected.sha256 {
			return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS file %s SHA-256 mismatch", entry.path)
		}
		pe, err := secureboot.InspectEFIImage(entry.data)
		if err != nil {
			return ArchitectureReport{}, fmt.Errorf("inspect UEFI:NTFS file %s: %w", entry.path, err)
		}
		if pe.Machine != expected.machine || pe.Subsystem != expected.subsystem {
			return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS file %s is %s/%s, expected machine 0x%04x subsystem %d", entry.path, pe.MachineName, pe.SubsystemName, expected.machine, expected.subsystem)
		}
		fileEvidence[key] = FileEvidence{
			Role: expected.role, Path: expected.path, Size: expected.size, SHA256: actualDigest,
			Machine: pe.Machine, MachineName: pe.MachineName, Subsystem: pe.Subsystem, SubsystemName: pe.SubsystemName,
		}
	}
	if len(actualEFIPaths) != len(expectedPaths) {
		return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS image contains %d EFI files, expected exactly %d", len(actualEFIPaths), len(expectedPaths))
	}
	for path := range actualEFIPaths {
		if _, expected := expectedPaths[path]; !expected {
			return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS image contains unexpected EFI file %q", path)
		}
	}
	if len(fileEvidence) != len(expectedPaths) {
		return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS image proved %d expected EFI files, expected %d", len(fileEvidence), len(expectedPaths))
	}

	grouped := make(map[string]*ArchitectureEvidence)
	for _, expected := range expectedArchitectureFiles {
		evidence := fileEvidence[strings.ToLower(expected.path)]
		group := grouped[expected.architecture]
		if group == nil {
			group = &ArchitectureEvidence{Name: expected.architecture}
			grouped[expected.architecture] = group
		}
		switch expected.role {
		case "fallback":
			group.Fallback = evidence
		case "ntfs":
			group.NTFS = evidence
		case "exfat":
			group.ExFAT = evidence
		default:
			return ArchitectureReport{}, fmt.Errorf("unsupported UEFI:NTFS architecture role %q", expected.role)
		}
	}
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	architectures := make([]ArchitectureEvidence, 0, len(names))
	for _, name := range names {
		item := *grouped[name]
		if item.Fallback.Path == "" || item.NTFS.Path == "" || item.ExFAT.Path == "" {
			return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS architecture %s is incomplete", name)
		}
		architectures = append(architectures, item)
	}
	manifestBytes, err := json.Marshal(architectures)
	if err != nil {
		return ArchitectureReport{}, fmt.Errorf("encode UEFI:NTFS architecture evidence: %w", err)
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	manifestSHA256 := hex.EncodeToString(manifestDigest[:])
	if manifestSHA256 != ArchitectureManifestSHA256 {
		return ArchitectureReport{}, fmt.Errorf("UEFI:NTFS architecture manifest SHA-256 is %s, expected %s", manifestSHA256, ArchitectureManifestSHA256)
	}
	return ArchitectureReport{
		Schema: architectureReportSchema, Filesystem: "fat12", VolumeLabel: filesystem.volumeLabel,
		ImageSize: ImageSize, ImageSHA256: imageDigest, Architectures: architectures,
		ManifestSHA256: manifestSHA256,
	}, nil
}

func parseFAT12Image(data []byte) (*fat12Image, error) {
	if len(data) < 512 || data[510] != 0x55 || data[511] != 0xaa {
		return nil, errors.New("UEFI:NTFS image has no valid FAT boot-sector signature")
	}
	bytesPerSector := uint32(binary.LittleEndian.Uint16(data[11:13]))
	sectorsPerCluster := uint32(data[13])
	reservedSectors := uint32(binary.LittleEndian.Uint16(data[14:16]))
	fatCount := uint32(data[16])
	rootEntries := uint32(binary.LittleEndian.Uint16(data[17:19]))
	totalSectors := uint32(binary.LittleEndian.Uint16(data[19:21]))
	if totalSectors == 0 {
		totalSectors = binary.LittleEndian.Uint32(data[32:36])
	}
	sectorsPerFAT := uint32(binary.LittleEndian.Uint16(data[22:24]))
	if bytesPerSector < 512 || bytesPerSector > 4096 || bytesPerSector&(bytesPerSector-1) != 0 ||
		sectorsPerCluster == 0 || sectorsPerCluster&(sectorsPerCluster-1) != 0 ||
		reservedSectors == 0 || fatCount == 0 || fatCount > 2 || rootEntries == 0 ||
		totalSectors == 0 || sectorsPerFAT == 0 {
		return nil, errors.New("UEFI:NTFS image has invalid FAT12 geometry")
	}
	if uint64(totalSectors)*uint64(bytesPerSector) != uint64(len(data)) {
		return nil, errors.New("UEFI:NTFS FAT volume size does not match the pinned image")
	}
	rootSectors := (rootEntries*32 + bytesPerSector - 1) / bytesPerSector
	firstDataSector := reservedSectors + fatCount*sectorsPerFAT + rootSectors
	if firstDataSector >= totalSectors {
		return nil, errors.New("UEFI:NTFS FAT data area is outside the image")
	}
	dataSectors := totalSectors - firstDataSector
	clusterCount := dataSectors / sectorsPerCluster
	if clusterCount == 0 || clusterCount >= 4085 {
		return nil, fmt.Errorf("UEFI:NTFS image is not a bounded FAT12 volume: %d clusters", clusterCount)
	}
	fatOffset := uint64(reservedSectors) * uint64(bytesPerSector)
	fatBytes := uint64(sectorsPerFAT) * uint64(bytesPerSector)
	rootOffset := uint64(reservedSectors+fatCount*sectorsPerFAT) * uint64(bytesPerSector)
	rootBytes := uint64(rootEntries) * 32
	dataOffset := uint64(firstDataSector) * uint64(bytesPerSector)
	if fatOffset+fatBytes > uint64(len(data)) || rootOffset+rootBytes > uint64(len(data)) || dataOffset > uint64(len(data)) {
		return nil, errors.New("UEFI:NTFS FAT metadata exceeds the image")
	}
	label := strings.TrimSpace(string(data[43:54]))
	if label != "RUFUS_BOOT" || strings.TrimSpace(string(data[54:62])) != "FAT12" {
		return nil, fmt.Errorf("UEFI:NTFS FAT identity is %q/%q, expected RUFUS_BOOT/FAT12", label, strings.TrimSpace(string(data[54:62])))
	}
	filesystem := &fat12Image{
		data: data, bytesPerSector: bytesPerSector, sectorsPerCluster: sectorsPerCluster,
		clusterBytes: bytesPerSector * sectorsPerCluster, rootOffset: uint32(rootOffset), rootBytes: uint32(rootBytes),
		dataOffset: uint32(dataOffset), clusterCount: clusterCount, fat: data[fatOffset : fatOffset+fatBytes], volumeLabel: label,
	}
	if filesystem.nextCluster(0) != 0xff8 || filesystem.nextCluster(1) < 0xff8 {
		return nil, errors.New("UEFI:NTFS FAT12 reserved entries are invalid")
	}
	return filesystem, nil
}

func (filesystem *fat12Image) files() ([]fat12Entry, error) {
	entries := make([]fat12Entry, 0, 20)
	seenDirectories := map[uint16]bool{}
	root := filesystem.data[filesystem.rootOffset : filesystem.rootOffset+filesystem.rootBytes]
	if err := filesystem.walkDirectory(root, "", 0, seenDirectories, &entries); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return entries, nil
}

func (filesystem *fat12Image) walkDirectory(data []byte, parent string, depth int, seenDirectories map[uint16]bool, files *[]fat12Entry) error {
	if depth > 8 {
		return errors.New("UEFI:NTFS FAT directory depth exceeds the safety limit")
	}
	var longEntries [][]byte
	for offset := 0; offset+32 <= len(data); offset += 32 {
		entry := data[offset : offset+32]
		if entry[0] == 0x00 {
			return nil
		}
		if entry[0] == 0xe5 {
			longEntries = nil
			continue
		}
		attribute := entry[11]
		if attribute == 0x0f {
			longEntries = append(longEntries, slices.Clone(entry))
			continue
		}
		name, err := fat12EntryName(entry, longEntries)
		longEntries = nil
		if err != nil {
			return err
		}
		if name == "." || name == ".." || attribute&0x08 != 0 {
			continue
		}
		if name == "" || strings.ContainsAny(name, "/\\\x00") {
			return fmt.Errorf("UEFI:NTFS FAT entry has unsafe name %q", name)
		}
		path := name
		if parent != "" {
			path = parent + "/" + name
		}
		cluster := binary.LittleEndian.Uint16(entry[26:28])
		size := binary.LittleEndian.Uint32(entry[28:32])
		if attribute&0x10 != 0 {
			if cluster < 2 || seenDirectories[cluster] {
				return fmt.Errorf("UEFI:NTFS FAT directory %s has invalid or repeated cluster %d", path, cluster)
			}
			seenDirectories[cluster] = true
			directoryData, err := filesystem.readChain(cluster, 0)
			if err != nil {
				return fmt.Errorf("read UEFI:NTFS FAT directory %s: %w", path, err)
			}
			if err := filesystem.walkDirectory(directoryData, path, depth+1, seenDirectories, files); err != nil {
				return err
			}
			continue
		}
		fileData, err := filesystem.readChain(cluster, uint64(size))
		if err != nil {
			return fmt.Errorf("read UEFI:NTFS FAT file %s: %w", path, err)
		}
		*files = append(*files, fat12Entry{path: path, data: fileData})
		if len(*files) > 64 {
			return errors.New("UEFI:NTFS FAT file count exceeds the safety limit")
		}
	}
	return errors.New("UEFI:NTFS FAT directory has no end marker")
}

func (filesystem *fat12Image) readChain(start uint16, size uint64) ([]byte, error) {
	if size == 0 && start == 0 {
		return nil, nil
	}
	if start < 2 || uint32(start) > filesystem.clusterCount+1 {
		return nil, fmt.Errorf("invalid first cluster %d", start)
	}
	result := make([]byte, 0)
	seen := make(map[uint16]struct{})
	cluster := start
	for {
		if _, duplicate := seen[cluster]; duplicate {
			return nil, errors.New("FAT12 cluster chain contains a loop")
		}
		seen[cluster] = struct{}{}
		if len(seen) > int(filesystem.clusterCount) {
			return nil, errors.New("FAT12 cluster chain exceeds the volume")
		}
		offset := uint64(filesystem.dataOffset) + uint64(uint32(cluster)-2)*uint64(filesystem.clusterBytes)
		end := offset + uint64(filesystem.clusterBytes)
		if end > uint64(len(filesystem.data)) {
			return nil, errors.New("FAT12 cluster exceeds the image")
		}
		result = append(result, filesystem.data[offset:end]...)
		next := filesystem.nextCluster(cluster)
		switch {
		case next >= 0xff8:
			if size > uint64(len(result)) {
				return nil, errors.New("FAT12 cluster chain is shorter than the file size")
			}
			if size > 0 {
				result = result[:size]
			}
			return result, nil
		case next == 0xff7:
			return nil, errors.New("FAT12 cluster chain references a bad cluster")
		case next < 2 || uint32(next) > filesystem.clusterCount+1:
			return nil, fmt.Errorf("FAT12 cluster chain references invalid cluster 0x%03x", next)
		default:
			cluster = next
		}
	}
}

func (filesystem *fat12Image) nextCluster(cluster uint16) uint16 {
	offset := int(cluster) + int(cluster)/2
	if offset+2 > len(filesystem.fat) {
		return 0xff7
	}
	value := binary.LittleEndian.Uint16(filesystem.fat[offset : offset+2])
	if cluster&1 == 0 {
		return value & 0x0fff
	}
	return value >> 4
}

func fat12EntryName(entry []byte, longEntries [][]byte) (string, error) {
	if len(longEntries) == 0 {
		base := strings.TrimSpace(string(entry[0:8]))
		extension := strings.TrimSpace(string(entry[8:11]))
		if extension != "" {
			return base + "." + extension, nil
		}
		return base, nil
	}
	checksum := fat12ShortNameChecksum(entry[:11])
	count := int(longEntries[0][0] & 0x1f)
	if count == 0 || count != len(longEntries) || longEntries[0][0]&0x40 == 0 {
		return "", errors.New("invalid FAT12 long-filename sequence")
	}
	chunks := make([][]uint16, count)
	for index, raw := range longEntries {
		sequence := int(raw[0] & 0x1f)
		if sequence != count-index || raw[13] != checksum || (index > 0 && raw[0]&0x40 != 0) {
			return "", errors.New("invalid FAT12 long-filename ordering or checksum")
		}
		units := make([]uint16, 0, 13)
		for _, pair := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
			for offset := pair[0]; offset < pair[1]; offset += 2 {
				units = append(units, binary.LittleEndian.Uint16(raw[offset:offset+2]))
			}
		}
		chunks[sequence-1] = units
	}
	units := make([]uint16, 0, count*13)
	for _, chunk := range chunks {
		units = append(units, chunk...)
	}
	end := len(units)
	for index, unit := range units {
		if unit == 0x0000 || unit == 0xffff {
			end = index
			break
		}
	}
	name := string(utf16.Decode(units[:end]))
	if name == "" || strings.ContainsRune(name, '\ufffd') {
		return "", errors.New("invalid FAT12 long filename")
	}
	return name, nil
}

func fat12ShortNameChecksum(name []byte) byte {
	var checksum byte
	for _, value := range name {
		checksum = ((checksum & 1) << 7) + (checksum >> 1) + value
	}
	return checksum
}
