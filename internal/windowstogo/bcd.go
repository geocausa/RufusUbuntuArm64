//go:build linux

package windowstogo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const (
	bootManagerGUIDText = "9dea862c-5cdd-4e70-acc1-f32b344d4795"
	loaderGUIDText      = "b012b84d-c47c-4ed5-b722-c0c42163e569"
	bootManagerType     = uint64(269484034)
	loaderType          = uint64(270532611)
	maxBCDTemplateBytes = 4 * 1024 * 1024
	maxBCDXMLBytes      = 16 * 1024 * 1024
)

var bcdLocalePattern = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$`)
var bcdWorkspaceRoot = "/run"

type BCDOptions struct {
	TemplatePath string
	OutputPath   string
	DiskGUID     GUID
	ESPGUID      GUID
	OSGUID       GUID
	Locale       string
	Description  string
}

type BCDEvidence struct {
	BootManagerGUID string `json:"boot_manager_guid"`
	LoaderGUID      string `json:"loader_guid"`
	DiskGUID        string `json:"disk_guid"`
	ESPGUID         string `json:"esp_guid"`
	OSGUID          string `json:"os_guid"`
	Locale          string `json:"locale"`
	Description     string `json:"description"`
	LoaderPath      string `json:"loader_path"`
	OutputBytes     uint64 `json:"output_bytes"`
}

func GPTDeviceRecord(partitionGUID, diskGUID GUID) [88]byte {
	var record [88]byte
	binary.LittleEndian.PutUint64(record[16:24], 6)
	binary.LittleEndian.PutUint64(record[24:32], 72)
	partitionBytes := partitionGUID.DiskBytes()
	diskBytes := diskGUID.DiskBytes()
	copy(record[32:48], partitionBytes[:])
	copy(record[56:72], diskBytes[:])
	return record
}

func CreateBCD(ctx context.Context, options BCDOptions) (BCDEvidence, error) {
	if err := validateBCDOptions(options); err != nil {
		return BCDEvidence{}, err
	}
	template, err := openBCDTemplate(options.TemplatePath)
	if err != nil {
		return BCDEvidence{}, err
	}
	defer template.Close()
	outputParent, outputName, err := openBCDOutputParent(options.OutputPath)
	if err != nil {
		return BCDEvidence{}, err
	}
	defer outputParent.Close()
	if _, err := os.Lstat(options.OutputPath); err == nil {
		return BCDEvidence{}, errors.New("the BCD output path already exists")
	} else if !os.IsNotExist(err) {
		return BCDEvidence{}, fmt.Errorf("inspect BCD output path: %w", err)
	}
	stableTemplate := stableBCDPath(template)
	stableOutput := stableBCDChildPath(outputParent, outputName)

	templateXML, err := inspectHive(ctx, stableTemplate)
	if err != nil {
		return BCDEvidence{}, fmt.Errorf("inspect BCD template: %w", err)
	}
	hive, err := parseHive(templateXML)
	if err != nil {
		return BCDEvidence{}, fmt.Errorf("parse BCD template: %w", err)
	}
	bootManager, err := requireBCDObject(hive, bootManagerGUIDText, bootManagerType)
	if err != nil {
		return BCDEvidence{}, err
	}
	loader, err := requireBCDObject(hive, loaderGUIDText, loaderType)
	if err != nil {
		return BCDEvidence{}, err
	}
	scriptOptions := options
	scriptOptions.OutputPath = stableOutput
	script, err := buildBCDScript(scriptOptions, bootManager, loader)
	if err != nil {
		return BCDEvidence{}, err
	}
	workspace, err := openBCDWorkspaceRoot(bcdWorkspaceRoot)
	if err != nil {
		return BCDEvidence{}, err
	}
	defer workspace.Close()
	scriptFile, err := os.CreateTemp(stableBCDPath(workspace), ".rufusarm64-bcd-*.hivex")
	if err != nil {
		return BCDEvidence{}, fmt.Errorf("create private BCD transaction script: %w", err)
	}
	scriptPath := scriptFile.Name()
	defer os.Remove(scriptPath)
	if err := scriptFile.Chmod(0o600); err != nil {
		scriptFile.Close()
		return BCDEvidence{}, fmt.Errorf("secure BCD transaction script: %w", err)
	}
	if _, err := scriptFile.WriteString(script); err != nil {
		scriptFile.Close()
		return BCDEvidence{}, fmt.Errorf("write BCD transaction script: %w", err)
	}
	if err := scriptFile.Sync(); err != nil {
		scriptFile.Close()
		return BCDEvidence{}, fmt.Errorf("sync BCD transaction script: %w", err)
	}
	if err := scriptFile.Close(); err != nil {
		return BCDEvidence{}, fmt.Errorf("close BCD transaction script: %w", err)
	}

	hivexsh, err := trustedexec.Resolve("hivexsh")
	if err != nil {
		return BCDEvidence{}, fmt.Errorf("resolve trusted hivexsh: %w", err)
	}
	command := exec.CommandContext(ctx, hivexsh, "-w", "-f", scriptPath, stableTemplate)
	command.Dir = "/"
	command.Env = bcdEnvironment()
	var stdout, stderr boundedBuffer
	stdout.limit = 64 * 1024
	stderr.limit = 64 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		_ = os.Remove(options.OutputPath)
		if ctx.Err() != nil {
			return BCDEvidence{}, ctx.Err()
		}
		return BCDEvidence{}, fmt.Errorf("commit BCD transaction: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	evidence, err := VerifyBCD(ctx, options)
	if err != nil {
		_ = os.Remove(options.OutputPath)
		return BCDEvidence{}, err
	}
	return evidence, nil
}

func VerifyBCD(ctx context.Context, options BCDOptions) (BCDEvidence, error) {
	if err := validateBCDOptions(options); err != nil {
		return BCDEvidence{}, err
	}
	info, err := os.Lstat(options.OutputPath)
	if err != nil {
		return BCDEvidence{}, fmt.Errorf("inspect generated BCD: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxBCDTemplateBytes {
		return BCDEvidence{}, errors.New("generated BCD is not a bounded regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return BCDEvidence{}, errors.New("generated BCD must have exactly one link")
	}
	outputXML, err := inspectHive(ctx, options.OutputPath)
	if err != nil {
		return BCDEvidence{}, fmt.Errorf("reopen generated BCD: %w", err)
	}
	hive, err := parseHive(outputXML)
	if err != nil {
		return BCDEvidence{}, fmt.Errorf("parse generated BCD: %w", err)
	}
	bootManager, err := requireBCDObject(hive, bootManagerGUIDText, bootManagerType)
	if err != nil {
		return BCDEvidence{}, err
	}
	loader, err := requireBCDObject(hive, loaderGUIDText, loaderType)
	if err != nil {
		return BCDEvidence{}, err
	}
	espRecord := GPTDeviceRecord(options.ESPGUID, options.DiskGUID)
	if err := verifyBinaryElement(bootManager, "11000001", espRecord[:]); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyStringElement(bootManager, "12000005", options.Locale); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyStringElement(bootManager, "23000003", "{"+loaderGUIDText+"}"); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyStringListElement(bootManager, "24000001", "{"+loaderGUIDText+"}"); err != nil {
		return BCDEvidence{}, err
	}
	osRecord := GPTDeviceRecord(options.OSGUID, options.DiskGUID)
	if err := verifyBinaryElement(loader, "11000001", osRecord[:]); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyBinaryElement(loader, "21000001", osRecord[:]); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyStringElement(loader, "12000002", `\WINDOWS\system32\winload.efi`); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyStringElement(loader, "12000004", options.Description); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyStringElement(loader, "12000005", options.Locale); err != nil {
		return BCDEvidence{}, err
	}
	if err := verifyBinaryElement(loader, "16000009", []byte{0}); err != nil {
		return BCDEvidence{}, fmt.Errorf("verify disabled Windows Recovery Environment: %w", err)
	}
	return BCDEvidence{
		BootManagerGUID: bootManagerGUIDText, LoaderGUID: loaderGUIDText,
		DiskGUID: options.DiskGUID.String(), ESPGUID: options.ESPGUID.String(), OSGUID: options.OSGUID.String(),
		Locale: options.Locale, Description: options.Description,
		LoaderPath: `\WINDOWS\system32\winload.efi`, OutputBytes: uint64(info.Size()),
	}, nil
}

func validateBCDOptions(options BCDOptions) error {
	for label, path := range map[string]string{"template": options.TemplatePath, "output": options.OutputPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n") {
			return fmt.Errorf("BCD %s path must be canonical and absolute", label)
		}
	}
	if filepath.Clean(options.TemplatePath) == filepath.Clean(options.OutputPath) {
		return errors.New("the BCD output must not replace its template")
	}
	if !bcdLocalePattern.MatchString(options.Locale) {
		return fmt.Errorf("invalid BCD locale %q", options.Locale)
	}
	if options.Description != "Windows 11" {
		return errors.New("experimental Windows To Go BCD description must be the fixed text Windows 11")
	}
	if options.DiskGUID == (GUID{}) || options.ESPGUID == (GUID{}) || options.OSGUID == (GUID{}) ||
		options.DiskGUID == options.ESPGUID || options.DiskGUID == options.OSGUID || options.ESPGUID == options.OSGUID {
		return errors.New("the BCD transaction requires three distinct nonzero GPT GUIDs")
	}
	return nil
}

func stableBCDPath(file *os.File) string {
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd())
}

func stableBCDChildPath(directory *os.File, name string) string {
	return stableBCDPath(directory) + "/" + name
}

func openBCDOutputParent(path string) (*os.File, string, error) {
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || strings.ContainsAny(name, " \\t\\r\\n/") {
		return nil, "", errors.New("the BCD output filename is not safe for a hive transaction")
	}
	parentPath := filepath.Dir(path)
	parent, err := openSecureBCDDirectory(parentPath, "output parent")
	if err != nil {
		return nil, "", err
	}
	return parent, name, nil
}

func openBCDWorkspaceRoot(path string) (*os.File, error) {
	return openSecureBCDDirectory(path, "workspace root")
}

func openSecureBCDDirectory(path, label string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect BCD %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("BCD %s must be a real directory", label)
	}
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open BCD %s: %w", label, err)
	}
	openInfo, err := directory.Stat()
	if err != nil {
		directory.Close()
		return nil, fmt.Errorf("inspect open BCD %s: %w", label, err)
	}
	if !os.SameFile(info, openInfo) {
		directory.Close()
		return nil, fmt.Errorf("BCD %s changed while opening", label)
	}
	stat, ok := openInfo.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || openInfo.Mode().Perm()&0o022 != 0 {
		directory.Close()
		return nil, fmt.Errorf("BCD %s must be owned by the effective user and not group/world writable", label)
	}
	return directory, nil
}

func openBCDTemplate(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open BCD template: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect BCD template: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maxBCDTemplateBytes {
		file.Close()
		return nil, errors.New("the BCD template must be a bounded single-link regular file")
	}
	return file, nil
}

func buildBCDScript(options BCDOptions, bootManager, loader *hiveNode) (string, error) {
	var lines []string
	set := func(object *hiveNode, objectGUID, element, value string) {
		base := `\Objects\{` + objectGUID + `}\Elements`
		if object.element(element) == nil {
			lines = append(lines, "cd "+base, "add "+element)
		}
		lines = append(lines, "cd "+base+`\`+element, "setval 1", "Element", value)
	}
	espRecord := GPTDeviceRecord(options.ESPGUID, options.DiskGUID)
	osRecord := GPTDeviceRecord(options.OSGUID, options.DiskGUID)
	loaderValue := "{" + loaderGUIDText + "}"
	set(bootManager, bootManagerGUIDText, "11000001", hiveBinary(espRecord[:]))
	set(bootManager, bootManagerGUIDText, "12000005", "string:"+options.Locale)
	set(bootManager, bootManagerGUIDText, "23000003", "string:"+loaderValue)
	set(bootManager, bootManagerGUIDText, "24000001", hiveMultiString([]string{loaderValue}))
	set(loader, loaderGUIDText, "11000001", hiveBinary(osRecord[:]))
	set(loader, loaderGUIDText, "21000001", hiveBinary(osRecord[:]))
	set(loader, loaderGUIDText, "12000002", `string:\WINDOWS\system32\winload.efi`)
	set(loader, loaderGUIDText, "12000004", "string:"+options.Description)
	set(loader, loaderGUIDText, "12000005", "string:"+options.Locale)
	set(loader, loaderGUIDText, "16000009", hiveBinary([]byte{0}))
	lines = append(lines, "commit "+options.OutputPath, "quit")
	return strings.Join(lines, "\n") + "\n", nil
}

func hiveBinary(value []byte) string {
	parts := make([]string, len(value))
	for index, item := range value {
		parts[index] = fmt.Sprintf("%02x", item)
	}
	return "hex:3:" + strings.Join(parts, ",")
}

func hiveMultiString(values []string) string {
	text := strings.Join(values, "\x00") + "\x00\x00"
	encoded := make([]byte, 0, len(text)*2)
	for _, character := range text {
		encoded = binary.LittleEndian.AppendUint16(encoded, uint16(character))
	}
	parts := make([]string, len(encoded))
	for index, item := range encoded {
		parts[index] = fmt.Sprintf("%02x", item)
	}
	return "hex:7:" + strings.Join(parts, ",")
}

func inspectHive(ctx context.Context, path string) ([]byte, error) {
	hivexml, err := trustedexec.Resolve("hivexml")
	if err != nil {
		return nil, fmt.Errorf("resolve trusted hivexml: %w", err)
	}
	command := exec.CommandContext(ctx, hivexml, path)
	command.Dir = "/"
	command.Env = bcdEnvironment()
	var stdout, stderr boundedBuffer
	stdout.limit = maxBCDXMLBytes
	stderr.limit = 64 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("hivexml: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func bcdEnvironment() []string {
	return []string{"HOME=/nonexistent", "LC_ALL=C.UTF-8", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TZ=UTC"}
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if buffer.limit <= 0 || buffer.buffer.Len()+len(value) > buffer.limit {
		return 0, errors.New("the BCD provider output exceeds its safe limit")
	}
	return buffer.buffer.Write(value)
}

func (buffer *boundedBuffer) Bytes() []byte  { return buffer.buffer.Bytes() }
func (buffer *boundedBuffer) String() string { return buffer.buffer.String() }

type hiveDocument struct {
	Nodes []hiveNode `xml:"node"`
}

type hiveNode struct {
	Name   string      `xml:"name,attr"`
	Nodes  []hiveNode  `xml:"node"`
	Values []hiveValue `xml:"value"`
}

type hiveValue struct {
	Key     string       `xml:"key,attr"`
	Type    string       `xml:"type,attr"`
	Value   string       `xml:"value,attr"`
	Strings []hiveString `xml:"string"`
}

type hiveString struct {
	Value string `xml:",chardata"`
}

func parseHive(value []byte) (*hiveNode, error) {
	var document hiveDocument
	decoder := xml.NewDecoder(bytes.NewReader(value))
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var objects *hiveNode
	selectObjects := func(candidate *hiveNode) error {
		if candidate == nil || !strings.EqualFold(candidate.Name, "Objects") {
			return nil
		}
		if objects != nil {
			return errors.New("the BCD hive contains multiple Objects roots")
		}
		objects = candidate
		return nil
	}
	for index := range document.Nodes {
		if err := selectObjects(&document.Nodes[index]); err != nil {
			return nil, err
		}
		for child := range document.Nodes[index].Nodes {
			if err := selectObjects(&document.Nodes[index].Nodes[child]); err != nil {
				return nil, err
			}
		}
	}
	if objects == nil {
		return nil, errors.New("the BCD hive has no Objects root")
	}
	return objects, nil
}

func requireBCDObject(objects *hiveNode, guid string, objectType uint64) (*hiveNode, error) {
	object := objects.child("{" + guid + "}")
	if object == nil {
		return nil, fmt.Errorf("BCD template is missing object {%s}", guid)
	}
	description := object.child("Description")
	if description == nil {
		return nil, fmt.Errorf("BCD object {%s} has no Description", guid)
	}
	value := description.value("Type")
	if value == nil {
		return nil, fmt.Errorf("BCD object {%s} has no type", guid)
	}
	actual, err := strconv.ParseUint(value.Value, 10, 64)
	if err != nil || actual != objectType {
		return nil, fmt.Errorf("BCD object {%s} type=%q, want %d", guid, value.Value, objectType)
	}
	return object, nil
}

func (node *hiveNode) child(name string) *hiveNode {
	if node == nil {
		return nil
	}
	for index := range node.Nodes {
		if strings.EqualFold(node.Nodes[index].Name, name) {
			return &node.Nodes[index]
		}
	}
	return nil
}

func (node *hiveNode) value(key string) *hiveValue {
	if node == nil {
		return nil
	}
	for index := range node.Values {
		if node.Values[index].Key == key {
			return &node.Values[index]
		}
	}
	return nil
}

func (node *hiveNode) element(identifier string) *hiveValue {
	elements := node.child("Elements")
	if elements == nil {
		return nil
	}
	element := elements.child(identifier)
	if element == nil {
		return nil
	}
	return element.value("Element")
}

func verifyBinaryElement(object *hiveNode, identifier string, expected []byte) error {
	value := object.element(identifier)
	if value == nil || value.Type != "binary" {
		return fmt.Errorf("BCD element %s is missing or is not binary", identifier)
	}
	actual, err := base64.StdEncoding.DecodeString(value.Value)
	if err != nil || !bytes.Equal(actual, expected) {
		return fmt.Errorf("BCD binary element %s does not match expected %s", identifier, hex.EncodeToString(expected))
	}
	return nil
}

func verifyStringElement(object *hiveNode, identifier, expected string) error {
	value := object.element(identifier)
	if value == nil || value.Type != "string" || value.Value != expected {
		return fmt.Errorf("BCD string element %s=%q, want %q", identifier, valueText(value), expected)
	}
	return nil
}

func verifyStringListElement(object *hiveNode, identifier, expected string) error {
	value := object.element(identifier)
	if value == nil || value.Type != "string-list" || len(value.Strings) == 0 || value.Strings[0].Value != expected {
		return fmt.Errorf("BCD string-list element %s does not begin with %q", identifier, expected)
	}
	for _, item := range value.Strings[1:] {
		if item.Value != "" {
			return fmt.Errorf("BCD string-list element %s contains unexpected value %q", identifier, item.Value)
		}
	}
	return nil
}

func valueText(value *hiveValue) string {
	if value == nil {
		return "<missing>"
	}
	return value.Value
}
