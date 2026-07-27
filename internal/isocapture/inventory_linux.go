//go:build linux

package isocapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	InventorySchema = 1
	openPathFlag    = 0x200000 // Linux O_PATH, absent from some syscall tables.
)

type EntryKind string

const (
	EntryDirectory EntryKind = "directory"
	EntryFile      EntryKind = "file"
)

// Limits bounds all descriptor traversal and hashing before any mastering tool
// can run. Zero values select the reviewed defaults.
type Limits struct {
	MaxEntries        int
	MaxDepth          int
	MaxPathBytes      int
	MaxPathLength     int
	MaxComponentBytes int
	MaxFileBytes      uint64
	MaxTotalBytes     uint64
}

func DefaultLimits() Limits {
	return Limits{
		MaxEntries:        100000,
		MaxDepth:          64,
		MaxPathBytes:      16 * 1024 * 1024,
		MaxPathLength:     240,
		MaxComponentBytes: 64,
		MaxFileBytes:      2*1024*1024*1024 - 1,
		MaxTotalBytes:     512 * 1024 * 1024 * 1024,
	}
}

// Entry is one stable source object. Only regular files and directories are
// admitted; symlinks, hard links, devices, sockets, FIFOs and mount crossings
// fail closed.
type Entry struct {
	Path    string    `json:"path"`
	Kind    EntryKind `json:"kind"`
	Size    uint64    `json:"size"`
	Mode    uint32    `json:"mode"`
	Device  uint64    `json:"device"`
	Inode   uint64    `json:"inode"`
	MTimeNS int64     `json:"mtime_ns"`
	CTimeNS int64     `json:"ctime_ns"`
	SHA256  string    `json:"sha256,omitempty"`
}

// Inventory contains both an exact source-binding digest and a content digest.
// The latter deliberately excludes inode and timestamp metadata so a mastered
// image can be compared against the supported path/type/size/content model.
type Inventory struct {
	Schema        int     `json:"schema"`
	Profile       string  `json:"profile"`
	RootDevice    uint64  `json:"root_device"`
	RootInode     uint64  `json:"root_inode"`
	RootMountID   uint64  `json:"root_mount_id"`
	Files         uint64  `json:"files"`
	Directories   uint64  `json:"directories"`
	TotalBytes    uint64  `json:"total_bytes"`
	PathBytes     uint64  `json:"path_bytes"`
	Entries       []Entry `json:"entries"`
	BindingSHA256 string  `json:"binding_sha256"`
	ContentSHA256 string  `json:"content_sha256"`
}

type scanner struct {
	ctx         context.Context
	limits      Limits
	rootDevice  uint64
	rootMountID uint64
	entries     []Entry
	directories map[fileIdentity]string
	files       uint64
	dirs        uint64
	totalBytes  uint64
	pathBytes   uint64
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

// Scan builds a deterministic inventory from a held readable directory
// descriptor. Every child is opened relative to its parent descriptor with
// O_NOFOLLOW, and every opened descriptor must remain on the root mount.
func Scan(ctx context.Context, root *os.File, limits Limits) (Inventory, error) {
	if ctx == nil {
		return Inventory{}, errors.New("ISO capture inventory context is nil")
	}
	if root == nil {
		return Inventory{}, errors.New("ISO capture inventory requires an open root directory")
	}
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	limits, err := normalizeLimits(limits)
	if err != nil {
		return Inventory{}, err
	}
	rootClone, rootStat, err := cloneRootDirectory(root)
	if err != nil {
		return Inventory{}, err
	}
	defer rootClone.Close()
	rootMountID, err := descriptorMountID(rootClone.Fd())
	if err != nil {
		return Inventory{}, err
	}

	scan := &scanner{
		ctx:         ctx,
		limits:      limits,
		rootDevice:  uint64(rootStat.Dev),
		rootMountID: rootMountID,
		directories: make(map[fileIdentity]string),
	}
	rootIdentity := fileIdentity{device: uint64(rootStat.Dev), inode: rootStat.Ino}
	scan.directories[rootIdentity] = "."
	if err := scan.scanDirectory(rootClone, "", 0); err != nil {
		return Inventory{}, err
	}
	sort.Slice(scan.entries, func(i, j int) bool { return scan.entries[i].Path < scan.entries[j].Path })
	inventory := Inventory{
		Schema:      InventorySchema,
		Profile:     ProfileISO9660JolietUDF,
		RootDevice:  uint64(rootStat.Dev),
		RootInode:   rootStat.Ino,
		RootMountID: rootMountID,
		Files:       scan.files,
		Directories: scan.dirs,
		TotalBytes:  scan.totalBytes,
		PathBytes:   scan.pathBytes,
		Entries:     scan.entries,
	}
	inventory.BindingSHA256, err = inventoryDigest(inventory, true)
	if err != nil {
		return Inventory{}, err
	}
	inventory.ContentSHA256, err = inventoryDigest(inventory, false)
	if err != nil {
		return Inventory{}, err
	}
	return inventory, nil
}

func normalizeLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaults.MaxEntries
	}
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaults.MaxDepth
	}
	if limits.MaxPathBytes == 0 {
		limits.MaxPathBytes = defaults.MaxPathBytes
	}
	if limits.MaxPathLength == 0 {
		limits.MaxPathLength = defaults.MaxPathLength
	}
	if limits.MaxComponentBytes == 0 {
		limits.MaxComponentBytes = defaults.MaxComponentBytes
	}
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = defaults.MaxFileBytes
	}
	if limits.MaxTotalBytes == 0 {
		limits.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if limits.MaxEntries < 1 || limits.MaxDepth < 1 || limits.MaxPathBytes < 1 || limits.MaxPathLength < 1 || limits.MaxComponentBytes < 1 || limits.MaxFileBytes < 1 || limits.MaxTotalBytes < 1 {
		return Limits{}, errors.New("ISO capture inventory limits must be positive")
	}
	return limits, nil
}

func cloneRootDirectory(root *os.File) (*os.File, syscall.Stat_t, error) {
	var expected syscall.Stat_t
	if err := syscall.Fstat(int(root.Fd()), &expected); err != nil {
		return nil, syscall.Stat_t{}, fmt.Errorf("inspect ISO capture root descriptor: %w", err)
	}
	if expected.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, syscall.Stat_t{}, errors.New("ISO capture root descriptor is not a directory")
	}
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(root.Fd()), 10)
	clone, err := os.Open(path)
	if err != nil {
		return nil, syscall.Stat_t{}, fmt.Errorf("clone ISO capture root descriptor: %w", err)
	}
	var actual syscall.Stat_t
	if err := syscall.Fstat(int(clone.Fd()), &actual); err != nil {
		clone.Close()
		return nil, syscall.Stat_t{}, fmt.Errorf("inspect cloned ISO capture root: %w", err)
	}
	if !sameStatIdentity(expected, actual) {
		clone.Close()
		return nil, syscall.Stat_t{}, errors.New("ISO capture root changed while its descriptor was cloned")
	}
	return clone, actual, nil
}

func (scan *scanner) scanDirectory(directory *os.File, relative string, depth int) error {
	if err := scan.ctx.Err(); err != nil {
		return err
	}
	if depth > scan.limits.MaxDepth {
		return fmt.Errorf("ISO capture tree exceeds maximum depth %d", scan.limits.MaxDepth)
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(int(directory.Fd()), &before); err != nil {
		return fmt.Errorf("inspect directory %q: %w", displayPath(relative), err)
	}
	if err := scan.requireSameMount(directory.Fd(), before, relative); err != nil {
		return err
	}
	children, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read directory %q: %w", displayPath(relative), err)
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	folded := make(map[string]string, len(children))
	for _, child := range children {
		name := child.Name()
		if err := validateComponent(name, scan.limits.MaxComponentBytes); err != nil {
			return fmt.Errorf("refuse source name under %q: %w", displayPath(relative), err)
		}
		key := strings.ToUpper(name)
		if previous, exists := folded[key]; exists {
			return fmt.Errorf("source names %q and %q collide case-insensitively under %q", previous, name, displayPath(relative))
		}
		folded[key] = name
		path := name
		if relative != "" {
			path = relative + "/" + name
		}
		if len(path) > scan.limits.MaxPathLength {
			return fmt.Errorf("source path %q exceeds maximum length %d", path, scan.limits.MaxPathLength)
		}
		if err := scan.scanChild(directory, path, name, depth+1); err != nil {
			return err
		}
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(directory.Fd()), &after); err != nil {
		return fmt.Errorf("reinspect directory %q: %w", displayPath(relative), err)
	}
	if !sameStableStat(before, after) {
		return fmt.Errorf("source directory %q changed while it was inventoried", displayPath(relative))
	}
	return nil
}

func (scan *scanner) scanChild(parent *os.File, path, name string, depth int) error {
	if err := scan.ctx.Err(); err != nil {
		return err
	}
	inspectionFD, err := syscall.Openat(int(parent.Fd()), name, openPathFlag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("inspect source object %q: %w", path, err)
	}
	var inspected syscall.Stat_t
	statErr := syscall.Fstat(inspectionFD, &inspected)
	closeErr := syscall.Close(inspectionFD)
	if statErr != nil {
		return fmt.Errorf("stat source object %q: %w", path, statErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close source inspection descriptor %q: %w", path, closeErr)
	}

	switch inspected.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		return scan.scanChildDirectory(parent, path, name, depth, inspected)
	case syscall.S_IFREG:
		return scan.scanChildFile(parent, path, name, inspected)
	case syscall.S_IFLNK:
		return fmt.Errorf("source object %q is a symbolic link", path)
	default:
		return fmt.Errorf("source object %q has unsupported file type %#o", path, inspected.Mode&syscall.S_IFMT)
	}
}

func (scan *scanner) scanChildDirectory(parent *os.File, path, name string, depth int, inspected syscall.Stat_t) error {
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open source directory %q: %w", path, err)
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		syscall.Close(fd)
		return fmt.Errorf("wrap source directory %q", path)
	}
	defer directory.Close()
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil {
		return fmt.Errorf("stat opened source directory %q: %w", path, err)
	}
	if !sameStatIdentity(inspected, opened) {
		return fmt.Errorf("source directory %q changed while it was opened", path)
	}
	if err := scan.requireSameMount(directory.Fd(), opened, path); err != nil {
		return err
	}
	identity := fileIdentity{device: uint64(opened.Dev), inode: opened.Ino}
	if previous, exists := scan.directories[identity]; exists {
		return fmt.Errorf("source directory %q repeats directory identity already seen at %q", path, previous)
	}
	scan.directories[identity] = path
	if err := scan.addEntry(entryFromStat(path, EntryDirectory, opened, "")); err != nil {
		return err
	}
	scan.dirs++
	return scan.scanDirectory(directory, path, depth)
}

func (scan *scanner) scanChildFile(parent *os.File, path, name string, inspected syscall.Stat_t) error {
	if inspected.Nlink != 1 {
		return fmt.Errorf("source file %q has %d hard links; only single-link regular files are supported", path, inspected.Nlink)
	}
	if inspected.Size < 0 {
		return fmt.Errorf("source file %q reports a negative size", path)
	}
	size := uint64(inspected.Size)
	if size > scan.limits.MaxFileBytes {
		return fmt.Errorf("source file %q size %d exceeds maximum %d", path, size, scan.limits.MaxFileBytes)
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return fmt.Errorf("wrap source file %q", path)
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return fmt.Errorf("stat opened source file %q: %w", path, err)
	}
	if !sameStatIdentity(inspected, before) {
		return fmt.Errorf("source file %q changed while it was opened", path)
	}
	if err := scan.requireSameMount(file.Fd(), before, path); err != nil {
		return err
	}
	digest, readBytes, err := hashFile(scan.ctx, file)
	if err != nil {
		return fmt.Errorf("hash source file %q: %w", path, err)
	}
	if readBytes != size {
		return fmt.Errorf("source file %q yielded %d bytes, expected %d", path, readBytes, size)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return fmt.Errorf("reinspect source file %q: %w", path, err)
	}
	if !sameStableStat(before, after) {
		return fmt.Errorf("source file %q changed while it was hashed", path)
	}
	if scan.totalBytes > math.MaxUint64-size || scan.totalBytes+size > scan.limits.MaxTotalBytes {
		return fmt.Errorf("source content exceeds maximum total bytes %d", scan.limits.MaxTotalBytes)
	}
	scan.totalBytes += size
	if err := scan.addEntry(entryFromStat(path, EntryFile, after, digest)); err != nil {
		return err
	}
	scan.files++
	return nil
}

func (scan *scanner) requireSameMount(fd uintptr, stat syscall.Stat_t, path string) error {
	if uint64(stat.Dev) != scan.rootDevice {
		return fmt.Errorf("source object %q crosses filesystem device boundary", displayPath(path))
	}
	mountID, err := descriptorMountID(fd)
	if err != nil {
		return fmt.Errorf("inspect mount identity for %q: %w", displayPath(path), err)
	}
	if mountID != scan.rootMountID {
		return fmt.Errorf("source object %q crosses mount boundary", displayPath(path))
	}
	return nil
}

func (scan *scanner) addEntry(entry Entry) error {
	if len(scan.entries) >= scan.limits.MaxEntries {
		return fmt.Errorf("source tree exceeds maximum entries %d", scan.limits.MaxEntries)
	}
	pathBytes := uint64(len(entry.Path))
	if scan.pathBytes > math.MaxUint64-pathBytes || scan.pathBytes+pathBytes > uint64(scan.limits.MaxPathBytes) {
		return fmt.Errorf("source paths exceed maximum aggregate bytes %d", scan.limits.MaxPathBytes)
	}
	scan.pathBytes += pathBytes
	scan.entries = append(scan.entries, entry)
	return nil
}

func validateComponent(name string, maximum int) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid path component %q", name)
	}
	if !utf8.ValidString(name) || len(name) > maximum {
		return fmt.Errorf("path component %q is not valid UTF-8 within %d bytes", name, maximum)
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("path component %q has an unsupported leading or trailing dot", name)
	}
	for _, character := range name {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return fmt.Errorf("path component %q contains unsupported character %q", name, character)
	}
	return nil
}

func descriptorMountID(fd uintptr) (uint64, error) {
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.FormatUint(uint64(fd), 10))
	if err != nil {
		return 0, fmt.Errorf("read descriptor mount metadata: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse descriptor mount id: %w", err)
			}
			return value, nil
		}
	}
	return 0, errors.New("descriptor mount id is unavailable")
}

func hashFile(ctx context.Context, file *os.File) (string, uint64, error) {
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return "", total, err
		}
		count, err := file.Read(buffer)
		if count > 0 {
			if _, writeErr := hash.Write(buffer[:count]); writeErr != nil {
				return "", total, writeErr
			}
			total += uint64(count)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", total, err
		}
		if count == 0 {
			return "", total, io.ErrNoProgress
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), total, nil
}

func inventoryDigest(inventory Inventory, binding bool) (string, error) {
	type contentEntry struct {
		Path   string    `json:"path"`
		Kind   EntryKind `json:"kind"`
		Size   uint64    `json:"size"`
		SHA256 string    `json:"sha256,omitempty"`
	}
	if !binding {
		entries := make([]contentEntry, 0, len(inventory.Entries))
		for _, entry := range inventory.Entries {
			entries = append(entries, contentEntry{Path: entry.Path, Kind: entry.Kind, Size: entry.Size, SHA256: entry.SHA256})
		}
		payload := struct {
			Schema      int            `json:"schema"`
			Profile     string         `json:"profile"`
			Files       uint64         `json:"files"`
			Directories uint64         `json:"directories"`
			TotalBytes  uint64         `json:"total_bytes"`
			Entries     []contentEntry `json:"entries"`
		}{inventory.Schema, inventory.Profile, inventory.Files, inventory.Directories, inventory.TotalBytes, entries}
		return marshalSHA256(payload)
	}
	payload := struct {
		Schema      int     `json:"schema"`
		Profile     string  `json:"profile"`
		RootDevice  uint64  `json:"root_device"`
		RootInode   uint64  `json:"root_inode"`
		RootMountID uint64  `json:"root_mount_id"`
		Files       uint64  `json:"files"`
		Directories uint64  `json:"directories"`
		TotalBytes  uint64  `json:"total_bytes"`
		PathBytes   uint64  `json:"path_bytes"`
		Entries     []Entry `json:"entries"`
	}{inventory.Schema, inventory.Profile, inventory.RootDevice, inventory.RootInode, inventory.RootMountID, inventory.Files, inventory.Directories, inventory.TotalBytes, inventory.PathBytes, inventory.Entries}
	return marshalSHA256(payload)
}

func marshalSHA256(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func entryFromStat(path string, kind EntryKind, stat syscall.Stat_t, digest string) Entry {
	return Entry{
		Path:    path,
		Kind:    kind,
		Size:    uint64(maxInt64(stat.Size, 0)),
		Mode:    stat.Mode,
		Device:  uint64(stat.Dev),
		Inode:   stat.Ino,
		MTimeNS: timespecNS(stat.Mtim),
		CTimeNS: timespecNS(stat.Ctim),
		SHA256:  digest,
	}
}

func sameStatIdentity(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&syscall.S_IFMT == right.Mode&syscall.S_IFMT
}

func sameStableStat(left, right syscall.Stat_t) bool {
	return sameStatIdentity(left, right) && left.Mode == right.Mode && left.Size == right.Size && left.Nlink == right.Nlink && timespecNS(left.Mtim) == timespecNS(right.Mtim) && timespecNS(left.Ctim) == timespecNS(right.Ctim)
}

func timespecNS(value syscall.Timespec) int64 {
	return value.Sec*1_000_000_000 + value.Nsec
}

func maxInt64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func displayPath(path string) string {
	if path == "" {
		return "."
	}
	return path
}
