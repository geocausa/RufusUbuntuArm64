//go:build linux

package drivebackup

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func validateGraphicalDestinationDirectory(directory *os.File) error {
	uidText := strings.TrimSpace(os.Getenv("PKEXEC_UID"))
	if uidText == "" {
		return nil
	}
	uid, groups, err := resolveGraphicalCredentials(uidText)
	if err != nil {
		return err
	}
	metadata, err := destinationMetadata(directory)
	if err != nil {
		return fmt.Errorf("verify graphical backup destination directory: %w", err)
	}
	if metadata.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("graphical backup destination is not a directory")
	}
	if !directoryPermitsCreate(metadata, uid, groups) {
		return fmt.Errorf(
			"graphical backup destination directory is not writable and searchable by desktop user %d",
			uid,
		)
	}
	return nil
}

func resolveGraphicalCredentials(uidText string) (int, map[uint32]struct{}, error) {
	uid, err := resolveGraphicalUID(uidText)
	if err != nil {
		return 0, nil, err
	}
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return 0, nil, fmt.Errorf("resolve graphical backup user %d: %w", uid, err)
	}
	groupTexts, err := account.GroupIds()
	if err != nil {
		return 0, nil, fmt.Errorf("resolve graphical backup groups for user %d: %w", uid, err)
	}
	groupTexts = append(groupTexts, account.Gid)
	groups := make(map[uint32]struct{}, len(groupTexts))
	for _, groupText := range groupTexts {
		group64, err := strconv.ParseUint(strings.TrimSpace(groupText), 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("graphical backup user %d has invalid group %q", uid, groupText)
		}
		groups[uint32(group64)] = struct{}{}
	}
	return uid, groups, nil
}

func directoryPermitsCreate(metadata *syscall.Stat_t, uid int, groups map[uint32]struct{}) bool {
	if metadata == nil || uid < 0 || metadata.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return false
	}
	permissions := metadata.Mode & 0o7
	if metadata.Uid == uint32(uid) {
		permissions = (metadata.Mode >> 6) & 0o7
	} else if _, ok := groups[metadata.Gid]; ok {
		permissions = (metadata.Mode >> 3) & 0o7
	}
	return permissions&0o3 == 0o3
}

func applyGraphicalDestinationOwner(file *os.File) error {
	uidText := strings.TrimSpace(os.Getenv("PKEXEC_UID"))
	if uidText == "" {
		return nil
	}
	uid, err := resolveGraphicalUID(uidText)
	if err != nil {
		return err
	}
	return applyDestinationOwner(file, uid)
}

func resolveGraphicalUID(uidText string) (int, error) {
	uid64, err := strconv.ParseInt(strings.TrimSpace(uidText), 10, 32)
	if err != nil || uid64 < 0 {
		return 0, fmt.Errorf("invalid PKEXEC_UID %q", uidText)
	}
	return int(uid64), nil
}

func applyDestinationOwner(file *os.File, uid int) error {
	if file == nil || uid < 0 {
		return fmt.Errorf("invalid graphical destination ownership request")
	}
	metadata, err := destinationMetadata(file)
	if err != nil {
		return err
	}
	// FAT, exFAT, and some NTFS mounts map every file to a configured UID and
	// reject chown. If the mounted filesystem already reports the desktop user,
	// the owner-only image is usable and no ownership mutation is required.
	if int(metadata.Uid) != uid {
		// A group value of -1 preserves the filesystem-selected group. Only the
		// authenticated desktop UID is authoritative for this handoff.
		if err := file.Chown(uid, -1); err != nil {
			return fmt.Errorf("assign backup image to graphical user: %w", err)
		}
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync backup image ownership: %w", err)
	}
	metadata, err = destinationMetadata(file)
	if err != nil {
		return err
	}
	if int(metadata.Uid) != uid {
		return fmt.Errorf(
			"verify backup image ownership: got %d:%d, expected user %d",
			metadata.Uid,
			metadata.Gid,
			uid,
		)
	}
	return nil
}

func destinationMetadata(file *os.File) (*syscall.Stat_t, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("verify backup image ownership: %w", err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("verify backup image ownership: unsupported file metadata")
	}
	return metadata, nil
}
