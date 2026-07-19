//go:build linux

package drivebackup

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

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
