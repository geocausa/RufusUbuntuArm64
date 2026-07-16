//go:build linux

package sourcefile

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// FormatIdentity serializes an inspected source identity for transfer across a
// privilege boundary. It contains kernel metadata only, never file contents.
func FormatIdentity(identity Identity) (string, error) {
	if identity.Device == 0 || identity.Inode == 0 || identity.Size <= 0 || identity.ModifiedNS < 0 || identity.ChangedNS < 0 {
		return "", errors.New("source identity is incomplete")
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d", identity.Device, identity.Inode, identity.Size, identity.ModifiedNS, identity.ChangedNS), nil
}

// ParseIdentity decodes the exact decimal form produced by FormatIdentity.
func ParseIdentity(value string) (Identity, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 5 {
		return Identity{}, errors.New("source identity must contain five decimal fields")
	}
	device, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("parse source device identity: %w", err)
	}
	inode, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("parse source inode identity: %w", err)
	}
	size, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("parse source size identity: %w", err)
	}
	modified, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("parse source modification identity: %w", err)
	}
	changed, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return Identity{}, fmt.Errorf("parse source change identity: %w", err)
	}
	identity := Identity{Device: device, Inode: inode, Size: size, ModifiedNS: modified, ChangedNS: changed}
	if _, err := FormatIdentity(identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}
