// Package volumelabel defines the filesystem-specific label contract shared by
// every media writer and formatter.
package volumelabel

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	fat32MaxBytes = 11
	ntfsMaxUTF16  = 32
)

// FAT32 applies the conservative portable FAT label contract. Empty input uses
// fallback; any non-empty input is otherwise preserved for validation before
// canonical ASCII uppercasing.
func FAT32(value, fallback string) (string, error) {
	value = withFallback(value, fallback)
	if err := validateExact(value, "FAT32"); err != nil {
		return "", err
	}
	value = strings.ToUpper(value)
	if len([]byte(value)) > fat32MaxBytes {
		return "", fmt.Errorf("FAT32 volume label must contain at most %d ASCII bytes", fat32MaxBytes)
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "", errors.New("FAT32 volume label must use printable ASCII")
		}
		if strings.ContainsRune(`"*+,./:;<=>?[\]|`, character) {
			return "", errors.New("FAT32 volume label contains an unsupported character")
		}
	}
	return value, nil
}

// NTFS preserves the exact valid Unicode spelling and case. The on-disk limit
// is measured in UTF-16 code units rather than UTF-8 bytes or Go runes.
func NTFS(value, fallback string) (string, error) {
	value = withFallback(value, fallback)
	if err := validateExact(value, "NTFS"); err != nil {
		return "", err
	}
	for _, character := range value {
		if strings.ContainsRune(`"*/:<>?\|`, character) {
			return "", errors.New("NTFS volume label contains an unsupported character")
		}
	}
	if units := len(utf16.Encode([]rune(value))); units > ntfsMaxUTF16 {
		return "", fmt.Errorf("NTFS volume label must contain at most %d UTF-16 code units", ntfsMaxUTF16)
	}
	return value, nil
}

func withFallback(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func validateExact(value, filesystem string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s volume label is not valid UTF-8", filesystem)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s volume label must not have leading or trailing whitespace", filesystem)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s volume label must not contain control characters", filesystem)
		}
	}
	return nil
}
