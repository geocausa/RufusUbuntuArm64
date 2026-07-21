//go:build linux

package qualification

import (
	"errors"
	"fmt"
	"strings"
)

func normalizeRecordProperties(properties map[string]string) (map[string]string, error) {
	if properties == nil {
		return nil, nil
	}
	clean := make(map[string]string, len(properties))
	for rawKey, rawValue := range properties {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if key == "" || len(key) > 64 || len(value) > 256 {
			return nil, errors.New("creation record property is invalid")
		}
		if _, exists := clean[key]; exists {
			return nil, fmt.Errorf("creation record properties collide after normalization at %q", key)
		}
		clean[key] = value
	}
	return clean, nil
}
