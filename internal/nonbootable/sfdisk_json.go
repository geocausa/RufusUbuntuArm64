//go:build linux

package nonbootable

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON deliberately accepts optional fields emitted by different
// util-linux versions. Required fields are still validated exactly by
// validateSfdiskDocument before any partition path is trusted.
func (document *sfdiskDocument) UnmarshalJSON(data []byte) error {
	type documentAlias sfdiskDocument
	var decoded documentAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("decode sfdisk document: %w", err)
	}
	*document = sfdiskDocument(decoded)
	return nil
}
