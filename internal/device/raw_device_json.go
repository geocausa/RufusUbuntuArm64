package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// UnmarshalJSON preserves lsblk numeric tokens as decimal strings instead of
// routing them through float64. The existing strict scalar parsers then perform
// the final uint64/bool conversion without precision loss.
func (out *rawDevice) UnmarshalJSON(data []byte) error {
	type wireDevice struct {
		Name               string          `json:"name"`
		Path               string          `json:"path"`
		Type               string          `json:"type"`
		Size               json.RawMessage `json:"size"`
		Model              string          `json:"model"`
		Vendor             string          `json:"vendor"`
		Transport          string          `json:"tran"`
		Removable          json.RawMessage `json:"rm"`
		ReadOnly           json.RawMessage `json:"ro"`
		Hotplug            json.RawMessage `json:"hotplug"`
		ParentName         string          `json:"pkname"`
		MajorMinor         string          `json:"maj:min"`
		Serial             string          `json:"serial"`
		WWN                string          `json:"wwn"`
		LogicalSectorSize  json.RawMessage `json:"log-sec"`
		PhysicalSectorSize json.RawMessage `json:"phy-sec"`
		Mountpoints        json.RawMessage `json:"mountpoints"`
		Children           []rawDevice     `json:"children,omitempty"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	var wire wireDevice
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("lsblk device contains multiple JSON values")
		}
		return err
	}

	var err error
	if out.Size, err = decodeExactLSBLKScalar(wire.Size); err != nil {
		return fmt.Errorf("decode size: %w", err)
	}
	if out.Removable, err = decodeExactLSBLKScalar(wire.Removable); err != nil {
		return fmt.Errorf("decode removable flag: %w", err)
	}
	if out.ReadOnly, err = decodeExactLSBLKScalar(wire.ReadOnly); err != nil {
		return fmt.Errorf("decode read-only flag: %w", err)
	}
	if out.Hotplug, err = decodeExactLSBLKScalar(wire.Hotplug); err != nil {
		return fmt.Errorf("decode hotplug flag: %w", err)
	}
	if out.LogicalSectorSize, err = decodeExactLSBLKScalar(wire.LogicalSectorSize); err != nil {
		return fmt.Errorf("decode logical sector size: %w", err)
	}
	if out.PhysicalSectorSize, err = decodeExactLSBLKScalar(wire.PhysicalSectorSize); err != nil {
		return fmt.Errorf("decode physical sector size: %w", err)
	}
	if len(wire.Mountpoints) != 0 {
		if err := json.Unmarshal(wire.Mountpoints, &out.Mountpoints); err != nil {
			return fmt.Errorf("decode mountpoints: %w", err)
		}
	}
	out.Name = wire.Name
	out.Path = wire.Path
	out.Type = wire.Type
	out.Model = wire.Model
	out.Vendor = wire.Vendor
	out.Transport = wire.Transport
	out.ParentName = wire.ParentName
	out.MajorMinor = wire.MajorMinor
	out.Serial = wire.Serial
	out.WWN = wire.WWN
	out.Children = wire.Children
	return nil
}

func decodeExactLSBLKScalar(raw json.RawMessage) (any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return nil, err
		}
		return value, nil
	}
	if bytes.Equal(trimmed, []byte("true")) {
		return true, nil
	}
	if bytes.Equal(trimmed, []byte("false")) {
		return false, nil
	}
	for _, b := range trimmed {
		if b < '0' || b > '9' {
			return nil, fmt.Errorf("unsupported scalar %q", string(trimmed))
		}
	}
	return string(trimmed), nil
}
