//go:build linux

package windowstogo

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
)

var windowsToGoOfflinePolicy = []byte(`<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="offlineServicing">
    <component name="Microsoft-Windows-PartitionManager" processorArchitecture="arm64" language="neutral" publicKeyToken="31bf3856ad364e35" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <SanPolicy>4</SanPolicy>
    </component>
  </settings>
</unattend>
`)

func WindowsToGoOfflinePolicy() ([]byte, error) {
	policy := append([]byte(nil), windowsToGoOfflinePolicy...)
	decoder := xml.NewDecoder(bytes.NewReader(policy))
	for {
		if _, err := decoder.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}
	return policy, nil
}
