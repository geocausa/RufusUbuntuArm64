//go:build linux

package ffu

import "testing"

func FuzzParseTrustStoreUpdateEvidenceDoesNotPanic(f *testing.F) {
	f.Add([]byte("not json"))
	f.Add([]byte(`{"schema":1,"purpose":"ffu-trust-bundle-update-generation"}`))
	f.Add([]byte(`{"schema":1,"purpose":"ffu-trust-bundle-withdrawal-generation","withdrawn":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseTrustStoreEvidence(data)
	})
}
