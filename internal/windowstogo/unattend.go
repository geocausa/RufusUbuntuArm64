//go:build linux

package windowstogo

import "github.com/geocausa/RufusArm64/internal/windowsconfig"

// WindowsToGoAnswerFile creates the exact answer file installed below
// Windows/Panther. SAN policy 4 is mandatory; selected first-boot preferences
// use the shared Windows configuration generator and exclude windowsPE-only
// installer behavior.
func WindowsToGoAnswerFile(customizations Customizations) ([]byte, error) {
	return windowsconfig.GenerateWindowsToGo("arm64", customizations.windowsOptions())
}

// WindowsToGoOfflinePolicy preserves the original narrow API for callers and
// tests that need only the mandatory internal-disk offline policy.
func WindowsToGoOfflinePolicy() ([]byte, error) {
	return WindowsToGoAnswerFile(Customizations{})
}
