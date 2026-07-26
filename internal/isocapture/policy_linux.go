//go:build linux

package isocapture

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const (
	ProfileISO9660JolietUDF = "iso9660-joliet-udf"
	ProviderSourceFD        = 3
	providerSourcePath      = "/proc/self/fd/3"
	defaultVolumeID         = "RUFUSARM64"
	fixedSourceDateEpoch    = int64(946684800) // 2000-01-01T00:00:00Z
)

// ProviderPlan is the complete, fixed-policy genisoimage invocation. Image
// bytes are emitted on stdout so the parent retains the private output file and
// never grants the provider a final destination pathname.
type ProviderPlan struct {
	Executable  string   `json:"executable"`
	Arguments   []string `json:"arguments"`
	Environment []string `json:"environment"`
	Profile     string   `json:"profile"`
	SourceFD    int      `json:"source_fd"`
	VolumeID    string   `json:"volume_id"`
}

var resolveGenISOImage = func() (string, error) {
	return trustedexec.Resolve("genisoimage")
}

// BuildProviderPlan validates the one supported bridge profile and returns an
// invocation with no caller-controlled mastering options, graft points, boot
// images, excludes, output pathname, symlink-following policy, or startup
// configuration file.
func BuildProviderPlan(profile, volumeID string) (ProviderPlan, error) {
	if profile != ProfileISO9660JolietUDF {
		return ProviderPlan{}, fmt.Errorf("unsupported ISO capture profile %q", profile)
	}
	if volumeID == "" {
		volumeID = defaultVolumeID
	}
	if err := validateVolumeID(volumeID); err != nil {
		return ProviderPlan{}, err
	}
	executable, err := resolveGenISOImage()
	if err != nil {
		return ProviderPlan{}, fmt.Errorf("resolve trusted genisoimage: %w", err)
	}
	if strings.TrimSpace(executable) == "" {
		return ProviderPlan{}, errors.New("trusted genisoimage resolver returned an empty path")
	}
	return ProviderPlan{
		Executable: executable,
		Arguments: []string{
			"-quiet",
			"-udf",
			"-J",
			"-input-charset", "default",
			"-iso-level", "3",
			"-no-cache-inodes",
			"-no-pad",
			"-V", volumeID,
			"-A", "RufusArm64",
			"-sysid", "LINUX",
			providerSourcePath,
		},
		Environment: []string{
			"GENISOIMAGERC=/dev/null",
			"MKISOFSRC=/dev/null",
			"HOME=/nonexistent",
			"LC_ALL=C.UTF-8",
			"TZ=UTC",
			"SOURCE_DATE_EPOCH=" + strconv.FormatInt(fixedSourceDateEpoch, 10),
		},
		Profile:  profile,
		SourceFD: ProviderSourceFD,
		VolumeID: volumeID,
	}, nil
}

func validateVolumeID(value string) error {
	if len(value) == 0 || len(value) > 32 {
		return errors.New("ISO volume identifier must contain 1 to 32 characters")
	}
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return fmt.Errorf("ISO volume identifier contains unsupported character %q", character)
	}
	return nil
}
