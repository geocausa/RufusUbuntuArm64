//go:build linux

package isocapture

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBuildProviderPlanUsesFixedDescriptorPolicy(t *testing.T) {
	previous := resolveGenISOImage
	resolveGenISOImage = func() (string, error) { return "/usr/bin/genisoimage", nil }
	t.Cleanup(func() { resolveGenISOImage = previous })

	plan, err := BuildProviderPlan(ProfileISO9660JolietUDF, "TEST_MEDIA")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable != "/usr/bin/genisoimage" || plan.Profile != ProfileISO9660JolietUDF || plan.SourceFD != ProviderSourceFD || plan.VolumeID != "TEST_MEDIA" {
		t.Fatalf("unexpected provider plan: %+v", plan)
	}
	wantArguments := []string{
		"-quiet",
		"-udf",
		"-J",
		"-iso-level", "3",
		"-no-cache-inodes",
		"-no-pad",
		"-V", "TEST_MEDIA",
		"-A", "RufusArm64",
		"-sysid", "LINUX",
		providerSourcePath,
	}
	if !reflect.DeepEqual(plan.Arguments, wantArguments) {
		t.Fatalf("arguments = %#v, want %#v", plan.Arguments, wantArguments)
	}
	wantEnvironment := []string{
		"LC_ALL=C.UTF-8",
		"TZ=UTC",
		"SOURCE_DATE_EPOCH=946684800",
	}
	if !reflect.DeepEqual(plan.Environment, wantEnvironment) {
		t.Fatalf("environment = %#v, want %#v", plan.Environment, wantEnvironment)
	}
	for _, forbidden := range []string{"-o", "-follow-links", "-graft-points", "-exclude", "-b", "-eltorito-boot"} {
		for _, argument := range plan.Arguments {
			if argument == forbidden {
				t.Fatalf("provider plan contains forbidden argument %q", forbidden)
			}
		}
	}
}

func TestBuildProviderPlanUsesReviewedDefaultVolume(t *testing.T) {
	previous := resolveGenISOImage
	resolveGenISOImage = func() (string, error) { return "/usr/bin/genisoimage", nil }
	t.Cleanup(func() { resolveGenISOImage = previous })

	plan, err := BuildProviderPlan(ProfileISO9660JolietUDF, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.VolumeID != defaultVolumeID {
		t.Fatalf("volume id = %q, want %q", plan.VolumeID, defaultVolumeID)
	}
}

func TestBuildProviderPlanRejectsUnsupportedInputs(t *testing.T) {
	previous := resolveGenISOImage
	resolveGenISOImage = func() (string, error) { return "/usr/bin/genisoimage", nil }
	t.Cleanup(func() { resolveGenISOImage = previous })

	for _, test := range []struct {
		name      string
		profile   string
		volumeID  string
		wantError string
	}{
		{name: "profile", profile: "raw", volumeID: "TEST", wantError: "unsupported ISO capture profile"},
		{name: "lowercase", profile: ProfileISO9660JolietUDF, volumeID: "test", wantError: "unsupported character"},
		{name: "dash", profile: ProfileISO9660JolietUDF, volumeID: "TEST-MEDIA", wantError: "unsupported character"},
		{name: "too-long", profile: ProfileISO9660JolietUDF, volumeID: strings.Repeat("A", 33), wantError: "1 to 32"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildProviderPlan(test.profile, test.volumeID)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want text %q", err, test.wantError)
			}
		})
	}
}

func TestBuildProviderPlanFailsClosedOnResolverErrors(t *testing.T) {
	previous := resolveGenISOImage
	t.Cleanup(func() { resolveGenISOImage = previous })

	resolveGenISOImage = func() (string, error) { return "", errors.New("untrusted") }
	if _, err := BuildProviderPlan(ProfileISO9660JolietUDF, "TEST"); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("resolver error = %v", err)
	}

	resolveGenISOImage = func() (string, error) { return "  ", nil }
	if _, err := BuildProviderPlan(ProfileISO9660JolietUDF, "TEST"); err == nil || !strings.Contains(err.Error(), "empty path") {
		t.Fatalf("empty resolver error = %v", err)
	}
}
