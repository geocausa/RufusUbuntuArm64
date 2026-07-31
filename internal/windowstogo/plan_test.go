//go:build linux

package windowstogo

import (
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const lexarCapacity = uint64(31_379_685_376)

func baseRequest() Request {
	return Request{
		TargetPath:        "/dev/sdb",
		ExpectedIdentity:  strings.Repeat("a", 64),
		TargetSizeBytes:   lexarCapacity,
		LogicalSectorSize: 512,
		ImageIndex:        3,
		Metadata: windowsconfig.MediaMetadata{
			ProductName:      "Windows 11 Pro",
			Version:          "10.0.26200",
			Architecture:     "arm64",
			InstallationType: "Client",
			ImageCount:       3,
			Images: []windowsconfig.WindowsImage{
				{Index: 1, Name: "Windows 11 Home", DefaultLanguage: "en-GB", TotalBytes: 25_000_000_000},
				{Index: 2, Name: "Windows 11 Education", DefaultLanguage: "en-GB", TotalBytes: 26_000_000_000},
				{Index: 3, Name: "Windows 11 Pro", DefaultLanguage: "en-GB", TotalBytes: 26_511_788_309},
			},
		},
	}
}

func TestBuildPlanAdmitsBoundedARM64Windows11Media(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != 1 || plan.Mode != Mode || !plan.Experimental || plan.BootableClaim {
		t.Fatalf("unexpected envelope: %#v", plan)
	}
	if plan.Image.Index != 3 || plan.Image.Name != "Windows 11 Pro" || plan.Image.TotalBytes != 26_511_788_309 {
		t.Fatalf("selected image=%#v", plan.Image)
	}
	if plan.ESP.StartBytes != 1024*1024 || plan.ESP.SizeBytes != 260*1024*1024 || plan.ESP.TypeGUID != efiSystemPartitionGUID {
		t.Fatalf("ESP=%#v", plan.ESP)
	}
	if plan.OS.StartBytes%alignmentBytes != 0 || plan.OS.Attributes != noDefaultDriveLetter || plan.OS.TypeGUID != basicDataPartitionGUID {
		t.Fatalf("OS=%#v", plan.OS)
	}
	if plan.OS.SizeBytes < plan.Image.TotalBytes+minimumFreeBytes {
		t.Fatalf("OS size=%d image=%d free=%d", plan.OS.SizeBytes, plan.Image.TotalBytes, minimumFreeBytes)
	}
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
}

func TestBuildPlanSupportsFourKilobyteLogicalSectors(t *testing.T) {
	request := baseRequest()
	request.LogicalSectorSize = 4096
	plan, err := BuildPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]uint64{
		"esp start": plan.ESP.StartBytes, "esp size": plan.ESP.SizeBytes,
		"os start": plan.OS.StartBytes, "os size": plan.OS.SizeBytes,
	} {
		if value%4096 != 0 {
			t.Fatalf("%s=%d is not 4 KiB aligned", name, value)
		}
	}
}

func TestBuildPlanRejectsUnqualifiedOrUnsafeRequests(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		want   string
	}{
		{name: "relative target", mutate: func(r *Request) { r.TargetPath = "dev/sdb" }, want: "beneath /dev"},
		{name: "missing identity", mutate: func(r *Request) { r.ExpectedIdentity = "" }, want: "identity"},
		{name: "sector size", mutate: func(r *Request) { r.LogicalSectorSize = 2048 }, want: "512 or 4096"},
		{name: "small target", mutate: func(r *Request) { r.TargetSizeBytes = minimumTargetBytes - 1 }, want: "32 GB-class"},
		{name: "Windows 10", mutate: func(r *Request) { r.Metadata.ProductName = "Windows 10 Pro"; r.Metadata.Version = "10.0.19045" }, want: "Windows 11"},
		{name: "server", mutate: func(r *Request) { r.Metadata.InstallationType = "Server" }, want: "Windows 11 client"},
		{name: "x64", mutate: func(r *Request) { r.Metadata.Architecture = "x64" }, want: "ARM64"},
		{name: "incomplete set", mutate: func(r *Request) { r.Metadata.ImageCount = 4 }, want: "complete exact"},
		{name: "missing index", mutate: func(r *Request) { r.ImageIndex = 9 }, want: "not present"},
		{name: "missing size", mutate: func(r *Request) { r.Metadata.Images[2].TotalBytes = 0 }, want: "expanded size"},
		{name: "missing language", mutate: func(r *Request) { r.Metadata.Images[2].DefaultLanguage = "" }, want: "default language"},
		{name: "insufficient headroom", mutate: func(r *Request) { r.Metadata.Images[2].TotalBytes = 30_000_000_000 }, want: "headroom"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := baseRequest()
			request.Metadata.Images = append([]windowsconfig.WindowsImage(nil), request.Metadata.Images...)
			test.mutate(&request)
			_, err := BuildPlan(request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestValidatePlanRejectsTampering(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Plan){
		"boot claim":       func(p *Plan) { p.BootableClaim = true },
		"scheme":           func(p *Plan) { p.PartitionScheme = "mbr" },
		"ESP type":         func(p *Plan) { p.ESP.TypeGUID = basicDataPartitionGUID },
		"OS attributes":    func(p *Plan) { p.OS.Attributes = 0 },
		"overlap":          func(p *Plan) { p.OS.StartBytes = p.ESP.StartBytes },
		"capacity":         func(p *Plan) { p.OS.SizeBytes = p.Image.TotalBytes },
		"missing image":    func(p *Plan) { p.Image.Index = 0 },
		"wrong filesystem": func(p *Plan) { p.OS.Filesystem = "fat32" },
		"ESP label":        func(p *Plan) { p.ESP.Label = "SYSTEM" },
		"ESP GPT name":     func(p *Plan) { p.ESP.GPTName = "SYSTEM" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := plan
			mutate(&copy)
			if err := ValidatePlan(copy); err == nil {
				t.Fatal("tampered plan was accepted")
			}
		})
	}
}
