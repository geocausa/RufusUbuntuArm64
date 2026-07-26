package drivebackup

import "testing"

func TestParseFormat(t *testing.T) {
	for _, test := range []struct {
		input string
		want  Format
	}{
		{"", FormatRaw},
		{" raw ", FormatRaw},
		{"VHD", FormatVHD},
		{"vhdx", FormatVHDX},
	} {
		got, err := ParseFormat(test.input)
		if err != nil {
			t.Fatalf("ParseFormat(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("ParseFormat(%q)=%q want %q", test.input, got, test.want)
		}
	}
	for _, input := range []string{"qcow2", "vpc", "fixed", "vhd,backing=x"} {
		if _, err := ParseFormat(input); err == nil {
			t.Fatalf("ParseFormat(%q) succeeded", input)
		}
	}
}

func TestContainerFormatQEMUContract(t *testing.T) {
	for _, test := range []struct {
		format  Format
		qemu    string
		options string
		ext     string
	}{
		{FormatVHD, "vpc", "subformat=dynamic,force_size=on", ".vhd"},
		{FormatVHDX, "vhdx", "subformat=dynamic,block_state_zero=on", ".vhdx"},
	} {
		if !test.format.Valid() || !test.format.Container() {
			t.Fatalf("format %q is not a valid container", test.format)
		}
		qemu, err := test.format.QEMUFormat()
		if err != nil || qemu != test.qemu {
			t.Fatalf("QEMUFormat(%q)=%q,%v want %q", test.format, qemu, err, test.qemu)
		}
		options, err := test.format.QEMUOptions()
		if err != nil || options != test.options {
			t.Fatalf("QEMUOptions(%q)=%q,%v want %q", test.format, options, err, test.options)
		}
		if got := test.format.Extension(); got != test.ext {
			t.Fatalf("Extension(%q)=%q want %q", test.format, got, test.ext)
		}
	}
	if FormatRaw.Container() {
		t.Fatal("raw format was classified as a container")
	}
	if _, err := FormatRaw.QEMUFormat(); err == nil {
		t.Fatal("raw format unexpectedly has a QEMU format")
	}
	if _, err := FormatRaw.QEMUOptions(); err == nil {
		t.Fatal("raw format unexpectedly has QEMU options")
	}
}
