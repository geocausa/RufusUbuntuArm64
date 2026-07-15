package windowsconfig

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Options describes optional, explicit changes to Windows Setup. A zero value
// produces no answer file and leaves the installation media unchanged.
type Options struct {
	BypassHardwareChecks bool
	BypassOnlineAccount  bool
	LocalAccount         string
	ReduceDataCollection bool
	DisableBitLocker     bool
	Locale               string
	TimeZone             string
}

func (o Options) Enabled() bool {
	return o.BypassHardwareChecks || o.BypassOnlineAccount || strings.TrimSpace(o.LocalAccount) != "" || o.ReduceDataCollection || o.DisableBitLocker || strings.TrimSpace(o.Locale) != "" || strings.TrimSpace(o.TimeZone) != ""
}

var validLocale = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$`)
var validTimeZone = regexp.MustCompile(`^[A-Za-z0-9 _+().-]{1,64}$`)

var reservedUsers = map[string]struct{}{
	"administrator": {}, "guest": {}, "defaultaccount": {}, "wdagutilityaccount": {},
	"helpassistant": {}, "krbtgt": {}, "local": {}, "none": {}, "system": {},
}

func Validate(o Options) error {
	rawUsername := o.LocalAccount
	username := strings.TrimSpace(rawUsername)
	if username != "" {
		if rawUsername != username || utf8.RuneCountInString(username) > 20 || strings.HasSuffix(username, ".") {
			return errors.New("local account name must be 1–20 characters with no leading/trailing spaces or final period")
		}
		for _, char := range username {
			if unicode.IsLetter(char) || unicode.IsNumber(char) || strings.ContainsRune(" ._-'", char) {
				continue
			}
			return errors.New("local account name may contain only letters, numbers, spaces, periods, underscores, hyphens, and apostrophes")
		}
		if _, reserved := reservedUsers[strings.ToLower(username)]; reserved {
			return fmt.Errorf("%q is a reserved Windows account name", username)
		}
	}
	locale := strings.TrimSpace(o.Locale)
	if locale != "" && !validLocale.MatchString(locale) {
		return fmt.Errorf("invalid Windows regional locale %q", locale)
	}
	timeZone := strings.TrimSpace(o.TimeZone)
	if timeZone != "" && !validTimeZone.MatchString(timeZone) {
		return fmt.Errorf("invalid Windows time-zone name %q", timeZone)
	}
	return nil
}

// Generate creates an autounattend.xml for a Windows ARM64 installation ISO.
// It uses only documented unattend sections plus the same LabConfig values used
// by common Windows installation media tools. Every behavior is opt-in.
func Generate(architecture string, o Options) ([]byte, error) {
	if !o.Enabled() {
		return nil, nil
	}
	if err := Validate(o); err != nil {
		return nil, err
	}
	arch := normalizeArchitecture(architecture)
	if arch == "" {
		return nil, fmt.Errorf("unsupported Windows architecture %q", architecture)
	}

	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	b.WriteString("<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">\n")

	locale := strings.TrimSpace(o.Locale)
	timeZone := strings.TrimSpace(o.TimeZone)
	setupComponent := o.BypassHardwareChecks || o.DisableBitLocker
	if setupComponent || locale != "" {
		b.WriteString("  <settings pass=\"windowsPE\">\n")
		if setupComponent {
			fmt.Fprintf(&b, "    <component name=\"Microsoft-Windows-Setup\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n", arch)
			if o.DisableBitLocker {
				b.WriteString("      <DisableEncryptedDiskProvisioning>true</DisableEncryptedDiskProvisioning>\n")
			}
			if o.BypassHardwareChecks {
				b.WriteString("      <RunSynchronous>\n")
				values := []string{"BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck"}
				for i, value := range values {
					fmt.Fprintf(&b, "        <RunSynchronousCommand wcm:action=\"add\"><Order>%d</Order><Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v %s /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>\n", i+1, value)
				}
				b.WriteString("      </RunSynchronous>\n")
			}
			b.WriteString("    </component>\n")
		}
		if locale != "" {
			fmt.Fprintf(&b, "    <component name=\"Microsoft-Windows-International-Core-WinPE\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n", arch)
			fmt.Fprintf(&b, "      <InputLocale>%s</InputLocale>\n      <SystemLocale>%s</SystemLocale>\n      <UserLocale>%s</UserLocale>\n", escapeText(locale), escapeText(locale), escapeText(locale))
			b.WriteString("    </component>\n")
		}
		b.WriteString("  </settings>\n")
	}

	if o.BypassOnlineAccount || o.ReduceDataCollection || o.DisableBitLocker {
		fmt.Fprintf(&b, "  <settings pass=\"specialize\">\n    <component name=\"Microsoft-Windows-Deployment\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n      <RunSynchronous>\n", arch)
		order := 1
		commands := []string{}
		if o.BypassOnlineAccount {
			commands = append(commands, `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f`)
		}
		if o.ReduceDataCollection {
			commands = append(commands,
				`reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f`,
				`reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f`,
				`reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f`,
			)
		}
		if o.DisableBitLocker {
			commands = append(commands, `reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v PreventDeviceEncryption /t REG_DWORD /d 1 /f`)
		}
		for _, command := range commands {
			fmt.Fprintf(&b, "        <RunSynchronousCommand wcm:action=\"add\"><Order>%d</Order><Path>%s</Path></RunSynchronousCommand>\n", order, escapeText(command))
			order++
		}
		b.WriteString("      </RunSynchronous>\n    </component>\n  </settings>\n")
	}

	shellComponent := o.BypassOnlineAccount || o.ReduceDataCollection || strings.TrimSpace(o.LocalAccount) != "" || timeZone != ""
	if shellComponent || locale != "" {
		b.WriteString("  <settings pass=\"oobeSystem\">\n")
		if shellComponent {
			fmt.Fprintf(&b, "    <component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n", arch)
			if o.BypassOnlineAccount || o.ReduceDataCollection {
				b.WriteString("      <OOBE>\n")
				if o.BypassOnlineAccount {
					b.WriteString("        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n")
				}
				if o.ReduceDataCollection {
					b.WriteString("        <ProtectYourPC>3</ProtectYourPC>\n")
				}
				b.WriteString("      </OOBE>\n")
			}
			if timeZone != "" {
				fmt.Fprintf(&b, "      <TimeZone>%s</TimeZone>\n", escapeText(timeZone))
			}
			username := strings.TrimSpace(o.LocalAccount)
			if username != "" {
				escaped := escapeText(username)
				b.WriteString("      <UserAccounts>\n        <LocalAccounts>\n          <LocalAccount wcm:action=\"add\">\n")
				fmt.Fprintf(&b, "            <Name>%s</Name>\n            <DisplayName>%s</DisplayName>\n", escaped, escaped)
				b.WriteString("            <Group>Administrators</Group>\n            <Password><Value>UABhAHMAcwB3AG8AcgBkAA==</Value><PlainText>false</PlainText></Password>\n")
				b.WriteString("          </LocalAccount>\n        </LocalAccounts>\n      </UserAccounts>\n")
				b.WriteString("      <FirstLogonCommands>\n")
				fmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\"add\"><Order>1</Order><Description>Require a password change</Description><CommandLine>net user &quot;%s&quot; /logonpasswordchg:yes</CommandLine></SynchronousCommand>\n", escaped)
				b.WriteString("        <SynchronousCommand wcm:action=\"add\"><Order>2</Order><Description>Disable password expiry</Description><CommandLine>net accounts /maxpwage:unlimited</CommandLine></SynchronousCommand>\n")
				b.WriteString("      </FirstLogonCommands>\n")
			}
			b.WriteString("    </component>\n")
		}
		if locale != "" {
			fmt.Fprintf(&b, "    <component name=\"Microsoft-Windows-International-Core\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n", arch)
			fmt.Fprintf(&b, "      <InputLocale>%s</InputLocale>\n      <SystemLocale>%s</SystemLocale>\n      <UserLocale>%s</UserLocale>\n", escapeText(locale), escapeText(locale), escapeText(locale))
			b.WriteString("    </component>\n")
		}
		b.WriteString("  </settings>\n")
	}

	b.WriteString("</unattend>\n")
	output := b.Bytes()
	decoder := xml.NewDecoder(bytes.NewReader(output))
	for {
		if _, err := decoder.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("generated invalid answer file: %w", err)
		}
	}
	return output, nil
}

func normalizeArchitecture(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "arm64"):
		return "arm64"
	case strings.Contains(lower, "x86-64"), strings.Contains(lower, "amd64"), strings.Contains(lower, "x64"):
		return "amd64"
	default:
		return ""
	}
}

func escapeText(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}
