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
	LoadDrivers          bool
	QualityOfLife        bool
	ApplySkuSiPolicy     bool
	SilentInstall        bool
	InstallImageIndex    int
	BootLanguage         string
	Locale               string
	TimeZone             string
}

func (o Options) Enabled() bool {
	return o.BypassHardwareChecks || o.BypassOnlineAccount || strings.TrimSpace(o.LocalAccount) != "" || o.ReduceDataCollection || o.DisableBitLocker || o.LoadDrivers || o.QualityOfLife || o.ApplySkuSiPolicy || o.SilentInstall || strings.TrimSpace(o.Locale) != "" || strings.TrimSpace(o.TimeZone) != ""
}

var validLocale = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$`)
var validTimeZone = regexp.MustCompile(`^[A-Za-z0-9 _+().-]{1,64}$`)

// reservedUsers mirrors Rufus's localized built-in account-name guard.
// Windows Setup must not be asked to create an account that collides with a
// localized Administrator account or another reserved system account.
var reservedUsers = []string{
	"Administrator",
	"Järjestelmänvalvoja",
	"Administrateur",
	"Rendszergazda",
	"Administrador",
	"Администратор",
	"Administratör",
	"Guest",
	"DefaultAccount",
	"WDAGUtilityAccount",
	"HelpAssistant",
	"KRBTGT",
	"Local",
	"NONE",
	"SYSTEM",
}

func isReservedWindowsUsername(value string) bool {
	for _, reserved := range reservedUsers {
		if strings.EqualFold(value, reserved) {
			return true
		}
	}
	return false
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
		if isReservedWindowsUsername(username) {
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
	bootLanguage := strings.TrimSpace(o.BootLanguage)
	if bootLanguage != "" && !validLocale.MatchString(bootLanguage) {
		return fmt.Errorf("invalid Windows Setup boot language %q", bootLanguage)
	}
	if o.SilentInstall {
		if username == "" || !o.ReduceDataCollection || locale == "" || timeZone == "" {
			return errors.New("silent installation requires a local account, reduced data collection, locale, and time zone")
		}
		if o.InstallImageIndex <= 0 || o.InstallImageIndex > 256 {
			return errors.New("silent installation requires an exact Windows image index from 1 to 256")
		}
	}
	return nil
}

// Generate creates an autounattend.xml for a supported Windows installation ISO.
// It uses only documented unattend sections plus the same LabConfig values used
// by common Windows installation media tools. Every behavior is opt-in.
func Generate(architecture string, o Options) ([]byte, error) {
	if !o.Enabled() {
		return nil, nil
	}
	if err := Validate(o); err != nil {
		return nil, err
	}
	if o.SilentInstall && strings.TrimSpace(o.BootLanguage) == "" {
		return nil, errors.New("silent installation requires a boot.wim language bound by media analysis")
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
	setupComponent := o.BypassHardwareChecks || o.DisableBitLocker || o.LoadDrivers || o.SilentInstall
	if setupComponent || locale != "" {
		b.WriteString("  <settings pass=\"windowsPE\">\n")
		if setupComponent {
			fmt.Fprintf(&b, "    <component name=\"Microsoft-Windows-Setup\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n", arch)
			if o.SilentInstall {
				writeSilentInstallSetup(&b, o)
			} else if o.DisableBitLocker {
				b.WriteString("      <DisableEncryptedDiskProvisioning>true</DisableEncryptedDiskProvisioning>\n")
			}
			if o.BypassHardwareChecks || o.LoadDrivers {
				b.WriteString("      <RunSynchronous>\n")
				order := 1
				if o.BypassHardwareChecks {
					values := []string{"BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck"}
					for _, value := range values {
						fmt.Fprintf(&b, "        <RunSynchronousCommand wcm:action=\"add\"><Order>%d</Order><Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v %s /t REG_DWORD /d 1 /f</Path><Description>Configure Windows hardware checks</Description></RunSynchronousCommand>\n", order, value)
						order++
					}
				}
				if o.LoadDrivers {
					command := `cmd.exe /c for %D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do @if exist %D:\RUFUSARM64.DRV for /R %D:\drivers %I in (*.inf) do @drvload "%I"`
					fmt.Fprintf(&b, "        <RunSynchronousCommand wcm:action=\"add\"><Order>%d</Order><Path>%s</Path><Description>Load storage and device drivers from the USB</Description></RunSynchronousCommand>\n", order, escapeText(command))
				}
				b.WriteString("      </RunSynchronous>\n")
			}
			b.WriteString("    </component>\n")
		}
		if locale != "" {
			fmt.Fprintf(&b, "    <component name=\"Microsoft-Windows-International-Core-WinPE\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n", arch)
			fmt.Fprintf(&b, "      <InputLocale>%s</InputLocale>\n      <SystemLocale>%s</SystemLocale>\n      <UserLocale>%s</UserLocale>\n", escapeText(locale), escapeText(locale), escapeText(locale))
			if o.SilentInstall {
				fmt.Fprintf(&b, "      <UILanguage>%s</UILanguage>\n", escapeText(strings.TrimSpace(o.BootLanguage)))
			}
			b.WriteString("    </component>\n")
		}
		b.WriteString("  </settings>\n")
	}

	if o.BypassOnlineAccount || o.ReduceDataCollection || o.DisableBitLocker || o.QualityOfLife {
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
		if o.QualityOfLife {
			commands = append(commands, qualityOfLifeSpecializeCommands()...)
		}
		for _, command := range commands {
			fmt.Fprintf(&b, "        <RunSynchronousCommand wcm:action=\"add\"><Order>%d</Order><Path>%s</Path></RunSynchronousCommand>\n", order, escapeText(command))
			order++
		}
		b.WriteString("      </RunSynchronous>\n    </component>\n  </settings>\n")
	}

	shellComponent := o.BypassOnlineAccount || o.ReduceDataCollection || strings.TrimSpace(o.LocalAccount) != "" || o.QualityOfLife || o.ApplySkuSiPolicy || o.SilentInstall || timeZone != ""
	if shellComponent || locale != "" {
		b.WriteString("  <settings pass=\"oobeSystem\">\n")
		if shellComponent {
			fmt.Fprintf(&b, "    <component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"%s\" language=\"neutral\" publicKeyToken=\"31bf3856ad364e35\" versionScope=\"nonSxS\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n", arch)
			if o.BypassOnlineAccount || o.ReduceDataCollection || o.SilentInstall {
				b.WriteString("      <OOBE>\n")
				if o.SilentInstall {
					b.WriteString("        <HideEULAPage>true</HideEULAPage>\n")
				}
				if o.BypassOnlineAccount || o.SilentInstall {
					b.WriteString("        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n")
				}
				if o.ReduceDataCollection || o.SilentInstall {
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
			}
			if username != "" || o.QualityOfLife || o.ApplySkuSiPolicy {
				b.WriteString("      <FirstLogonCommands>\n")
				order := 1
				if username != "" {
					escaped := escapeText(username)
					fmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\"add\"><Order>%d</Order><CommandLine>net user &quot;%s&quot; /logonpasswordchg:yes</CommandLine></SynchronousCommand>\n", order, escaped)
					order++
					fmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\"add\"><Order>%d</Order><CommandLine>net accounts /maxpwage:unlimited</CommandLine></SynchronousCommand>\n", order)
					order++
				}
				if o.ApplySkuSiPolicy {
					// Use the installed system's own policy, matching Rufus's safety
					// boundary. Delayed expansion preserves the copy result while the
					// ESP is unmounted even when copying fails.
					command := `cmd.exe /V:ON /C "mountvol S: /S && (copy /Y %WINDIR%\System32\SecureBootUpdates\SkuSiPolicy.p7b S:\EFI\Microsoft\Boot\SkuSiPolicy.p7b & set rc=!ERRORLEVEL! & mountvol S: /D & exit /B !rc!)"`
					fmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\"add\"><Order>%d</Order><CommandLine>%s</CommandLine><Description>Apply the installed Windows SkuSiPolicy to the EFI System Partition</Description></SynchronousCommand>\n", order, escapeText(command))
					order++
				}
				if o.QualityOfLife {
					for _, command := range qualityOfLifeFirstLogonCommands() {
						fmt.Fprintf(&b, "        <SynchronousCommand wcm:action=\"add\"><Order>%d</Order><CommandLine>%s</CommandLine></SynchronousCommand>\n", order, escapeText(command))
						order++
					}
				}
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

func writeSilentInstallSetup(b *bytes.Buffer, o Options) {
	b.WriteString("      <UserData>\n        <AcceptEula>true</AcceptEula>\n        <ProductKey><Key /></ProductKey>\n      </UserData>\n")
	b.WriteString("      <DiskConfiguration>\n        <WillShowUI>OnError</WillShowUI>\n")
	if o.DisableBitLocker {
		b.WriteString("        <DisableEncryptedDiskProvisioning>true</DisableEncryptedDiskProvisioning>\n")
	}
	// The verified NTFS USB is expected to be Disk 1 with UEFI:NTFS as
	// partition 2. A different disk order, missing partition, or additional
	// ambiguous disk is intended to make this modification fail and expose
	// Setup's disk UI; users must still disconnect every other storage device.
	b.WriteString(`        <Disk wcm:action="modify">
          <DiskID>1</DiskID>
          <ModifyPartitions>
            <ModifyPartition wcm:action="modify">
              <Order>1</Order>
              <PartitionID>2</PartitionID>
              <Label>RUFUS_BOOT</Label>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
`)
	b.WriteString(`        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Label>EFI</Label><Format>FAT32</Format></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Label>Windows</Label><Letter>C</Letter><Format>NTFS</Format></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
`)
	fmt.Fprintf(b, `      <ImageInstall>
        <OSImage>
          <WillShowUI>OnError</WillShowUI>
          <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>%d</Value></MetaData></InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>
`, o.InstallImageIndex)
}

func normalizeArchitecture(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "arm64"):
		return "arm64"
	case strings.Contains(lower, "x86-64"), strings.Contains(lower, "amd64"), strings.Contains(lower, "x64"):
		return "amd64"
	case strings.Contains(lower, "x86"), strings.Contains(lower, "i386"), strings.Contains(lower, "i686"):
		return "x86"
	default:
		return ""
	}
}

func escapeText(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}
