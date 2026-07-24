package windowsconfig

// These commands adapt Rufus 4.15's opt-in Windows User Experience "Quality
// of Life" policy from pbatard/rufus commit
// 6d8fbf98305ff37eb531c45cbd6ff44563c53917. They are data only: Generate
// XML-escapes them before placing them into autounattend.xml.
func qualityOfLifeSpecializeCommands() []string {
	return []string{
		`reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f`,
		`PowerShell -NoProfile -NonInteractive -WindowStyle Hidden -Command "Get-Item -Path $env:SystemRoot\System32\OneDriveSetup.exe,$env:SystemRoot\SysWOW64\OneDriveSetup.exe -ErrorAction SilentlyContinue | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue"`,
		`PowerShell -NoProfile -NonInteractive -WindowStyle Hidden -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like '*Outlook*'} | Remove-AppxProvisionedPackage -Online"`,
		`PowerShell -NoProfile -NonInteractive -WindowStyle Hidden -Command "Get-AppxPackage -AllUsers *Outlook* | Remove-AppxPackage -AllUsers"`,
		`PowerShell -NoProfile -NonInteractive -WindowStyle Hidden -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like '*Teams*'} | Remove-AppxProvisionedPackage -Online"`,
		`PowerShell -NoProfile -NonInteractive -WindowStyle Hidden -Command "Get-AppxPackage -AllUsers *Teams* | Remove-AppxPackage -AllUsers"`,
	}
}

const upstreamVisiblePlacesBase64 = "ztU0LVr6Q0WC8iLm6vd3PC+zZ+PeiVVDv85h83sYqTe8JIoUDNaJQqCAbtm7okiCRIF1/g0IrkKL2jTtl7ZjlEqwvXRK+WhPi9ZDmAcdqLyGCHNSqlFDQp97J3ZYRlnU"

func qualityOfLifeFirstLogonCommands() []string {
	return []string{
		`reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f`,
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f`,
		`reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f`,
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f`,
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarModeCache /t REG_DWORD /d 1 /f`,
		`reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f`,
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f`,
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f`,
		`reg add "HKLM\Software\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f`,
		`reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f`,
		`reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f`,
		`reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /t REG_DWORD /d 1 /f`,
		`reg add "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f`,
		`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Layout /t REG_DWORD /d 1 /f`,
		`PowerShell -NoProfile -NonInteractive -WindowStyle Hidden -Command "Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start' -Name 'VisiblePlaces' -Value $([convert]::FromBase64String('` + upstreamVisiblePlacesBase64 + `')) -Type 'Binary'"`,
	}
}
