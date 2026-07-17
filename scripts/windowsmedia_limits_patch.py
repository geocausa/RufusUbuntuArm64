#!/usr/bin/env python3
"""Apply the reviewed Windows-media traversal and arithmetic hardening."""

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "internal/windowsmedia/windowsmedia.go"
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"expected Windows-media source block not found: {old[:100]!r}")
    text = text.replace(old, new, 1)


def replace_function(start: str, end: str, replacement: str) -> None:
    global text
    first = text.find(start)
    if first < 0:
        if replacement in text:
            return
        raise SystemExit(f"function start not found: {start}")
    last = text.find(end, first)
    if last < 0:
        raise SystemExit(f"function end not found after {start}: {end}")
    text = text[:first] + replacement + "\n\n" + text[last:]


replace_once(
    "\tfinalizePlan(&plan)\n\n\tvar ntfsFormatter string",
    "\tif err := finalizePlan(&plan); err != nil {\n\t\treturn fmt.Errorf(\"calculate Windows media capacity: %w\", err)\n\t}\n\n\tvar ntfsFormatter string",
)
replace_once(
    "\t\tif err := ensureAvailableSpace(splitDir, plan.InstallSize+temporaryMargin); err != nil {\n\t\t\treturn err\n\t\t}",
    "\t\trequiredTemporarySpace, err := checkedAdd(\"temporary split-image space\", plan.InstallSize, temporaryMargin)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := ensureAvailableSpace(splitDir, requiredTemporarySpace); err != nil {\n\t\t\treturn err\n\t\t}",
)
replace_once(
    "\t\tfinalizePlan(&plan)\n\t\tif opts.TargetSize < plan.RequiredBytes {",
    "\t\tif err := finalizePlan(&plan); err != nil {\n\t\t\treturn fmt.Errorf(\"calculate split Windows media capacity: %w\", err)\n\t\t}\n\t\tif opts.TargetSize < plan.RequiredBytes {",
)

replace_function(
    "func inspectMountedISO(root string) (mediaPlan, error) {",
    "// validateFATCompatibility performs",
    r'''func inspectMountedISO(root string) (mediaPlan, error) {
	if _, ok := findRelativeCaseInsensitive(root, "sources/boot.wim"); !ok {
		return mediaPlan{}, errors.New("this is not a supported Windows installation ISO: sources/boot.wim was not found")
	}

	_, arm64 := findRelativeCaseInsensitive(root, "efi/boot/bootaa64.efi")
	_, x64 := findRelativeCaseInsensitive(root, "efi/boot/bootx64.efi")
	_, x86 := findRelativeCaseInsensitive(root, "efi/boot/bootia32.efi")
	_, bootmgr := findRelativeCaseInsensitive(root, "bootmgr")
	architecture := "UEFI"
	switch {
	case arm64 && x64:
		architecture = "ARM64/x86-64 UEFI"
	case arm64:
		architecture = "ARM64 UEFI"
	case x64:
		architecture = "x86-64 UEFI"
	case x86:
		architecture = "x86 UEFI"
	default:
		return mediaPlan{}, errors.New("the ISO has no standard ARM64 or x86-64 UEFI boot file")
	}

	installWIM, hasWIM := findRelativeCaseInsensitive(root, "sources/install.wim")
	installESD, hasESD := findRelativeCaseInsensitive(root, "sources/install.esd")
	existingSplitFiles, err := findExistingSplitFiles(root)
	if err != nil {
		return mediaPlan{}, err
	}
	payloadKinds := 0
	if hasWIM {
		payloadKinds++
	}
	if hasESD {
		payloadKinds++
	}
	if len(existingSplitFiles) > 0 {
		payloadKinds++
	}
	if payloadKinds == 0 {
		return mediaPlan{}, errors.New("this Windows ISO has no sources/install.wim, sources/install.esd, or split install.swm payload")
	}
	if payloadKinds > 1 {
		return mediaPlan{}, errors.New("this Windows ISO contains conflicting installation payloads (WIM, ESD, or SWM)")
	}
	installPath := installWIM
	if hasESD {
		installPath = installESD
	}
	hasInstall := hasWIM || hasESD
	plan := mediaPlan{
		InstallPath:        installPath,
		ExistingSplitFiles: existingSplitFiles,
		Architecture:       architecture,
		HasARM64:           arm64,
		HasX64:             x64,
		HasX86:             x86,
		HasBootmgr:         bootmgr,
	}
	if answerPath, ok := findRelativeCaseInsensitive(root, "autounattend.xml"); ok {
		plan.ExistingAnswerPath = answerPath
		if info, statErr := os.Stat(answerPath); statErr == nil {
			plan.ExistingAnswerSize = uint64(info.Size())
		}
	}
	if hasInstall {
		rel, err := filepath.Rel(root, installPath)
		if err != nil {
			return mediaPlan{}, err
		}
		plan.InstallRelative = filepath.Clean(rel)
		info, err := os.Stat(installPath)
		if err != nil {
			return mediaPlan{}, fmt.Errorf("read Windows installation image: %w", err)
		}
		plan.InstallSize = uint64(info.Size())
	}

	entryCount := 0
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := countBoundedEntry(&entryCount, maxWindowsMediaEntries, "Windows ISO"); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsupported symbolic link in ISO: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular file in ISO: %s", path)
		}
		if !samePath(path, plan.InstallPath) {
			plan.OtherBytes, err = checkedAdd("Windows ISO file total", plan.OtherBytes, uint64(info.Size()))
			if err != nil {
				return err
			}
		}
		return nil
	})
	if walkErr != nil {
		return mediaPlan{}, walkErr
	}
	// Default sizing keeps the inspector useful in tests and callers that only
	// need a conservative plan. Create resolves the requested filesystem and
	// recalculates these values before any destructive operation.
	plan.Filesystem = "fat32"
	plan.NeedsSplit = plan.InstallSize > fat32MaxFileSize
	if err := finalizePlan(&plan); err != nil {
		return mediaPlan{}, err
	}
	return plan, nil
}''',
)

replace_function(
    "func validateFATCompatibility(root string, plan mediaPlan) error {",
    "func inspectDriverFolder(root string, filesystem string) (uint64, error) {",
    r'''func validateFATCompatibility(root string, plan mediaPlan) error {
	seenFATPaths := make(map[string]string)
	entryCount := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := countBoundedEntry(&entryCount, maxWindowsMediaEntries, "Windows ISO"); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative != "." {
			if err := validateFATRelativePath(relative); err != nil {
				return err
			}
			key := strings.ToLower(filepath.ToSlash(relative))
			if previous, exists := seenFATPaths[key]; exists {
				return fmt.Errorf("the ISO contains names that collide on FAT32: %s and %s", filepath.ToSlash(previous), filepath.ToSlash(relative))
			}
			seenFATPaths[key] = relative
		}
		if entry.IsDir() || samePath(path, plan.InstallPath) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if uint64(info.Size()) > fat32MaxFileSize {
			return fmt.Errorf("the ISO contains another file too large for FAT32: %s (%s); choose NTFS", filepath.ToSlash(relative), humanBytes(uint64(info.Size())))
		}
		return nil
	})
}''',
)

replace_function(
    "func inspectDriverFolder(root string, filesystem string) (uint64, error) {",
    "func finalizePlan(plan *mediaPlan)",
    r'''func inspectDriverFolder(root string, filesystem string) (uint64, error) {
	if strings.TrimSpace(root) == "" {
		return 0, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return 0, fmt.Errorf("open Windows driver folder: %w", err)
	}
	if !info.IsDir() {
		return 0, errors.New("the Windows driver path is not a directory")
	}
	var total uint64
	entryCount := 0
	hasINF := false
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := countBoundedEntry(&entryCount, maxDriverFolderEntries, "Windows driver folder"); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("driver folder contains a symbolic link: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative != "." && filesystem == "fat32" {
			if err := validateFATRelativePath(filepath.Join("drivers", relative)); err != nil {
				return err
			}
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("driver folder contains a non-regular file: %s", path)
		}
		if filesystem == "fat32" && uint64(fileInfo.Size()) > fat32MaxFileSize {
			return fmt.Errorf("driver file is too large for FAT32: %s", path)
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".inf") {
			hasINF = true
		}
		total, err = checkedAdd("Windows driver folder total", total, uint64(fileInfo.Size()))
		return err
	})
	if err != nil {
		return 0, err
	}
	if !hasINF {
		return 0, errors.New("the selected driver folder contains no .inf driver files")
	}
	return total, nil
}''',
)

replace_function(
    "func finalizePlan(plan *mediaPlan)",
    "func prepareSplitImage(ctx context.Context",
    r'''func finalizePlan(plan *mediaPlan) error {
	if plan == nil {
		return errors.New("Windows media plan is nil")
	}
	installOutput := plan.InstallSize
	if plan.NeedsSplit && plan.SplitBytes > 0 {
		installOutput = plan.SplitBytes
	}
	otherBytes := plan.OtherBytes
	if len(plan.AnswerFile) > 0 {
		if plan.ExistingAnswerSize > otherBytes {
			return errors.New("existing Windows answer file size exceeds the inspected media total")
		}
		otherBytes -= plan.ExistingAnswerSize
		var err error
		otherBytes, err = checkedAdd("Windows answer-file replacement total", otherBytes, uint64(len(plan.AnswerFile)))
		if err != nil {
			return err
		}
	}
	copyBytes, err := checkedAdd("Windows media copy size", otherBytes, installOutput, plan.DriverBytes)
	if err != nil {
		return err
	}
	if plan.DriverFolder != "" {
		copyBytes, err = checkedAdd("Windows media copy size", copyBytes, uint64(len(rufusDriverMarker)))
		if err != nil {
			return err
		}
	}
	plan.CopyBytes = copyBytes
	marginDivisor := uint64(10)
	if plan.Filesystem == "ntfs" {
		marginDivisor = 20
	}
	margin := plan.CopyBytes / marginDivisor
	if margin < minimumFreeMargin {
		margin = minimumFreeMargin
	}
	reserve := uint64(2 * 1024 * 1024)
	if plan.Filesystem == "ntfs" {
		reserve += oneMiB
	}
	plan.RequiredBytes, err = checkedAdd("required Windows USB capacity", plan.CopyBytes, margin, reserve)
	return err
}''',
)

replace_function(
    "func ensureAvailableSpace(path string, required uint64) error {",
    "func validateSplitParts(parts []string)",
    r'''func ensureAvailableSpace(path string, required uint64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("check temporary free space: %w", err)
	}
	available, err := checkedMultiply("temporary filesystem free space", uint64(stat.Bavail), uint64(stat.Bsize))
	if err != nil {
		return err
	}
	if available < required {
		return fmt.Errorf("not enough temporary disk space to prepare the Windows image safely: need %s, available %s", humanBytes(required), humanBytes(available))
	}
	return nil
}''',
)

replace_function(
    "func validateSplitParts(parts []string)",
    "func copyTree(ctx context.Context",
    r'''func validateSplitParts(parts []string) (uint64, error) {
	if len(parts) == 0 {
		return 0, errors.New("no split WIM parts were produced")
	}
	var total uint64
	for _, part := range parts {
		info, err := os.Stat(part)
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 {
			return 0, fmt.Errorf("invalid split WIM part: %s", part)
		}
		size := uint64(info.Size())
		if size > fat32MaxFileSize {
			return 0, fmt.Errorf("%s is %s and cannot fit on FAT32; this ISO contains a resource that wimlib cannot split below the FAT32 file limit", filepath.Base(part), humanBytes(size))
		}
		total, err = checkedAdd("split Windows image total", total, size)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}''',
)

path.write_text(text, encoding="utf-8")
