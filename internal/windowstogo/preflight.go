//go:build linux

package windowstogo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/geocausa/RufusArm64/internal/secureboot"
	"github.com/geocausa/RufusArm64/internal/windowsmedia"
)

type preflightEvidence struct {
	TemplatePath                  string
	BootManagerPath               string
	BootManagerAuthenticodeSHA256 string
	BootManagerMachine            uint16
}

func preflightImage(ctx context.Context, tools map[string]string, payload windowsmedia.InstallPayload, plan Plan, workDir string) (preflightEvidence, error) {
	if err := ValidatePlan(plan); err != nil {
		return preflightEvidence{}, err
	}
	wim := tools["wimlib-imagex"]
	if wim == "" {
		return preflightEvidence{}, errors.New("package-owned WIM engine is unavailable")
	}
	preflightDir := filepath.Join(workDir, "preflight")
	if err := os.Mkdir(preflightDir, 0o700); err != nil {
		return preflightEvidence{}, fmt.Errorf("create Windows To Go preflight directory: %w", err)
	}
	args := []string{
		"extract", payload.PrimaryPath, strconv.Itoa(plan.Image.Index),
		"Windows/System32/config/BCD-Template",
		"Windows/Boot/EFI/bootmgfw.efi",
		"--dest-dir=" + preflightDir,
		"--no-acls", "--no-attributes", "--preserve-dir-structure", "--no-globs",
	}
	for _, reference := range payload.ReferencePaths {
		args = append(args, "--ref="+reference)
	}
	if err := runTool(ctx, wim, args...); err != nil {
		return preflightEvidence{}, fmt.Errorf("extract Windows To Go boot prerequisites: %w", err)
	}
	template, err := findCaseInsensitive(preflightDir, "Windows/System32/config/BCD-Template")
	if err != nil {
		return preflightEvidence{}, err
	}
	bootManager, err := findCaseInsensitive(preflightDir, "Windows/Boot/EFI/bootmgfw.efi")
	if err != nil {
		return preflightEvidence{}, err
	}
	pe, err := secureboot.AuthenticodeSHA256File(bootManager)
	if err != nil {
		return preflightEvidence{}, fmt.Errorf("inspect selected Windows boot manager: %w", err)
	}
	if pe.Machine != secureboot.MachineARM64 {
		return preflightEvidence{}, fmt.Errorf("selected Windows boot manager machine 0x%04x is not ARM64", pe.Machine)
	}

	// Exercise the exact BCD transaction before erasure using fixed disposable
	// GUIDs. The generated store is deleted after reopen-and-verify succeeds.
	diskGUID, _ := ParseGUID("00112233-4455-4677-8899-aabbccddeeff")
	espGUID, _ := ParseGUID("11112222-3333-4444-8555-666677778888")
	osGUID, _ := ParseGUID("9999aaaa-bbbb-4ccc-8ddd-eeeeffffffff")
	probeDir := filepath.Join(preflightDir, "bcd-probe")
	if err := os.Mkdir(probeDir, 0o700); err != nil {
		return preflightEvidence{}, fmt.Errorf("create BCD preflight output directory: %w", err)
	}
	probeOutput := filepath.Join(probeDir, "BCD")
	if _, err := CreateBCD(ctx, BCDOptions{
		TemplatePath: template,
		OutputPath:   probeOutput,
		DiskGUID:     diskGUID,
		ESPGUID:      espGUID,
		OSGUID:       osGUID,
		Locale:       plan.Image.DefaultLanguage,
		Description:  "Windows 11",
	}); err != nil {
		return preflightEvidence{}, fmt.Errorf("validate selected BCD template transaction: %w", err)
	}
	if err := os.Remove(probeOutput); err != nil {
		return preflightEvidence{}, fmt.Errorf("remove BCD preflight output: %w", err)
	}
	return preflightEvidence{
		TemplatePath: template, BootManagerPath: bootManager,
		BootManagerAuthenticodeSHA256: pe.SHA256, BootManagerMachine: pe.Machine,
	}, nil
}

func findCaseInsensitive(root, relative string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("case-insensitive lookup root must be canonical and absolute")
	}
	current := root
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("invalid lookup component %q", component)
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", current, err)
		}
		var match os.DirEntry
		for _, entry := range entries {
			if strings.EqualFold(entry.Name(), component) {
				if match != nil {
					return "", fmt.Errorf("ambiguous case-insensitive path component %q below %s", component, current)
				}
				match = entry
			}
		}
		if match == nil {
			return "", fmt.Errorf("required Windows path %s was not found", filepath.ToSlash(relative))
		}
		if match.Type()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("required Windows path %s contains a symbolic link", filepath.ToSlash(relative))
		}
		current = filepath.Join(current, match.Name())
	}
	return current, nil
}
