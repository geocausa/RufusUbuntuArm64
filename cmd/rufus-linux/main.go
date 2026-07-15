package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/imaging"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/windowsmedia"
)

var version = "0.2.0-dev"

type jsonEvent struct {
	Event   string  `json:"event"`
	Stage   string  `json:"stage,omitempty"`
	Message string  `json:"message,omitempty"`
	Done    uint64  `json:"done,omitempty"`
	Total   uint64  `json:"total,omitempty"`
	Rate    float64 `json:"rate,omitempty"`
	Hash    string  `json:"sha256,omitempty"`
}

type emitter struct{ json bool }

func (e emitter) event(v jsonEvent) {
	if e.json {
		data, _ := json.Marshal(v)
		fmt.Println(string(data))
		return
	}
	if v.Message != "" {
		fmt.Println(v.Message)
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "list":
		return runList(args[1:])
	case "write":
		return runWrite(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "hash":
		return runHash(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Printf(`RufusArm64 %s — bootable USB creator for Linux ARM64

Usage:
  rufus-linux list [--json]
  sudo rufus-linux write --image FILE --device /dev/DEVICE [--verify]

The automatic mode writes Linux ISOHybrid/raw images directly and creates
standard Windows installation USBs using FAT32 and automatic WIM splitting.
Writing is destructive and the running system disk is always refused.
`, version)
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include non-removable whole disks")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	devices, err := device.List()
	if err != nil {
		return err
	}
	disks := device.WholeDisks(devices)
	filtered := make([]device.BlockDevice, 0, len(disks))
	for _, d := range disks {
		if !*all && !d.Removable && d.Transport != "usb" && d.Transport != "mmc" {
			continue
		}
		filtered = append(filtered, d)
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(filtered)
	}
	fmt.Printf("%-16s %-10s %-8s %-5s %-5s %s\n", "DEVICE", "SIZE", "TRAN", "RM", "RO", "MODEL")
	for _, d := range filtered {
		model := strings.TrimSpace(d.Vendor + " " + d.Model)
		fmt.Printf("%-16s %-10s %-8s %-5t %-5t %s\n", d.Path, humanBytes(d.Size), d.Transport, d.Removable, d.ReadOnly, model)
		for _, child := range d.Children {
			if len(child.Mountpoints) > 0 {
				fmt.Printf("  mounted: %-12s %s\n", child.Path, strings.Join(child.Mountpoints, ", "))
			}
		}
	}
	return nil
}

func runWrite(args []string) error {
	fs := flag.NewFlagSet("write", flag.ContinueOnError)
	imagePath := fs.String("image", "", "image or ISO file")
	devicePath := fs.String("device", "", "whole target disk")
	mode := fs.String("mode", "auto", "auto, raw, or windows")
	verify := fs.Bool("verify", false, "verify raw media after writing")
	yes := fs.Bool("yes", false, "skip interactive confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow a non-removable disk")
	noUnmount := fs.Bool("no-unmount", false, "do not unmount mounted filesystems")
	forceRaw := fs.Bool("force-raw", false, "force raw writing of a plain ISO")
	dryRun := fs.Bool("dry-run", false, "check only")
	jsonProgress := fs.Bool("json-progress", false, "emit JSON lines for the GUI")
	if err := fs.Parse(args); err != nil {
		return err
	}
	out := emitter{json: *jsonProgress}
	if *imagePath == "" || *devicePath == "" {
		return errors.New("--image and --device are required")
	}
	switch *mode {
	case "auto", "raw", "windows":
	default:
		return errors.New("--mode must be auto, raw, or windows")
	}
	if err := safety.RequireRoot(); err != nil && !*dryRun {
		return err
	}
	imageInfo, err := os.Stat(*imagePath)
	if err != nil {
		return fmt.Errorf("stat image: %w", err)
	}
	if !imageInfo.Mode().IsRegular() || imageInfo.Size() <= 0 {
		return errors.New("image must be a non-empty regular file")
	}
	inspection, err := imaging.InspectImage(*imagePath)
	if err != nil {
		return err
	}

	selectedMode := *mode
	if selectedMode == "auto" {
		if inspection.HasOpticalFilesystem() && !inspection.LooksLikeRawBootMedia() {
			selectedMode = "windows"
		} else {
			selectedMode = "raw"
		}
	}
	if selectedMode == "raw" && inspection.HasOpticalFilesystem() && !inspection.LooksLikeRawBootMedia() && !*forceRaw {
		return errors.New("this optical ISO is not raw-bootable; use automatic Windows mode or select a bootable disk image")
	}

	resolved, err := safety.ResolveDevice(*devicePath)
	if err != nil {
		return err
	}
	dev, err := device.Find(resolved)
	if err != nil {
		return err
	}
	if err := safety.ValidateTarget(resolved, dev, *allowFixed); err != nil {
		return err
	}
	if err := safety.EnsureImageNotOnTarget(*imagePath, resolved); err != nil {
		return err
	}
	if selectedMode == "raw" && uint64(imageInfo.Size()) > dev.Size {
		return fmt.Errorf("image is %s but target is only %s", humanBytes(uint64(imageInfo.Size())), humanBytes(dev.Size))
	}

	out.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: fmt.Sprintf("Image: %s; target: %s (%s)", filepath.Base(*imagePath), resolved, humanBytes(dev.Size))})
	mounts := device.MountedDescendants(dev)
	if len(mounts) > 0 && *noUnmount {
		return errors.New("target has mounted filesystems")
	}
	if *dryRun {
		out.event(jsonEvent{Event: "complete", Message: "Checks passed; no data was written."})
		return nil
	}
	if !*yes {
		if err := confirmDestructive(resolved); err != nil {
			return err
		}
	}
	if !*noUnmount {
		if err := safety.UnmountDescendants(dev); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if selectedMode == "windows" {
		out.event(jsonEvent{Event: "stage", Stage: "windows", Message: "Creating Windows installation media…"})
		err := windowsmedia.Create(ctx, *imagePath, resolved, windowsmedia.Options{TargetSize: dev.Size, Verify: *verify}, func(ev windowsmedia.Event) {
			eventName := "stage"
			if ev.Stage == "log" {
				eventName = "log"
			}
			if ev.Stage == "complete" {
				eventName = "complete"
			}
			out.event(jsonEvent{Event: eventName, Stage: ev.Stage, Message: ev.Message, Done: ev.Done, Total: ev.Total})
		})
		if err != nil {
			return err
		}
		_ = safety.RereadPartitionTable(resolved)
		return nil
	}

	out.event(jsonEvent{Event: "stage", Stage: "write", Message: "Writing the image…"})
	var last time.Time
	written, err := imaging.WriteImage(ctx, *imagePath, resolved, imaging.WriteOptions{Progress: func(p imaging.Progress) {
		if !*jsonProgress && time.Since(last) < 200*time.Millisecond && p.Done != p.Total {
			return
		}
		last = time.Now()
		if *jsonProgress {
			out.event(jsonEvent{Event: "progress", Stage: "write", Done: p.Done, Total: p.Total, Rate: p.BytesPerSec})
		} else {
			printProgress("write", p)
		}
	}})
	if !*jsonProgress {
		fmt.Println()
	}
	if err != nil {
		return err
	}
	out.event(jsonEvent{Event: "stage", Stage: "sync", Message: fmt.Sprintf("Wrote %s successfully.", humanBytes(written))})
	_ = safety.RereadPartitionTable(resolved)
	if *verify {
		out.event(jsonEvent{Event: "stage", Stage: "verify", Message: "Verifying the USB…"})
		hash, err := imaging.VerifyImage(ctx, *imagePath, resolved, func(p imaging.Progress) {
			if *jsonProgress {
				out.event(jsonEvent{Event: "progress", Stage: "verify", Done: p.Done, Total: p.Total, Rate: p.BytesPerSec})
			} else {
				printProgress("verify", p)
			}
		})
		if !*jsonProgress {
			fmt.Println()
		}
		if err != nil {
			return err
		}
		out.event(jsonEvent{Event: "complete", Stage: "complete", Message: "USB created and verified successfully.", Hash: hash})
	} else {
		out.event(jsonEvent{Event: "complete", Stage: "complete", Message: "Bootable USB created successfully."})
	}
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	image := fs.String("image", "", "image")
	target := fs.String("device", "", "device")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *image == "" || *target == "" {
		return errors.New("--image and --device are required")
	}
	resolved, err := safety.ResolveDevice(*target)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	hash, err := imaging.VerifyImage(ctx, *image, resolved, func(p imaging.Progress) { printProgress("verify", p) })
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Printf("Verification succeeded. SHA-256: %s\n", hash)
	return nil
}
func runHash(args []string) error {
	if len(args) != 1 {
		return errors.New("hash requires exactly one file")
	}
	h, err := imaging.SHA256File(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", h, args[0])
	return nil
}
func confirmDestructive(path string) error {
	fmt.Printf("\nALL DATA ON %s WILL BE DESTROYED.\nType exactly 'ERASE %s' to continue: ", path, path)
	s := bufio.NewScanner(os.Stdin)
	if !s.Scan() {
		return errors.New("confirmation cancelled")
	}
	if strings.TrimSpace(s.Text()) != "ERASE "+path {
		return errors.New("confirmation did not match; cancelled")
	}
	return nil
}
func printProgress(label string, p imaging.Progress) {
	percent := 0.0
	if p.Total > 0 {
		percent = float64(p.Done) * 100 / float64(p.Total)
	}
	fmt.Printf("\r%-6s %6.2f%%  %s / %s  %s/s", label, percent, humanBytes(p.Done), humanBytes(p.Total), humanBytes(uint64(p.BytesPerSec)))
}
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 5; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
