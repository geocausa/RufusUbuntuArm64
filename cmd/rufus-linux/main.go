package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/rufus-linux-arm64/internal/device"
	"github.com/geocausa/rufus-linux-arm64/internal/imaging"
	"github.com/geocausa/rufus-linux-arm64/internal/safety"
)

var version = "0.1.0-dev"

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
	fmt.Printf(`rufus-linux %s — experimental Linux ARM64 boot-media writer

Usage:
  rufus-linux list
  sudo rufus-linux write --image FILE --device /dev/DEVICE [--verify]
  sudo rufus-linux verify --image FILE --device /dev/DEVICE
  rufus-linux hash FILE

Commands:
  list    Show whole-disk targets reported by lsblk
  write   Unmount and write a raw/ISOHybrid image to a whole disk
  verify  Compare an image with the first matching bytes on a device
  hash    Print SHA-256 for an image

The write command is destructive. It refuses the root disk, partitions,
read-only devices, and fixed disks unless --allow-fixed is supplied.
`, version)
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include non-removable whole disks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	devices, err := device.List()
	if err != nil {
		return err
	}
	disks := device.WholeDisks(devices)
	fmt.Printf("%-16s %-10s %-8s %-5s %-5s %s\n", "DEVICE", "SIZE", "TRAN", "RM", "RO", "MODEL")
	for _, d := range disks {
		if !*all && !d.Removable && d.Transport != "usb" && d.Transport != "mmc" {
			continue
		}
		model := strings.TrimSpace(strings.TrimSpace(d.Vendor + " " + d.Model))
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
	imagePath := fs.String("image", "", "raw disk image or ISOHybrid file")
	devicePath := fs.String("device", "", "whole target disk, for example /dev/sda")
	verify := fs.Bool("verify", false, "verify every written byte after syncing")
	yes := fs.Bool("yes", false, "skip interactive confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow a non-removable disk after other safety checks")
	noUnmount := fs.Bool("no-unmount", false, "do not unmount mounted child filesystems")
	forceRaw := fs.Bool("force-raw", false, "write a plain optical ISO or unrecognized image without disk signatures")
	dryRun := fs.Bool("dry-run", false, "perform checks but do not write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *imagePath == "" || *devicePath == "" {
		return errors.New("--image and --device are required")
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
	if inspection.HasISO9660 && !inspection.LooksLikeRawBootMedia() && !*forceRaw {
		return errors.New("plain optical ISO detected without MBR/GPT disk signatures; raw writing is unlikely to produce bootable USB media (use --force-raw only if intentional)")
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
	if uint64(imageInfo.Size()) > dev.Size {
		return fmt.Errorf("image is %s but target is only %s", humanBytes(uint64(imageInfo.Size())), humanBytes(dev.Size))
	}

	fmt.Printf("Image:  %s (%s)\n", filepath.Clean(*imagePath), humanBytes(uint64(imageInfo.Size())))
	fmt.Printf("Target: %s (%s, %s %s, transport=%s, removable=%t)\n", resolved, humanBytes(dev.Size), dev.Vendor, dev.Model, dev.Transport, dev.Removable)
	mounts := device.MountedDescendants(dev)
	if len(mounts) > 0 {
		if *noUnmount {
			return errors.New("target has mounted filesystems; refusing to write with --no-unmount")
		}
		fmt.Println("Mounted filesystems that will be unmounted:")
		for _, node := range mounts {
			fmt.Printf("  %s: %s\n", node.Path, strings.Join(node.Mountpoints, ", "))
		}
	}

	if *dryRun {
		fmt.Println("Dry run complete; no data was written.")
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

	fmt.Println("Writing image...")
	var lastLine time.Time
	written, err := imaging.WriteImage(ctx, *imagePath, resolved, imaging.WriteOptions{Progress: func(p imaging.Progress) {
		if time.Since(lastLine) < 200*time.Millisecond && p.Done != p.Total {
			return
		}
		lastLine = time.Now()
		printProgress("write", p)
	}})
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s successfully.\n", humanBytes(written))

	if err := safety.RereadPartitionTable(resolved); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	if *verify {
		fmt.Println("Verifying...")
		hash, err := imaging.VerifyImage(ctx, *imagePath, resolved, func(p imaging.Progress) { printProgress("verify", p) })
		fmt.Println()
		if err != nil {
			return err
		}
		fmt.Printf("Verification succeeded. SHA-256: %s\n", hash)
	}
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	imagePath := fs.String("image", "", "image file")
	devicePath := fs.String("device", "", "target device")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *imagePath == "" || *devicePath == "" {
		return errors.New("--image and --device are required")
	}
	resolved, err := safety.ResolveDevice(*devicePath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hash, err := imaging.VerifyImage(ctx, *imagePath, resolved, func(p imaging.Progress) { printProgress("verify", p) })
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
	hash, err := imaging.SHA256File(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", hash, args[0])
	return nil
}

func confirmDestructive(path string) error {
	fmt.Printf("\nALL DATA ON %s WILL BE DESTROYED.\n", path)
	fmt.Printf("Type exactly 'ERASE %s' to continue: ", path)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return errors.New("confirmation cancelled")
	}
	expected := "ERASE " + path
	if strings.TrimSpace(scanner.Text()) != expected {
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
	for value := n / unit; value >= unit && exp < 5; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
