package imaging

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

// InputKind describes the container around the disk image bytes. Plain inputs
// are already raw/ISO bytes. Compressed and virtual-disk inputs are expanded to
// a private raw temporary file before any destructive operation starts.
type InputKind string

const (
	InputPlain InputKind = "plain"
	InputZIP   InputKind = "zip"
	InputGZIP  InputKind = "gzip"
	InputBZIP2 InputKind = "bzip2"
	InputXZ    InputKind = "xz"
	InputLZMA  InputKind = "lzma"
	InputZSTD  InputKind = "zstd"
	InputVHD   InputKind = "vhd"
	InputVHDX  InputKind = "vhdx"
	InputQCOW2 InputKind = "qcow2"
	InputVMDK  InputKind = "vmdk"
	InputFFU   InputKind = "ffu"
)

type InputProbe struct {
	Kind             InputKind
	Description      string
	NeedsPreparation bool
	Supported        bool
}

type PrepareProgress struct {
	Stage   string
	Message string
	Done    uint64
	Total   uint64
}

type PrepareProgressFunc func(PrepareProgress)

type PrepareOptions struct {
	// MaxPreparedSize limits the expanded raw image. Zero means no explicit
	// limit. Writers pass the selected target size so decompression bombs and
	// accidentally selected oversized virtual disks fail before erasure.
	MaxPreparedSize uint64
}

// PreparedInput is an identity-bound raw image ready for inspection and writing.
// Close removes the private temporary materialization when one was required.
type PreparedInput struct {
	Path             string
	Identity         sourcefile.Identity
	OriginalPath     string
	OriginalIdentity sourcefile.Identity
	Kind             InputKind
	SourceSHA256     string
	Temporary        bool
	tempDir          string
}

func (p *PreparedInput) Close() error {
	if p == nil || !p.Temporary || p.tempDir == "" {
		return nil
	}
	err := os.RemoveAll(p.tempDir)
	p.tempDir = ""
	return err
}

func ProbeInput(path string, file *os.File) (InputProbe, error) {
	if file == nil {
		return InputProbe{}, errors.New("image file is nil")
	}
	info, err := file.Stat()
	if err != nil {
		return InputProbe{}, fmt.Errorf("stat image container: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return InputProbe{}, errors.New("image must be a non-empty regular file")
	}

	header := make([]byte, 64*1024)
	n, readErr := file.ReadAt(header, 0)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return InputProbe{}, fmt.Errorf("read image container header: %w", readErr)
	}
	header = header[:n]
	lower := strings.ToLower(path)

	switch {
	case len(header) >= 4 && header[0] == 0x50 && header[1] == 0x4b && (header[2] == 0x03 || header[2] == 0x05 || header[2] == 0x07) && (header[3] == 0x04 || header[3] == 0x06 || header[3] == 0x08):
		return supportedProbe(InputZIP, "ZIP-compressed disk image"), nil
	case len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b:
		return supportedProbe(InputGZIP, "gzip-compressed disk image"), nil
	case len(header) >= 3 && string(header[:3]) == "BZh":
		return supportedProbe(InputBZIP2, "bzip2-compressed disk image"), nil
	case len(header) >= 6 && string(header[:6]) == "\xfd7zXZ\x00":
		return supportedProbe(InputXZ, "XZ-compressed disk image"), nil
	case len(header) >= 4 && binary.LittleEndian.Uint32(header[:4]) == 0xfd2fb528:
		return supportedProbe(InputZSTD, "Zstandard-compressed disk image"), nil
	case len(header) >= 8 && string(header[:8]) == "vhdxfile":
		return supportedProbe(InputVHDX, "Hyper-V VHDX virtual disk"), nil
	case len(header) >= 4 && binary.BigEndian.Uint32(header[:4]) == 0x514649fb:
		return supportedProbe(InputQCOW2, "QEMU QCOW2 virtual disk"), nil
	case len(header) >= 4 && string(header[:4]) == "KDMV":
		return supportedProbe(InputVMDK, "VMware VMDK virtual disk"), nil
	case len(header) >= 16 && string(header[4:16]) == "SignedImage ":
		return InputProbe{Kind: InputFFU, Description: "Microsoft Full Flash Update image", NeedsPreparation: true, Supported: false}, nil
	}

	// VHD stores its identifying footer at the end of the file. A fixed VHD may
	// also begin with that footer, but checking both locations covers dynamic
	// and differencing images without trusting the extension.
	if info.Size() >= 512 {
		footer := make([]byte, 512)
		if _, err := file.ReadAt(footer, info.Size()-512); err == nil && string(footer[:8]) == "conectix" {
			return supportedProbe(InputVHD, "Virtual PC VHD virtual disk"), nil
		}
	}

	// LZMA-alone has no strong fixed magic. Only accept it by extension; the
	// decoder still validates the stream before the target can be touched.
	switch {
	case strings.HasSuffix(lower, ".lzma"):
		return supportedProbe(InputLZMA, "LZMA-compressed disk image"), nil
	case strings.HasSuffix(lower, ".vhd"):
		return supportedProbe(InputVHD, "Virtual PC VHD virtual disk"), nil
	case strings.HasSuffix(lower, ".vhdx"):
		return supportedProbe(InputVHDX, "Hyper-V VHDX virtual disk"), nil
	case strings.HasSuffix(lower, ".qcow2") || strings.HasSuffix(lower, ".qcow"):
		return supportedProbe(InputQCOW2, "QEMU QCOW2 virtual disk"), nil
	case strings.HasSuffix(lower, ".vmdk"):
		return supportedProbe(InputVMDK, "VMware VMDK virtual disk"), nil
	case strings.HasSuffix(lower, ".ffu"):
		return InputProbe{Kind: InputFFU, Description: "Microsoft Full Flash Update image", NeedsPreparation: true, Supported: false}, nil
	}
	return InputProbe{Kind: InputPlain, Description: "Uncompressed disk image", Supported: true}, nil
}

func supportedProbe(kind InputKind, description string) InputProbe {
	return InputProbe{Kind: kind, Description: description, NeedsPreparation: kind != InputPlain, Supported: true}
}

const previewBytes = 160 * 1024

// PreviewInput inspects the decompressed prefix of common compressed images so
// the GUI can distinguish optical-only Windows ISOs from raw ISOHybrid media
// without expanding the entire archive during file selection. Virtual disks
// still require full qemu-img preparation before their embedded layout is known.
func PreviewInput(ctx context.Context, path string, file *os.File, probe InputProbe) (ImageInfo, bool, error) {
	if file == nil {
		return ImageInfo{}, false, errors.New("image file is nil")
	}
	if probe.Kind == InputPlain {
		info, err := InspectOpenFile(file)
		return info, true, err
	}
	if probe.Kind == InputVHD || probe.Kind == InputVHDX || probe.Kind == InputQCOW2 || probe.Kind == InputVMDK || probe.Kind == InputFFU {
		return ImageInfo{}, false, nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ImageInfo{}, false, err
	}
	var reader io.Reader
	var closer io.Closer
	switch probe.Kind {
	case InputZIP:
		stat, err := file.Stat()
		if err != nil {
			return ImageInfo{}, false, err
		}
		archive, err := zip.NewReader(file, stat.Size())
		if err != nil {
			return ImageInfo{}, false, err
		}
		var candidate *zip.File
		for _, entry := range archive.File {
			if entry.FileInfo().IsDir() {
				continue
			}
			if candidate != nil || entry.Mode()&os.ModeSymlink != 0 {
				return ImageInfo{}, false, errors.New("ZIP images must contain exactly one regular non-symlink file")
			}
			candidate = entry
		}
		if candidate == nil {
			return ImageInfo{}, false, errors.New("ZIP image contains no regular file")
		}
		opened, err := candidate.Open()
		if err != nil {
			return ImageInfo{}, false, err
		}
		reader, closer = opened, opened
	case InputGZIP:
		opened, err := gzip.NewReader(file)
		if err != nil {
			return ImageInfo{}, false, err
		}
		reader, closer = opened, opened
	case InputBZIP2:
		reader = bzip2.NewReader(file)
	case InputXZ, InputLZMA, InputZSTD:
		data, err := externalPreview(ctx, file, probe.Kind)
		if err != nil {
			return ImageInfo{}, false, err
		}
		info, err := InspectReaderAt(bytes.NewReader(data), 2*1024*1024*1024*1024)
		return info, true, err
	default:
		return ImageInfo{}, false, nil
	}
	if closer != nil {
		defer closer.Close()
	}
	data, err := io.ReadAll(io.LimitReader(reader, previewBytes))
	if err != nil {
		return ImageInfo{}, false, fmt.Errorf("read compressed image preview: %w", err)
	}
	if len(data) < 1024 {
		return ImageInfo{}, false, errors.New("compressed image is too small")
	}
	info, err := InspectReaderAt(bytes.NewReader(data), 2*1024*1024*1024*1024)
	return info, true, err
}

func externalPreview(ctx context.Context, source *os.File, kind InputKind) ([]byte, error) {
	tool := "xz"
	args := []string{"--decompress", "--stdout"}
	if kind == InputLZMA {
		args = []string{"--format=lzma", "--decompress", "--stdout"}
	} else if kind == InputZSTD {
		tool = "zstd"
		args = []string{"--decompress", "--stdout", "--quiet"}
	}
	executable, err := exec.LookPath(tool)
	if err != nil {
		return nil, fmt.Errorf("%s is required to preview this image", tool)
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(childCtx, executable, args...)
	cmd.Stdin = source
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{W: &stderr, N: 16 * 1024}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, previewBytes))
	cancel()
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if len(data) < 1024 {
		if waitErr != nil {
			return nil, fmt.Errorf("preview image with %s: %v: %s", tool, waitErr, strings.TrimSpace(stderr.String()))
		}
		return nil, errors.New("compressed image is too small")
	}
	return data, nil
}

// PrepareInput converts a compressed or virtual disk container into a private,
// regular raw file. The original source is hashed before and after conversion;
// this prevents a changing source from producing a mixed image even when file
// timestamps are restored by another process.
func PrepareInput(ctx context.Context, path string, expected sourcefile.Identity, progress PrepareProgressFunc) (*PreparedInput, error) {
	return PrepareInputWithOptions(ctx, path, expected, PrepareOptions{}, progress)
}

func PrepareInputWithOptions(ctx context.Context, path string, expected sourcefile.Identity, options PrepareOptions, progress PrepareProgressFunc) (*PreparedInput, error) {
	src, err := sourcefile.OpenRegular(path, expected)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	probe, err := ProbeInput(path, src)
	if err != nil {
		return nil, err
	}
	if !probe.Supported {
		if probe.Kind == InputFFU {
			return nil, errors.New("FFU restoration is not available on Linux: official Rufus relies on the Windows FFU provider, and no safe Linux equivalent is installed")
		}
		return nil, fmt.Errorf("unsupported image container %q", probe.Kind)
	}
	if probe.Kind == InputPlain {
		return &PreparedInput{Path: path, Identity: expected, OriginalPath: path, OriginalIdentity: expected, Kind: InputPlain}, nil
	}

	emitPrepare(progress, PrepareProgress{Stage: "hash_container", Message: "Hashing the selected image container before preparation…", Total: uint64(expected.Size)})
	firstHash, err := sourcefile.SHA256Open(ctx, src, func(done, total uint64) {
		emitPrepare(progress, PrepareProgress{Stage: "hash_container", Message: "Hashing the selected image container before preparation…", Done: done, Total: total})
	})
	if err != nil {
		return nil, fmt.Errorf("hash image container: %w", err)
	}
	if err := sourcefile.VerifyPinned(src, expected); err != nil {
		return nil, err
	}

	tempDir, err := os.MkdirTemp("/var/tmp", ".rufusarm64-input-")
	if err != nil {
		return nil, fmt.Errorf("create private image preparation directory: %w", err)
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("protect image preparation directory: %w", err)
	}
	rawPath := filepath.Join(tempDir, "prepared.raw")
	cleanup := func(returnErr error) (*PreparedInput, error) {
		_ = os.RemoveAll(tempDir)
		return nil, returnErr
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return cleanup(fmt.Errorf("seek image container: %w", err))
	}
	emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: "Preparing the disk image before erasing the USB…"})
	switch probe.Kind {
	case InputZIP:
		err = prepareZIP(ctx, src, expected.Size, rawPath, options.MaxPreparedSize, progress)
	case InputGZIP:
		err = prepareStream(ctx, src, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
			decoder, err := gzip.NewReader(r)
			return decoder, decoder, err
		}, progress)
	case InputBZIP2:
		err = prepareStream(ctx, src, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
			return bzip2.NewReader(r), nil, nil
		}, progress)
	case InputXZ:
		err = prepareExternalDecompress(ctx, src, rawPath, "xz", []string{"--decompress", "--stdout"}, options.MaxPreparedSize, progress)
	case InputLZMA:
		err = prepareExternalDecompress(ctx, src, rawPath, "xz", []string{"--format=lzma", "--decompress", "--stdout"}, options.MaxPreparedSize, progress)
	case InputZSTD:
		err = prepareExternalDecompress(ctx, src, rawPath, "zstd", []string{"--decompress", "--stdout", "--quiet"}, options.MaxPreparedSize, progress)
	case InputVHD, InputVHDX, InputQCOW2, InputVMDK:
		err = prepareVirtualDisk(ctx, src, rawPath, probe.Kind, options.MaxPreparedSize, progress)
	default:
		err = fmt.Errorf("unsupported image preparation kind %q", probe.Kind)
	}
	if err != nil {
		return cleanup(err)
	}

	if err := sourcefile.VerifyPinned(src, expected); err != nil {
		return cleanup(err)
	}
	secondHash, err := sourcefile.SHA256Open(ctx, src, nil)
	if err != nil {
		return cleanup(fmt.Errorf("rehash image container after preparation: %w", err))
	}
	if firstHash != secondHash {
		return cleanup(errors.New("the selected image container changed while it was being prepared; no USB data was changed"))
	}

	raw, err := os.Open(rawPath)
	if err != nil {
		return cleanup(fmt.Errorf("open prepared raw image: %w", err))
	}
	rawIdentity, identityErr := sourcefile.IdentityOf(raw)
	closeErr := raw.Close()
	if identityErr != nil {
		return cleanup(identityErr)
	}
	if closeErr != nil {
		return cleanup(fmt.Errorf("close prepared raw image: %w", closeErr))
	}
	if rawIdentity.Size <= 0 {
		return cleanup(errors.New("prepared image is empty"))
	}
	emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: fmt.Sprintf("Prepared %s of raw disk data.", humanInputBytes(uint64(rawIdentity.Size))), Done: uint64(rawIdentity.Size), Total: uint64(rawIdentity.Size)})
	return &PreparedInput{
		Path:             rawPath,
		Identity:         rawIdentity,
		OriginalPath:     path,
		OriginalIdentity: expected,
		Kind:             probe.Kind,
		SourceSHA256:     hex.EncodeToString(firstHash[:]),
		Temporary:        true,
		tempDir:          tempDir,
	}, nil
}

type readerFactory func(io.Reader) (io.Reader, io.Closer, error)

func prepareStream(ctx context.Context, src *os.File, rawPath string, maxSize uint64, factory readerFactory, progress PrepareProgressFunc) error {
	decoder, closer, err := factory(src)
	if err != nil {
		return fmt.Errorf("open compressed image: %w", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	return copyPrepared(ctx, decoder, rawPath, 0, maxSize, progress)
}

func prepareZIP(ctx context.Context, src *os.File, sourceSize int64, rawPath string, maxSize uint64, progress PrepareProgressFunc) error {
	archive, err := zip.NewReader(src, sourceSize)
	if err != nil {
		return fmt.Errorf("open ZIP image: %w", err)
	}
	var candidate *zip.File
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if candidate != nil {
			return errors.New("ZIP images must contain exactly one regular disk-image file")
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return errors.New("ZIP image entry must not be a symbolic link")
		}
		candidate = entry
	}
	if candidate == nil {
		return errors.New("ZIP image contains no regular file")
	}
	if err := requireHostFileSize("expanded ZIP image", candidate.UncompressedSize64); err != nil {
		return err
	}
	reader, err := candidate.Open()
	if err != nil {
		return fmt.Errorf("open ZIP image entry: %w", err)
	}
	defer reader.Close()
	if maxSize > 0 && candidate.UncompressedSize64 > maxSize {
		return fmt.Errorf("expanded ZIP image is %s, larger than the selected target (%s)", humanInputBytes(candidate.UncompressedSize64), humanInputBytes(maxSize))
	}
	return copyPrepared(ctx, reader, rawPath, candidate.UncompressedSize64, maxSize, progress)
}

func prepareExternalDecompress(ctx context.Context, src *os.File, rawPath, tool string, args []string, maxSize uint64, progress PrepareProgressFunc) error {
	executable, err := exec.LookPath(tool)
	if err != nil {
		return fmt.Errorf("%s is required to decompress this image", tool)
	}
	out, err := os.OpenFile(rawPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create prepared image: %w", err)
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = src
	limitedOutput := &sizeLimitWriter{Writer: out, Max: maxSize}
	cmd.Stdout = limitedOutput
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{W: &stderr, N: 64 * 1024}
	stop := monitorOutput(ctx, rawPath, 0, progress)
	runErr := cmd.Run()
	stop()
	syncErr := out.Sync()
	closeErr := out.Close()
	if limitedOutput.Exceeded {
		return fmt.Errorf("expanded image exceeds the selected target size of %s", humanInputBytes(maxSize))
	}
	if runErr != nil {
		return fmt.Errorf("decompress image with %s: %v: %s", tool, runErr, strings.TrimSpace(stderr.String()))
	}
	if syncErr != nil {
		return fmt.Errorf("sync prepared image: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close prepared image: %w", closeErr)
	}
	return nil
}

type qemuInfo struct {
	Format          string `json:"format"`
	VirtualSize     uint64 `json:"virtual-size"`
	BackingFilename string `json:"backing-filename"`
	Encrypted       bool   `json:"encrypted"`
}

func prepareVirtualDisk(ctx context.Context, src *os.File, rawPath string, kind InputKind, maxSize uint64, progress PrepareProgressFunc) error {
	executable, err := exec.LookPath("qemu-img")
	if err != nil {
		return errors.New("qemu-img is required for VHD, VHDX, QCOW2, and VMDK restoration; install the qemu-utils package")
	}
	format := map[InputKind]string{InputVHD: "vpc", InputVHDX: "vhdx", InputQCOW2: "qcow2", InputVMDK: "vmdk"}[kind]
	if format == "" {
		return fmt.Errorf("unsupported virtual disk type %q", kind)
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek virtual disk: %w", err)
	}
	infoCmd := exec.CommandContext(ctx, executable, "info", "--output=json", "-f", format, "/proc/self/fd/3")
	infoCmd.ExtraFiles = []*os.File{src}
	var infoOut, infoErr strings.Builder
	infoCmd.Stdout = &infoOut
	infoCmd.Stderr = &limitedWriter{W: &infoErr, N: 64 * 1024}
	if err := infoCmd.Run(); err != nil {
		return fmt.Errorf("inspect virtual disk with qemu-img: %v: %s", err, strings.TrimSpace(infoErr.String()))
	}
	var details qemuInfo
	if err := json.Unmarshal([]byte(infoOut.String()), &details); err != nil {
		return fmt.Errorf("parse qemu-img information: %w", err)
	}
	if details.VirtualSize == 0 {
		return errors.New("virtual disk reports a zero logical size")
	}
	if err := requireHostFileSize("virtual disk logical size", details.VirtualSize); err != nil {
		return err
	}
	if maxSize > 0 && details.VirtualSize > maxSize {
		return fmt.Errorf("virtual disk expands to %s, larger than the selected target (%s)", humanInputBytes(details.VirtualSize), humanInputBytes(maxSize))
	}
	if details.BackingFilename != "" {
		return fmt.Errorf("virtual disk depends on external backing file %q; flatten it before writing", details.BackingFilename)
	}
	if details.Encrypted {
		return errors.New("encrypted virtual disks are not supported")
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind virtual disk: %w", err)
	}
	convertCmd := exec.CommandContext(ctx, executable, "convert", "-f", format, "-O", "raw", "/proc/self/fd/3", rawPath)
	convertCmd.ExtraFiles = []*os.File{src}
	var stderr strings.Builder
	convertCmd.Stderr = &limitedWriter{W: &stderr, N: 64 * 1024}
	stop := monitorOutput(ctx, rawPath, details.VirtualSize, progress)
	runErr := convertCmd.Run()
	stop()
	if runErr != nil {
		return fmt.Errorf("convert virtual disk with qemu-img: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	file, err := os.OpenFile(rawPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open converted raw image: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync converted raw image: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat converted raw image: %w", err)
	}
	if uint64(info.Size()) != details.VirtualSize {
		return fmt.Errorf("converted raw image size is %d bytes; expected %d", info.Size(), details.VirtualSize)
	}
	return nil
}

func copyPrepared(ctx context.Context, reader io.Reader, rawPath string, total, maxSize uint64, progress PrepareProgressFunc) error {
	out, err := os.OpenFile(rawPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create prepared image: %w", err)
	}
	defer out.Close()
	buffer := make([]byte, DefaultBufferSize)
	var done uint64
	last := time.Now().Add(-time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			nextDone, err := checkedImageAdd("expanded image size", done, uint64(n))
			if err != nil {
				return err
			}
			if maxSize > 0 && nextDone > maxSize {
				return fmt.Errorf("expanded image exceeds the selected target size of %s", humanInputBytes(maxSize))
			}
			if _, err := writeFull(out, buffer[:n]); err != nil {
				return fmt.Errorf("write prepared image: %w", err)
			}
			done = nextDone
			if time.Since(last) >= 200*time.Millisecond || (total > 0 && done == total) {
				emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: "Preparing the disk image before erasing the USB…", Done: done, Total: total})
				last = time.Now()
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("decompress image: %w", readErr)
		}
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync prepared image: %w", err)
	}
	emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: "Preparing the disk image before erasing the USB…", Done: done, Total: total})
	return nil
}

func monitorOutput(ctx context.Context, path string, total uint64, progress PrepareProgressFunc) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				if info, err := os.Stat(path); err == nil {
					emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: "Preparing the disk image before erasing the USB…", Done: uint64(info.Size()), Total: total})
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

func emitPrepare(progress PrepareProgressFunc, value PrepareProgress) {
	if progress != nil {
		progress(value)
	}
}

type sizeLimitWriter struct {
	Writer   io.Writer
	Max      uint64
	Written  uint64
	Exceeded bool
}

func (w *sizeLimitWriter) Write(data []byte) (int, error) {
	next, addErr := checkedImageAdd("expanded image size", w.Written, uint64(len(data)))
	if addErr != nil {
		w.Exceeded = true
		return 0, addErr
	}
	if w.Max > 0 && next > w.Max {
		w.Exceeded = true
		if w.Written >= w.Max {
			return 0, errors.New("expanded image size limit exceeded")
		}
		allowed := int(w.Max - w.Written)
		n, err := w.Writer.Write(data[:allowed])
		w.Written += uint64(n)
		if err != nil {
			return n, err
		}
		return n, errors.New("expanded image size limit exceeded")
	}
	n, err := w.Writer.Write(data)
	w.Written += uint64(n)
	return n, err
}

type limitedWriter struct {
	W io.Writer
	N int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	original := len(p)
	if w.N <= 0 {
		return original, nil
	}
	if int64(len(p)) > w.N {
		p = p[:w.N]
	}
	n, err := w.W.Write(p)
	w.N -= int64(n)
	if err != nil {
		return n, err
	}
	return original, nil
}

func humanInputBytes(n uint64) string {
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

// Keep sha256 imported as an explicit compile-time assertion that the source
// digest returned by PrepareInput is a full SHA-256 digest.
var _ = sha256.Size
