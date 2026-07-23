#!/usr/bin/env python3
import json
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_function(path: str, name: str, replacement: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    marker = f"func {name}("
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"{path}: function {name} not found")
    brace = text.find("{", start)
    if brace < 0:
        raise SystemExit(f"{path}: function {name} has no body")
    depth = 0
    end = None
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end is None:
        raise SystemExit(f"{path}: function {name} body is unbalanced")
    file_path.write_text(text[:start] + replacement.rstrip() + text[end:], encoding="utf-8")


replace_once(
    "internal/imaging/input.go",
    '''\tTemporary        bool
\ttempDir          string
''',
    '''\tTemporary        bool
\ttempDir          string
\trawSHA256        [sha256.Size]byte
\trawSHA256Bound   bool
''',
)

replace_function(
    "internal/imaging/input.go",
    "PrepareInputWithOptions",
    r'''func PrepareInputWithOptions(ctx context.Context, path string, expected sourcefile.Identity, options PrepareOptions, progress PrepareProgressFunc) (prepared *PreparedInput, returnErr error) {
	src, err := sourcefile.OpenRegular(path, expected)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := src.Close(); closeErr != nil {
			if prepared != nil {
				_ = prepared.Close()
				prepared = nil
			}
			returnErr = errors.Join(returnErr, fmt.Errorf("close image container: %w", closeErr))
		}
	}()

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

	sourceLease, leaseErr := sourcefile.AcquireReadLease(ctx, src, expected)
	switch {
	case leaseErr == nil:
		ctx = sourceLease.Context()
		emitPrepare(progress, PrepareProgress{Stage: "source_hold", Message: "Holding the selected image container read-only with a Linux kernel lease during preparation."})
		defer func() {
			heldErr := sourceLease.Check()
			if errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
				heldErr = fmt.Errorf("the selected image container was opened for writing while it was being prepared; no USB data was changed: %w", heldErr)
			}
			closeErr := sourceLease.Close()
			if heldErr != nil || closeErr != nil {
				if prepared != nil {
					_ = prepared.Close()
					prepared = nil
				}
				returnErr = errors.Join(returnErr, heldErr, closeErr)
			}
		}()
	case errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
		sourceLease = nil
		emitPrepare(progress, PrepareProgress{Stage: "source_hold", Message: fmt.Sprintf("Kernel source hold unavailable (%v); using conservative pre/post container hashing.", leaseErr)})
	default:
		return nil, fmt.Errorf("hold image container stable: %w", leaseErr)
	}

	sequential := isSequentialCompressedInput(probe.Kind)
	var containerDigest [sha256.Size]byte
	containerDigestBound := false
	if sourceLease == nil || !sequential {
		message := "Authenticating the selected image container once under the kernel source hold…"
		if sourceLease == nil {
			message = "Hashing the selected image container before preparation (conservative pass 1 of 2)…"
		}
		emitPrepare(progress, PrepareProgress{Stage: "hash_container", Message: message, Total: uint64(expected.Size)})
		containerDigest, err = sourcefile.SHA256Open(ctx, src, func(done, total uint64) {
			emitPrepare(progress, PrepareProgress{Stage: "hash_container", Message: message, Done: done, Total: total})
		})
		if err != nil {
			return nil, fmt.Errorf("hash image container: %w", err)
		}
		containerDigestBound = true
		if err := sourcefile.VerifyPinned(src, expected); err != nil {
			return nil, err
		}
	}

	tempDir, err := os.MkdirTemp("/var/tmp", ".rufusarm64-input-")
	if err != nil {
		return nil, fmt.Errorf("create private image preparation directory: %w", err)
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("protect image preparation directory: %w", err)
	}
	rawPath := filepath.Join(tempDir, "prepared.raw")
	cleanup := func(cause error) (*PreparedInput, error) {
		_ = os.RemoveAll(tempDir)
		return nil, cause
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return cleanup(fmt.Errorf("seek image container: %w", err))
	}
	emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: "Preparing the disk image before erasing the USB…"})
	streamingHash := sha256.New()
	preparationReader := io.Reader(src)
	streamingAuthentication := sourceLease != nil && sequential
	if streamingAuthentication {
		preparationReader = io.TeeReader(src, streamingHash)
	}

	var rawDigest [sha256.Size]byte
	rawDigestBound := false
	switch probe.Kind {
	case InputZIP:
		rawDigest, err = prepareZIP(ctx, src, expected.Size, rawPath, options.MaxPreparedSize, progress)
		rawDigestBound = err == nil
	case InputGZIP:
		rawDigest, err = prepareStream(ctx, preparationReader, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
			decoder, openErr := gzip.NewReader(r)
			return decoder, decoder, openErr
		}, progress)
		rawDigestBound = err == nil
	case InputBZIP2:
		rawDigest, err = prepareStream(ctx, preparationReader, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
			return bzip2.NewReader(r), nil, nil
		}, progress)
		rawDigestBound = err == nil
	case InputXZ:
		rawDigest, err = prepareExternalDecompress(ctx, preparationReader, rawPath, "xz", []string{"--decompress", "--stdout"}, options.MaxPreparedSize, progress)
		rawDigestBound = err == nil
	case InputLZMA:
		rawDigest, err = prepareExternalDecompress(ctx, preparationReader, rawPath, "xz", []string{"--format=lzma", "--decompress", "--stdout"}, options.MaxPreparedSize, progress)
		rawDigestBound = err == nil
	case InputZSTD:
		rawDigest, err = prepareExternalDecompress(ctx, preparationReader, rawPath, "zstd", []string{"--decompress", "--stdout", "--quiet"}, options.MaxPreparedSize, progress)
		rawDigestBound = err == nil
	case InputVHD, InputVHDX, InputQCOW2, InputVMDK:
		err = prepareVirtualDisk(ctx, src, rawPath, probe.Kind, options.MaxPreparedSize, progress)
	default:
		err = fmt.Errorf("unsupported image preparation kind %q", probe.Kind)
	}
	if err != nil {
		return cleanup(err)
	}

	if streamingAuthentication {
		if err := hashRemainingContainer(ctx, streamingHash, src); err != nil {
			return cleanup(fmt.Errorf("finish authenticating image container: %w", err))
		}
		copy(containerDigest[:], streamingHash.Sum(nil))
		containerDigestBound = true
		emitPrepare(progress, PrepareProgress{Stage: "hash_container", Message: "Authenticated the complete image container while preparing it.", Done: uint64(expected.Size), Total: uint64(expected.Size)})
	}
	if err := sourcefile.VerifyPinned(src, expected); err != nil {
		return cleanup(err)
	}
	if sourceLease != nil {
		if err := sourceLease.Check(); err != nil {
			return cleanup(err)
		}
	} else {
		secondHash, hashErr := sourcefile.SHA256Open(ctx, src, nil)
		if hashErr != nil {
			return cleanup(fmt.Errorf("rehash image container after preparation: %w", hashErr))
		}
		if containerDigest != secondHash {
			return cleanup(errors.New("the selected image container changed while it was being prepared; no USB data was changed"))
		}
	}
	if !containerDigestBound {
		return cleanup(errors.New("image container authentication digest is unavailable"))
	}

	raw, err := os.Open(rawPath)
	if err != nil {
		return cleanup(fmt.Errorf("open prepared raw image: %w", err))
	}
	rawIdentity, identityErr := sourcefile.IdentityOf(raw)
	if identityErr == nil && !rawDigestBound {
		rawDigest, identityErr = sourcefile.SHA256Open(ctx, raw, nil)
		rawDigestBound = identityErr == nil
	}
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
	if !rawDigestBound {
		return cleanup(errors.New("prepared raw image authentication digest is unavailable"))
	}
	emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: fmt.Sprintf("Prepared %s of raw disk data.", humanInputBytes(uint64(rawIdentity.Size))), Done: uint64(rawIdentity.Size), Total: uint64(rawIdentity.Size)})
	return &PreparedInput{
		Path:             rawPath,
		Identity:         rawIdentity,
		OriginalPath:     path,
		OriginalIdentity: expected,
		Kind:             probe.Kind,
		SourceSHA256:     hex.EncodeToString(containerDigest[:]),
		Temporary:        true,
		tempDir:          tempDir,
		rawSHA256:        rawDigest,
		rawSHA256Bound:   true,
	}, nil
}''',
)

replace_once(
    "internal/imaging/input.go",
    '''type readerFactory func(io.Reader) (io.Reader, io.Closer, error)
''',
    '''func isSequentialCompressedInput(kind InputKind) bool {
\tswitch kind {
\tcase InputGZIP, InputBZIP2, InputXZ, InputLZMA, InputZSTD:
\t\treturn true
\tdefault:
\t\treturn false
\t}
}

func hashRemainingContainer(ctx context.Context, digest io.Writer, reader io.Reader) error {
\tbuffer := make([]byte, DefaultBufferSize)
\tfor {
\t\tif err := ctx.Err(); err != nil {
\t\t\treturn context.Cause(ctx)
\t\t}
\t\tn, readErr := reader.Read(buffer)
\t\tif n > 0 {
\t\t\tif _, err := digest.Write(buffer[:n]); err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t}
\t\tif errors.Is(readErr, io.EOF) {
\t\t\treturn nil
\t\t}
\t\tif readErr != nil {
\t\t\treturn readErr
\t\t}
\t}
}

type readerFactory func(io.Reader) (io.Reader, io.Closer, error)
''',
)

replace_function(
    "internal/imaging/input.go",
    "prepareStream",
    r'''func prepareStream(ctx context.Context, src io.Reader, rawPath string, maxSize uint64, factory readerFactory, progress PrepareProgressFunc) ([sha256.Size]byte, error) {
	decoder, closer, err := factory(src)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("open compressed image: %w", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	return copyPrepared(ctx, decoder, rawPath, 0, maxSize, progress)
}''',
)

replace_function(
    "internal/imaging/input.go",
    "prepareZIP",
    r'''func prepareZIP(ctx context.Context, src *os.File, sourceSize int64, rawPath string, maxSize uint64, progress PrepareProgressFunc) ([sha256.Size]byte, error) {
	archive, err := zip.NewReader(src, sourceSize)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("open ZIP image: %w", err)
	}
	var candidate *zip.File
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if candidate != nil {
			return [sha256.Size]byte{}, errors.New("ZIP images must contain exactly one regular disk-image file")
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return [sha256.Size]byte{}, errors.New("ZIP image entry must not be a symbolic link")
		}
		candidate = entry
	}
	if candidate == nil {
		return [sha256.Size]byte{}, errors.New("ZIP image contains no regular file")
	}
	if err := requireHostFileSize("expanded ZIP image", candidate.UncompressedSize64); err != nil {
		return [sha256.Size]byte{}, err
	}
	reader, err := candidate.Open()
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("open ZIP image entry: %w", err)
	}
	defer reader.Close()
	if maxSize > 0 && candidate.UncompressedSize64 > maxSize {
		return [sha256.Size]byte{}, fmt.Errorf("expanded ZIP image is %s, larger than the selected target (%s)", humanInputBytes(candidate.UncompressedSize64), humanInputBytes(maxSize))
	}
	return copyPrepared(ctx, reader, rawPath, candidate.UncompressedSize64, maxSize, progress)
}''',
)

replace_function(
    "internal/imaging/input.go",
    "prepareExternalDecompress",
    r'''func prepareExternalDecompress(ctx context.Context, src io.Reader, rawPath, tool string, args []string, maxSize uint64, progress PrepareProgressFunc) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	executable, err := exec.LookPath(tool)
	if err != nil {
		return digest, fmt.Errorf("%s is required to decompress this image", tool)
	}
	out, err := os.OpenFile(rawPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return digest, fmt.Errorf("create prepared image: %w", err)
	}
	rawHash := sha256.New()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = src
	limitedOutput := &sizeLimitWriter{Writer: io.MultiWriter(out, rawHash), Max: maxSize}
	cmd.Stdout = limitedOutput
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{W: &stderr, N: 64 * 1024}
	stop := monitorOutput(ctx, rawPath, 0, progress)
	runErr := cmd.Run()
	stop()
	syncErr := out.Sync()
	closeErr := out.Close()
	if limitedOutput.Exceeded {
		return digest, fmt.Errorf("expanded image exceeds the selected target size of %s", humanInputBytes(maxSize))
	}
	if runErr != nil {
		return digest, fmt.Errorf("decompress image with %s: %v: %s", tool, runErr, strings.TrimSpace(stderr.String()))
	}
	if syncErr != nil {
		return digest, fmt.Errorf("sync prepared image: %w", syncErr)
	}
	if closeErr != nil {
		return digest, fmt.Errorf("close prepared image: %w", closeErr)
	}
	copy(digest[:], rawHash.Sum(nil))
	return digest, nil
}''',
)

replace_function(
    "internal/imaging/input.go",
    "copyPrepared",
    r'''func copyPrepared(ctx context.Context, reader io.Reader, rawPath string, total, maxSize uint64, progress PrepareProgressFunc) (digest [sha256.Size]byte, returnErr error) {
	out, err := os.OpenFile(rawPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return digest, fmt.Errorf("create prepared image: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, out.Close())
		}
	}()
	rawHash := sha256.New()
	writer := io.MultiWriter(out, rawHash)
	buffer := make([]byte, DefaultBufferSize)
	var done uint64
	last := time.Now().Add(-time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return digest, context.Cause(ctx)
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			nextDone, addErr := checkedImageAdd("expanded image size", done, uint64(n))
			if addErr != nil {
				return digest, addErr
			}
			if maxSize > 0 && nextDone > maxSize {
				return digest, fmt.Errorf("expanded image exceeds the selected target size of %s", humanInputBytes(maxSize))
			}
			if _, err := writeFull(writer, buffer[:n]); err != nil {
				return digest, fmt.Errorf("write prepared image: %w", err)
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
			return digest, fmt.Errorf("decompress image: %w", readErr)
		}
	}
	if err := out.Sync(); err != nil {
		return digest, fmt.Errorf("sync prepared image: %w", err)
	}
	if err := out.Close(); err != nil {
		return digest, fmt.Errorf("close prepared image: %w", err)
	}
	closed = true
	copy(digest[:], rawHash.Sum(nil))
	emitPrepare(progress, PrepareProgress{Stage: "prepare", Message: "Preparing the disk image before erasing the USB…", Done: done, Total: total})
	return digest, nil
}''',
)

replace_once(
    "internal/imaging/imaging.go",
    '''\tBeforeWrite func(source *os.File) error
}''',
    '''\tBeforeWrite func(source *os.File) error

\ttrustedSnapshot         [sha256.Size]byte
\ttrustedSnapshotSet      bool
\ttrustedSnapshotIdentity sourcefile.Identity
}''',
)
replace_once(
    "internal/imaging/imaging.go",
    '''// WriteOpenImage writes from an already-open source file. Keeping the source
// descriptor open across the final safety checks, signature wipe, write, and
// verification prevents path replacement from changing the selected image
// after the user confirms the destructive operation.
type WriteResult struct {''',
    '''// WriteResult records the exact byte count and SHA-256 authenticated by a completed image write.
type WriteResult struct {''',
)
replace_once(
    "internal/imaging/imaging.go",
    '''func WriteOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (uint64, error) {''',
    '''// WriteOpenImage writes from an already-open source file. Keeping the source
// descriptor open across the final safety checks, signature wipe, write, and
// verification prevents path replacement from changing the selected image
// after the user confirms the destructive operation.
func WriteOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (uint64, error) {''',
)
replace_once(
    "internal/imaging/imaging.go",
    '''func WriteOpenImageWithResult(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (WriteResult, error) {
\treturn writeOpenImage(ctx, src, devicePath, opts)
}
''',
    '''func WriteOpenImageWithResult(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (WriteResult, error) {
\treturn writeOpenImage(ctx, src, devicePath, opts)
}

// WritePreparedOpenImageWithResult accepts the package-owned digest bound while
// materializing a private prepared.raw file. Caller-created PreparedInput values
// cannot set the unexported digest and therefore remain on the normal prehash path.
func WritePreparedOpenImageWithResult(ctx context.Context, prepared *PreparedInput, src *os.File, devicePath string, opts WriteOptions) (WriteResult, error) {
\tif prepared == nil {
\t\treturn WriteResult{}, errors.New("prepared image is nil")
\t}
\tif src == nil {
\t\treturn WriteResult{}, errors.New("prepared image source is nil")
\t}
\tactual, err := sourcefile.IdentityOf(src)
\tif err != nil {
\t\treturn WriteResult{}, err
\t}
\tif actual != prepared.Identity {
\t\treturn WriteResult{}, errors.New("opened prepared image does not match its package-owned identity")
\t}
\tif opts.ExpectedSource != (sourcefile.Identity{}) && opts.ExpectedSource != prepared.Identity {
\t\treturn WriteResult{}, errors.New("prepared image identity does not match the writer plan")
\t}
\topts.ExpectedSource = prepared.Identity
\tif prepared.rawSHA256Bound {
\t\tif !prepared.Temporary || prepared.tempDir == "" || filepath.Clean(filepath.Dir(prepared.Path)) != filepath.Clean(prepared.tempDir) {
\t\t\treturn WriteResult{}, errors.New("prepared image digest is not bound to a private package-owned materialization")
\t\t}
\t\topts.trustedSnapshot = prepared.rawSHA256
\t\topts.trustedSnapshotSet = true
\t\topts.trustedSnapshotIdentity = prepared.Identity
\t}
\treturn writeOpenImage(ctx, src, devicePath, opts)
}
''',
)
replace_once(
    "internal/imaging/imaging.go",
    '''\t// Hash the already-open source before the target is opened for writing. The
\t// write loop hashes the exact bytes it consumes and compares them with this
\t// snapshot, catching same-size in-place edits even when mtime is restored.
\tsnapshotTracker := newRateTracker()
\tsnapshotHash, err := sourcefile.SHA256Open(ctx, src, func(done, total uint64) {
\t\temitProgress(opts.SnapshotProgress, snapshotTracker, done, total)
\t})
\tif err != nil {
\t\treturn writeResult, fmt.Errorf("hash selected image before writing: %w", err)
\t}
\tif err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
\t\treturn writeResult, err
\t}
''',
    '''\t// Ordinary sources are hashed before the target is opened. A package-owned
\t// prepared.raw may supply the digest computed while it was privately
\t// materialized, avoiding a redundant read without exposing a caller-controlled
\t// digest bypass.
\tvar snapshotHash [sha256.Size]byte
\tif opts.trustedSnapshotSet {
\t\tif err := sourcefile.Verify(src, opts.trustedSnapshotIdentity); err != nil {
\t\t\treturn writeResult, err
\t\t}
\t\tsnapshotHash = opts.trustedSnapshot
\t} else {
\t\tsnapshotTracker := newRateTracker()
\t\tsnapshotHash, err = sourcefile.SHA256Open(ctx, src, func(done, total uint64) {
\t\t\temitProgress(opts.SnapshotProgress, snapshotTracker, done, total)
\t\t})
\t\tif err != nil {
\t\t\treturn writeResult, fmt.Errorf("hash selected image before writing: %w", err)
\t\t}
\t\tif err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
\t\t\treturn writeResult, err
\t\t}
\t}
''',
)
replace_once(
    "internal/imaging/imaging.go",
    '''\t"os"\n\t"strings"''',
    '''\t"os"\n\t"path/filepath"\n\t"strings"''',
)

replace_once(
    "cmd/rufus-linux/main.go",
    '''\twriteResult, err := imaging.WriteOpenImageWithResult(ctx, rawSource, resolved, imaging.WriteOptions{''',
    '''\twriteResult, err := imaging.WritePreparedOpenImageWithResult(ctx, prepared, rawSource, resolved, imaging.WriteOptions{''',
)

# Strengthen existing preparation tests and add a private-digest writer regression.
input_test = Path("internal/imaging/input_test.go")
test_text = input_test.read_text(encoding="utf-8")
test_text = test_text.replace('''\t"context"\n''', '''\t"context"\n\t"crypto/sha256"\n\t"encoding/hex"\n''', 1)
replace_marker = '''\tif !bytes.Equal(readPrepared(t, prepared), raw) {
\t\tt.Fatal("prepared gzip content differs")
\t}
'''
replacement = replace_marker + '''\texpectedRaw := sha256.Sum256(raw)
\tif !prepared.rawSHA256Bound || prepared.rawSHA256 != expectedRaw {
\t\tt.Fatalf("prepared raw digest was not bound: %x", prepared.rawSHA256)
\t}
\tcontainerData, err := os.ReadFile(path)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\texpectedContainer := sha256.Sum256(containerData)
\tif prepared.SourceSHA256 != hex.EncodeToString(expectedContainer[:]) {
\t\tt.Fatalf("container digest=%q want=%x", prepared.SourceSHA256, expectedContainer)
\t}
'''
if test_text.count(replace_marker) != 1:
    raise SystemExit("internal/imaging/input_test.go: gzip assertion marker mismatch")
test_text = test_text.replace(replace_marker, replacement, 1)
marker = '''func TestProbeFFUIsExplicitlyUnsupported(t *testing.T) {'''
new_test = r'''func TestPreparedDigestSkipsRedundantRawSnapshotRead(t *testing.T) {
	raw := testRawImage()
	path := filepath.Join(t.TempDir(), "disk.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	prepared, err := PrepareInput(context.Background(), resolved, identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	source, err := sourcefile.OpenRegular(prepared.Path, prepared.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target := filepath.Join(t.TempDir(), "target.img")
	if err := os.WriteFile(target, make([]byte, len(raw)+4096), 0o600); err != nil {
		t.Fatal(err)
	}
	var snapshotEvents int
	result, err := WritePreparedOpenImageWithResult(context.Background(), prepared, source, target, WriteOptions{
		ExpectedSource: prepared.Identity,
		TargetSize:     uint64(len(raw) + 4096),
		SnapshotProgress: func(Progress) {
			snapshotEvents++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshotEvents != 0 {
		t.Fatalf("private prepared image was redundantly prehashed: %d progress events", snapshotEvents)
	}
	expected := sha256.Sum256(raw)
	if result.SHA256 != hex.EncodeToString(expected[:]) || result.BytesWritten != uint64(len(raw)) {
		t.Fatalf("prepared write result=%#v", result)
	}
}

'''
if test_text.count(marker) != 1:
    raise SystemExit("internal/imaging/input_test.go: FFU marker mismatch")
test_text = test_text.replace(marker, new_test + marker, 1)
input_test.write_text(test_text, encoding="utf-8")

Path("internal/imaging/input_source_lease_linux_test.go").write_text(r'''//go:build linux

package imaging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestPrepareInputFallsBackWithExistingContainerWriter(t *testing.T) {
	raw := testRawImage()
	path := filepath.Join(t.TempDir(), "disk.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var events []PrepareProgress
	prepared, err := PrepareInput(context.Background(), resolved, identity, func(progress PrepareProgress) {
		events = append(events, progress)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !prepareMessagesContain(events, "conservative pre/post") {
		t.Fatalf("fallback message missing: %#v", events)
	}
}

func TestPrepareInputLeaseBreakCancelsAndRemovesPrivateOutput(t *testing.T) {
	raw := make([]byte, 16*1024*1024+123)
	for index := range raw {
		raw[index] = byte((index*13 + 7) % 251)
	}
	path := filepath.Join(t.TempDir(), "disk.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	before, err := filepath.Glob("/var/tmp/.rufusarm64-input-*")
	if err != nil {
		t.Fatal(err)
	}
	known := make(map[string]struct{}, len(before))
	for _, entry := range before {
		known[entry] = struct{}{}
	}

	var once sync.Once
	var triggerErr error
	writerDone := make(chan error, 1)
	prepared, err := PrepareInput(context.Background(), resolved, identity, func(progress PrepareProgress) {
		if progress.Stage != "prepare" || progress.Done == 0 {
			return
		}
		once.Do(func() {
			probe, openErr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
			if probe != nil {
				_ = probe.Close()
			}
			triggerErr = openErr
			go func() {
				writer, writerErr := os.OpenFile(path, os.O_WRONLY, 0)
				if writer != nil {
					_ = writer.Close()
				}
				writerDone <- writerErr
			}()
		})
	})
	if prepared != nil {
		_ = prepared.Close()
		t.Fatal("lease-broken preparation returned a prepared image")
	}
	if !errors.Is(triggerErr, syscall.EAGAIN) {
		t.Fatalf("conflicting writer trigger error=%v", triggerErr)
	}
	if !errors.Is(err, sourcefile.ErrReadLeaseBroken) || !strings.Contains(err.Error(), "no USB data was changed") {
		t.Fatalf("lease-break preparation error=%v", err)
	}
	select {
	case writerErr := <-writerDone:
		if writerErr != nil {
			t.Fatalf("blocked writer after cleanup=%v", writerErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked container writer was not released")
	}
	after, err := filepath.Glob("/var/tmp/.rufusarm64-input-*")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range after {
		if _, existed := known[entry]; !existed {
			t.Fatalf("lease-broken preparation left private output %s", entry)
		}
	}
}

func prepareMessagesContain(events []PrepareProgress, wanted string) bool {
	for _, event := range events {
		if strings.Contains(event.Message, wanted) {
			return true
		}
	}
	return false
}
''', encoding="utf-8")

# Update the operation-cost contract by format class.
contract_path = Path("docs/operation-cost-contract.json")
contract = json.loads(contract_path.read_text(encoding="utf-8"))
operations = contract["operations"]
index = {operation["id"]: position for position, operation in enumerate(operations)}
compressed = {
    "id": "compressed_image_prepare",
    "surface": "Prepare sequentially compressed disk image",
    "classification": "imaging",
    "status": "conformant",
    "tracking_issue": 253,
    "upstream_operation": "Decompress the selected image and write the resulting raw byte stream.",
    "intentional_linux_divergence": "RufusArm64 privately materializes and hashes the expanded raw bytes before erasure; sequential containers are authenticated during the same read under a Linux source lease, with two conditional fallback hashes.",
    "phases": [
        {"name": "decompress_and_authenticate_container", "direction": "source_read", "scaling": "container_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "conservative_fallback_hashes", "direction": "source_read", "scaling": "container_size", "multiplier": 2, "enabled_by_default": False},
        {"name": "materialize_and_hash_raw", "direction": "temporary_write", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "write_authenticated_prepared_raw", "direction": "temporary_read", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "write_image", "direction": "target_write", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
    ],
}
zip_operation = {
    "id": "zip_image_prepare",
    "surface": "Prepare ZIP-contained disk image",
    "classification": "imaging",
    "status": "conformant",
    "tracking_issue": 253,
    "upstream_operation": "Extract the single regular disk-image entry and write the resulting raw byte stream.",
    "intentional_linux_divergence": "ZIP random access retains one complete container authentication hash under the source lease; the extracted raw bytes are hashed while privately materialized.",
    "phases": [
        {"name": "authenticate_zip_container", "direction": "source_read", "scaling": "container_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "extract_zip_entry", "direction": "source_read", "scaling": "container_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "conservative_fallback_rehash", "direction": "source_read", "scaling": "container_size", "multiplier": 1, "enabled_by_default": False},
        {"name": "materialize_and_hash_raw", "direction": "temporary_write", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "write_authenticated_prepared_raw", "direction": "temporary_read", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "write_image", "direction": "target_write", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
    ],
}
virtual = {
    "id": "virtual_disk_prepare",
    "surface": "Prepare VHD/VHDX/QCOW2/VMDK image",
    "classification": "imaging",
    "status": "conformant",
    "tracking_issue": 253,
    "upstream_operation": "Convert or restore the virtual-disk payload into its raw disk representation.",
    "intentional_linux_divergence": "RufusArm64 uses qemu-img to materialize the complete virtual size privately, authenticates the held container once, hashes the converted raw file once, then writes it once.",
    "phases": [
        {"name": "authenticate_virtual_container", "direction": "source_read", "scaling": "container_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "inspect_and_convert_virtual_disk", "direction": "source_read", "scaling": "container_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "conservative_fallback_rehash", "direction": "source_read", "scaling": "container_size", "multiplier": 1, "enabled_by_default": False},
        {"name": "materialize_raw", "direction": "temporary_write", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "bind_converted_raw", "direction": "temporary_read", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "write_authenticated_prepared_raw", "direction": "temporary_read", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
        {"name": "write_image", "direction": "target_write", "scaling": "expanded_size", "multiplier": 1, "enabled_by_default": True},
    ],
}
compressed_index = index["compressed_image_prepare"]
operations[compressed_index] = compressed
operations.insert(compressed_index + 1, zip_operation)
operations[index["virtual_disk_prepare"] + 1] = virtual
contract_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")

replace_once(
    "internal/operationcost/contract.go",
    '''\t"compressed_image_prepare",\n\t"virtual_disk_prepare",''',
    '''\t"compressed_image_prepare",\n\t"zip_image_prepare",\n\t"virtual_disk_prepare",''',
)
replace_once(
    "internal/operationcost/contract.go",
    '''\tif err := requirePhase(operations["raw_image_write"], "target_write", "source_size", true); err != nil {
\t\treturn err
\t}
''',
    '''\tif err := requirePhase(operations["raw_image_write"], "target_write", "source_size", true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["compressed_image_prepare"], "decompress_and_authenticate_container", "source_read", "container_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["compressed_image_prepare"], "write_authenticated_prepared_raw", "temporary_read", "expanded_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["zip_image_prepare"], "authenticate_zip_container", "source_read", "container_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["zip_image_prepare"], "write_authenticated_prepared_raw", "temporary_read", "expanded_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["virtual_disk_prepare"], "authenticate_virtual_container", "source_read", "container_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["virtual_disk_prepare"], "bind_converted_raw", "temporary_read", "expanded_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["virtual_disk_prepare"], "write_authenticated_prepared_raw", "temporary_read", "expanded_size", 1, true); err != nil {
\t\treturn err
\t}
''',
)
replace_once(
    "internal/operationcost/contract_test.go",
    '''func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {''',
    '''func TestValidateRequiresSinglePreparedRawWriterRead(t *testing.T) {
\tcontract := loadRepositoryContract(t)
\tfor _, id := range []string{"compressed_image_prepare", "zip_image_prepare", "virtual_disk_prepare"} {
\t\toperation := findOperationIndex(t, contract, id)
\t\tfor phase := range contract.Operations[operation].Phases {
\t\t\tif contract.Operations[operation].Phases[phase].Name == "write_authenticated_prepared_raw" {
\t\t\t\tcontract.Operations[operation].Phases[phase].Multiplier = 2
\t\t\t}
\t\t}
\t\tif err := Validate(contract); err == nil || !strings.Contains(err.Error(), "write_authenticated_prepared_raw") {
\t\t\tt.Fatalf("%s prepared raw read boundary error = %v", id, err)
\t\t}
\t\tcontract = loadRepositoryContract(t)
\t}
}

func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {''',
)

replace_once(
    "docs/upstream-operation-parity.md",
    '''| Compressed image preparation | Container plus complete expanded raw staging | Raw writer contract | Audit in #242 |
| Virtual-disk preparation | Container plus complete virtual-size raw staging | Raw writer contract | Audit in #242 |''',
    '''| Sequential compressed image preparation | One container read that also authenticates it, one private expanded write, one prepared-raw read for target writing | Authenticated expanded digest plus optional physical target verification | Conformant after #253 |
| ZIP image preparation | One complete ZIP hash plus extraction, one private expanded write, one prepared-raw read for target writing | Authenticated expanded digest plus optional physical target verification | Conformant after #253 |
| Virtual-disk preparation | One complete container hash plus qemu conversion, one converted-raw binding read, one prepared-raw read for target writing | Authenticated converted digest plus optional physical target verification | Conformant after #253 |''',
)
replace_once(
    "CHANGELOG.md",
    '''- Changed optional raw-image verification to hash only the physical target and compare it with the SHA-256 authenticated during the completed write, removing a redundant third complete source read.
''',
    '''- Changed optional raw-image verification to hash only the physical target and compare it with the SHA-256 authenticated during the completed write, removing a redundant third complete source read.
- Reduced sequential compressed-image preparation to one lease-held container read that authenticates while decompressing, removed the post-preparation container rehash on held ZIP/virtual inputs, and passed package-owned expanded digests to the raw writer so private prepared images are read only once during target writing.
''',
)
