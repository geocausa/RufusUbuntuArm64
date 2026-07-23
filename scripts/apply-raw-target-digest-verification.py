#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


imaging_path = Path("internal/imaging/imaging.go")
imaging = imaging_path.read_text(encoding="utf-8")
imaging = imaging.replace('''\t"sync"\n''', '''\t"strings"\n\t"sync"\n''', 1)

old_signature = '''func WriteOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (writtenResult uint64, resultErr error) {'''
if imaging.count(old_signature) != 1:
    raise SystemExit("internal/imaging/imaging.go: WriteOpenImage signature mismatch")
new_prefix = '''type WriteResult struct {
\tBytesWritten uint64
\tSHA256       string
}

func WriteOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (uint64, error) {
\tresult, err := writeOpenImage(ctx, src, devicePath, opts)
\treturn result.BytesWritten, err
}

func WriteOpenImageWithResult(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (WriteResult, error) {
\treturn writeOpenImage(ctx, src, devicePath, opts)
}

func writeOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (writeResult WriteResult, resultErr error) {'''
imaging = imaging.replace(old_signature, new_prefix, 1)

start = imaging.index("func writeOpenImage(")
end = imaging.index("\ntype VerifyOptions struct", start)
writer = imaging[start:end]
writer = writer.replace("return 0,", "return writeResult,")
writer = writer.replace("return written,", "return WriteResult{BytesWritten: written},")
final = "return WriteResult{BytesWritten: written}, nil"
if writer.count(final) != 1:
    raise SystemExit(f"internal/imaging/imaging.go: final writer return count={writer.count(final)}")
writer = writer.replace(final, 'return WriteResult{BytesWritten: written, SHA256: hex.EncodeToString(snapshotHash[:])}, nil', 1)
imaging = imaging[:start] + writer + imaging[end:]

verify_marker = '''type VerifyOptions struct {
\tExpectedDeviceID   uint64
\tExpectedDeviceSize uint64
\tExpectedSource     sourcefile.Identity
}
'''
if imaging.count(verify_marker) != 1:
    raise SystemExit("internal/imaging/imaging.go: VerifyOptions marker mismatch")
verify_block = verify_marker + r'''

type DigestVerifyOptions struct {
	ExpectedDeviceID   uint64
	ExpectedDeviceSize uint64
	ImageSize          uint64
	ExpectedSHA256     string
}

// VerifyTargetDigestWithOptions reads only the physical target prefix and
// compares it with the SHA-256 authenticated by the completed write. It avoids
// rereading an unchanged source solely to recompute the same digest.
func VerifyTargetDigestWithOptions(ctx context.Context, devicePath string, opts DigestVerifyOptions, progress ProgressFunc) (string, error) {
	if opts.ImageSize == 0 {
		return "", errors.New("verification image size is zero")
	}
	if opts.ExpectedDeviceSize > 0 && opts.ImageSize > opts.ExpectedDeviceSize {
		return "", errors.New("verification image size exceeds the selected target")
	}
	expected, err := hex.DecodeString(strings.TrimSpace(opts.ExpectedSHA256))
	if err != nil || len(expected) != sha256.Size {
		return "", errors.New("verification requires a valid authenticated SHA-256 digest")
	}

	dst, sectorSize, direct, err := openForVerification(devicePath)
	if err != nil {
		return "", fmt.Errorf("open target for verification: %w", err)
	}
	defer func() { _ = dst.Close() }()
	if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.ExpectedDeviceSize); err != nil {
		return "", err
	}

	alignment := directIOAlignment
	if sectorSize > alignment {
		alignment = sectorSize
	}
	dstBuf := alignedBuffer(DefaultBufferSize, alignment)
	deviceHash := sha256.New()
	var done uint64
	tracker := newRateTracker()
	lastEmit := time.Time{}

	for done < opts.ImageSize {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		remaining := opts.ImageSize - done
		chunk := len(dstBuf)
		if uint64(chunk) > remaining {
			chunk = int(remaining)
		}
		deviceChunk := chunk
		if direct {
			deviceChunk = roundUp(chunk, sectorSize)
		}
		if _, readErr := io.ReadFull(dst, dstBuf[:deviceChunk]); readErr != nil {
			if direct && directIOUnsupported(readErr) {
				_ = dst.Close()
				dst, err = os.Open(devicePath)
				if err != nil {
					return "", fmt.Errorf("reopen target after O_DIRECT refusal: %w", err)
				}
				if err := safety.VerifyOpenDevice(dst, opts.ExpectedDeviceID, opts.ExpectedDeviceSize); err != nil {
					return "", err
				}
				if _, err := dst.Seek(int64(done), io.SeekStart); err != nil {
					return "", fmt.Errorf("seek buffered verification target: %w", err)
				}
				direct = false
				sectorSize = 1
				deviceChunk = chunk
				if _, readErr = io.ReadFull(dst, dstBuf[:deviceChunk]); readErr != nil {
					return "", fmt.Errorf("read target during buffered verification: %w", readErr)
				}
			} else {
				return "", fmt.Errorf("read target during verification: %w", readErr)
			}
		}
		_, _ = deviceHash.Write(dstBuf[:chunk])
		done += uint64(chunk)
		if now := time.Now(); done == opts.ImageSize || now.Sub(lastEmit) >= 200*time.Millisecond {
			lastEmit = now
			emitProgress(progress, tracker, done, opts.ImageSize)
		}
	}

	actual := deviceHash.Sum(nil)
	if !bytes.Equal(expected, actual) {
		return "", errors.New("verification SHA-256 mismatch; the USB does not match the authenticated image bytes")
	}
	return hex.EncodeToString(actual), nil
}
'''
imaging = imaging.replace(verify_marker, verify_block, 1)
imaging_path.write_text(imaging, encoding="utf-8")

replace_once(
    "cmd/rufus-linux/main.go",
    '''\twritten, err := imaging.WriteOpenImage(ctx, rawSource, resolved, imaging.WriteOptions{''',
    '''\twriteResult, err := imaging.WriteOpenImageWithResult(ctx, rawSource, resolved, imaging.WriteOptions{''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\tif err != nil {
\t\treturn err
\t}
\tout.event(jsonEvent{Event: "stage", Stage: "sync", Message: fmt.Sprintf("Wrote %s successfully.", humanBytes(written))})
''',
    '''\tif err != nil {
\t\treturn err
\t}
\twritten := writeResult.BytesWritten
\tout.event(jsonEvent{Event: "stage", Stage: "sync", Message: fmt.Sprintf("Wrote %s successfully.", humanBytes(written))})
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\t\thash, err := imaging.VerifyOpenImageWithOptions(ctx, rawSource, resolved, imaging.VerifyOptions{ExpectedDeviceID: kernelDeviceID, ExpectedDeviceSize: dev.Size, ExpectedSource: sourceIdentity}, func(p imaging.Progress) {''',
    '''\t\thash, err := imaging.VerifyTargetDigestWithOptions(ctx, resolved, imaging.DigestVerifyOptions{ExpectedDeviceID: kernelDeviceID, ExpectedDeviceSize: dev.Size, ImageSize: writeResult.BytesWritten, ExpectedSHA256: writeResult.SHA256}, func(p imaging.Progress) {''',
)

imaging_test = Path("internal/imaging/imaging_test.go")
test_text = imaging_test.read_text(encoding="utf-8")
test_text = test_text.replace('''\t"context"\n''', '''\t"context"\n\t"crypto/sha256"\n\t"encoding/hex"\n''', 1)
marker = '''func TestWriteBeforeWriteFailureLeavesTargetUntouched(t *testing.T) {'''
if test_text.count(marker) != 1:
    raise SystemExit("internal/imaging/imaging_test.go: insertion marker mismatch")
new_test = r'''func TestWriteResultSupportsTargetOnlyDigestVerification(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "image.bin")
	dstPath := filepath.Join(dir, "device.bin")
	payload := make([]byte, 2*1024*1024+37)
	for index := range payload {
		payload[index] = byte((index*17 + 9) % 251)
	}
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, make([]byte, len(payload)+4096), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sourcefile.IdentityOf(source)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	result, err := WriteOpenImageWithResult(context.Background(), source, dstPath, WriteOptions{ExpectedSource: identity, TargetSize: uint64(len(payload) + 4096)})
	if closeErr := source.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(payload)
	if result.BytesWritten != uint64(len(payload)) || result.SHA256 != hex.EncodeToString(expected[:]) {
		t.Fatalf("write result = %#v", result)
	}

	// Verification is bound to the authenticated write digest, not to another
	// read of the source path. Replacing the source after writing must not affect
	// physical target verification.
	if err := os.WriteFile(srcPath, []byte("source changed after the completed write"), 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyTargetDigestWithOptions(context.Background(), dstPath, DigestVerifyOptions{
		ExpectedDeviceSize: uint64(len(payload) + 4096),
		ImageSize:          result.BytesWritten,
		ExpectedSHA256:     result.SHA256,
	}, nil)
	if err != nil || verified != result.SHA256 {
		t.Fatalf("target-only verification hash=%q err=%v", verified, err)
	}

	target, err := os.OpenFile(dstPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.WriteAt([]byte{payload[0] ^ 0xff}, 0); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTargetDigestWithOptions(context.Background(), dstPath, DigestVerifyOptions{
		ExpectedDeviceSize: uint64(len(payload) + 4096),
		ImageSize:          result.BytesWritten,
		ExpectedSHA256:     result.SHA256,
	}, nil); err == nil {
		t.Fatal("target-only verification accepted a corrupted target")
	}
}

'''
test_text = test_text.replace(marker, new_test + marker, 1)
imaging_test.write_text(test_text, encoding="utf-8")

replace_once(
    "docs/operation-cost-contract.json",
    '''      "status": "audit",
      "tracking_issue": 242,
      "upstream_operation": "Write the selected disk image byte-for-byte and optionally compare the written bytes.",
      "intentional_linux_divergence": "RufusArm64 hashes the complete source before writing and again while writing so same-size source mutation fails closed.",''',
    '''      "status": "conformant",
      "tracking_issue": 254,
      "upstream_operation": "Write the selected disk image byte-for-byte and optionally compare the written bytes.",
      "intentional_linux_divergence": "RufusArm64 hashes the complete source before writing and again while writing so same-size source mutation fails closed; optional physical verification hashes only the target and compares it with the authenticated write digest.",''',
)
replace_once(
    "docs/operation-cost-contract.json",
    '''        {
          "name": "verification_source_read",
          "direction": "source_read",
          "scaling": "source_size",
          "multiplier": 1,
          "enabled_by_default": false
        },
''',
    '''''',
)

replace_once(
    "docs/upstream-operation-parity.md",
    '''| Raw/ISOHybrid writing | Source image size | Optional source/target comparison | Audit source-pass count in #242 |''',
    '''| Raw/ISOHybrid writing | One pre-write source hash plus the source read that writes the image | Optional physical target hash compared with the authenticated write digest; no third source read | Conformant plain-source path after #254; prepared-input hand-off remains in #253 |''',
)

replace_once(
    "internal/operationcost/contract.go",
    '''\tif err := requirePhase(operations["raw_image_write"], "target_write", "source_size", true); err != nil {
\t\treturn err
\t}
''',
    '''\tif err := requireExactPhase(operations["raw_image_write"], "bind_source_hash", "source_read", "source_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["raw_image_write"], "write_and_hash_source", "source_read", "source_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := rejectPhaseName(operations["raw_image_write"], "verification_source_read"); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["raw_image_write"], "verification_target_read", "target_read", "source_size", 1, false); err != nil {
\t\treturn err
\t}
\tif err := requirePhase(operations["raw_image_write"], "target_write", "source_size", true); err != nil {
\t\treturn err
\t}
''',
)
replace_once(
    "internal/operationcost/contract.go",
    '''func requireExactPhase(operation Operation, name, direction, scaling string, multiplier int, enabled bool) error {''',
    '''func rejectPhaseName(operation Operation, name string) error {
\tfor _, phase := range operation.Phases {
\t\tif phase.Name == name {
\t\t\treturn fmt.Errorf("operation %s must not contain phase %s", operation.ID, name)
\t\t}
\t}
\treturn nil
}

func requireExactPhase(operation Operation, name, direction, scaling string, multiplier int, enabled bool) error {''',
)

replace_once(
    "internal/operationcost/contract_test.go",
    '''func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {''',
    '''func TestValidateForbidsRawVerificationSourcePass(t *testing.T) {
\tcontract := loadRepositoryContract(t)
\toperation := findOperationIndex(t, contract, "raw_image_write")
\tcontract.Operations[operation].Phases = append(contract.Operations[operation].Phases, Phase{
\t\tName:             "verification_source_read",
\t\tDirection:        "source_read",
\t\tScaling:          "source_size",
\t\tMultiplier:       1,
\t\tEnabledByDefault: false,
\t})
\tif err := Validate(contract); err == nil || !strings.Contains(err.Error(), "must not contain phase verification_source_read") {
\t\tt.Fatalf("raw optional source reread boundary error = %v", err)
\t}
}

func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {''',
)

replace_once(
    "CHANGELOG.md",
    '''- Reduced persistent Linux source verification from three complete image hashes to one authenticated pass under the same identity-bound Linux read lease, while retaining manifest-bound copy verification and the conservative three-pass fallback.
''',
    '''- Reduced persistent Linux source verification from three complete image hashes to one authenticated pass under the same identity-bound Linux read lease, while retaining manifest-bound copy verification and the conservative three-pass fallback.
- Changed optional raw-image verification to hash only the physical target and compare it with the SHA-256 authenticated during the completed write, removing a redundant third complete source read.
''',
)
