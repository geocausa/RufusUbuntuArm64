package devicequal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"
)

const (
	DefaultRegionSize = 4 * 1024 * 1024
	DefaultBufferSize = 1024 * 1024
	QuickRegionCount  = 32
	MaxRegions        = 1 << 20
)

type Profile string

const (
	ProfileQuick Profile = "quick"
	ProfileFull  Profile = "full"
)

type Status string

const (
	StatusPassed    Status = "passed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

var ErrVerification = errors.New("device qualification verification failed")

// Backend is the minimal random-access surface required by the qualification
// engine. The first integration deliberately uses ordinary files and synthetic
// backends only; a block-device adapter belongs to the privileged follow-up.
type Backend interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

type Pattern struct {
	ID   string `json:"id"`
	Seed uint64 `json:"seed"`
}

type Region struct {
	Index  int    `json:"index"`
	Offset uint64 `json:"offset"`
	Length uint64 `json:"length"`
}

type Plan struct {
	Profile         Profile  `json:"profile"`
	Capacity        uint64   `json:"capacity"`
	RegionSize      uint64   `json:"region_size"`
	Regions         []Region `json:"regions"`
	SentinelIndices []int    `json:"sentinel_indices"`
	PlannedBytes    uint64   `json:"planned_bytes"`
}

type Progress struct {
	Stage   string `json:"stage"`
	Pass    int    `json:"pass"`
	Pattern string `json:"pattern"`
	Done    uint64 `json:"done"`
	Total   uint64 `json:"total"`
	Offset  uint64 `json:"offset"`
}

type ProgressFunc func(Progress)

type Failure struct {
	Kind               string `json:"kind"`
	Pass               int    `json:"pass"`
	Pattern            string `json:"pattern"`
	RegionIndex        int    `json:"region_index"`
	RegionOffset       uint64 `json:"region_offset"`
	ByteOffset         uint64 `json:"byte_offset"`
	ExpectedSHA256     string `json:"expected_sha256,omitempty"`
	ActualSHA256       string `json:"actual_sha256,omitempty"`
	AliasedWithOffset  uint64 `json:"aliased_with_offset,omitempty"`
	Message            string `json:"message"`
}

type PassReport struct {
	Number         int      `json:"number"`
	Pattern        string   `json:"pattern"`
	WrittenBytes   uint64   `json:"written_bytes"`
	VerifiedBytes  uint64   `json:"verified_bytes"`
	DurationMillis int64    `json:"duration_millis"`
	BytesPerSecond uint64   `json:"bytes_per_second"`
	Failure        *Failure `json:"failure,omitempty"`
}

type Report struct {
	Schema           int          `json:"schema"`
	Profile          Profile      `json:"profile"`
	Capacity         uint64       `json:"capacity"`
	RegionSize       uint64       `json:"region_size"`
	RegionCount      int          `json:"region_count"`
	SentinelCount    int          `json:"sentinel_count"`
	PatternCount     int          `json:"pattern_count"`
	PlannedBytes     uint64       `json:"planned_bytes"`
	CompletedBytes   uint64       `json:"completed_bytes"`
	Status           Status       `json:"status"`
	AliasingDetected bool         `json:"aliasing_detected"`
	Passes           []PassReport `json:"passes"`
	Failure          *Failure     `json:"failure,omitempty"`
}

type Config struct {
	Profile    Profile
	RegionSize uint64
	BufferSize int
	Patterns   []Pattern
	Progress   ProgressFunc
	Now        func() time.Time
}

func DefaultPatterns(profile Profile) ([]Pattern, error) {
	switch profile {
	case ProfileQuick:
		return []Pattern{
			{ID: "address-a", Seed: 0x243f6a8885a308d3},
			{ID: "address-b", Seed: 0x13198a2e03707344},
		}, nil
	case ProfileFull:
		return []Pattern{
			{ID: "address-a", Seed: 0x243f6a8885a308d3},
			{ID: "address-b", Seed: 0x13198a2e03707344},
			{ID: "address-c", Seed: 0xa4093822299f31d0},
			{ID: "address-d", Seed: 0x082efa98ec4e6c89},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported qualification profile %q", profile)
	}
}

func BuildPlan(capacity, regionSize uint64, profile Profile) (Plan, error) {
	if capacity == 0 {
		return Plan{}, fmt.Errorf("capacity must be greater than zero")
	}
	if capacity > math.MaxInt64 {
		return Plan{}, fmt.Errorf("capacity %d exceeds random-access offset limits", capacity)
	}
	if regionSize == 0 {
		regionSize = DefaultRegionSize
	}
	if regionSize > math.MaxInt32 {
		return Plan{}, fmt.Errorf("region size %d exceeds the bounded buffer contract", regionSize)
	}
	totalRegions := capacity / regionSize
	if capacity%regionSize != 0 {
		totalRegions++
	}
	if totalRegions == 0 || totalRegions > MaxRegions {
		return Plan{}, fmt.Errorf("qualification plan requires %d regions; maximum is %d", totalRegions, MaxRegions)
	}

	var indices []uint64
	switch profile {
	case ProfileQuick:
		count := uint64(QuickRegionCount)
		if totalRegions < count {
			count = totalRegions
		}
		indices = make([]uint64, 0, count)
		for i := uint64(0); i < count; i++ {
			index := sampledIndex(i, count, totalRegions)
			if len(indices) == 0 || indices[len(indices)-1] != index {
				indices = append(indices, index)
			}
		}
	case ProfileFull:
		indices = make([]uint64, totalRegions)
		for i := range indices {
			indices[i] = uint64(i)
		}
	default:
		return Plan{}, fmt.Errorf("unsupported qualification profile %q", profile)
	}

	plan := Plan{
		Profile:    profile,
		Capacity:   capacity,
		RegionSize: regionSize,
		Regions:    make([]Region, 0, len(indices)),
	}
	for _, index := range indices {
		offset := index * regionSize
		length := regionSize
		if remaining := capacity - offset; remaining < length {
			length = remaining
		}
		if math.MaxUint64-plan.PlannedBytes < length {
			return Plan{}, fmt.Errorf("planned-byte total overflow")
		}
		plan.Regions = append(plan.Regions, Region{
			Index:  len(plan.Regions),
			Offset: offset,
			Length: length,
		})
		plan.PlannedBytes += length
	}
	plan.SentinelIndices = sentinelIndices(len(plan.Regions), profile)
	return plan, nil
}

func sampledIndex(sample, count, total uint64) uint64 {
	if count <= 1 || total <= 1 {
		return 0
	}
	hi, lo := bits.Mul64(total-1, sample)
	quotient, _ := bits.Div64(hi, lo, count-1)
	return quotient
}

func sentinelIndices(count int, profile Profile) []int {
	if count <= 0 {
		return nil
	}
	if profile == ProfileQuick {
		indices := make([]int, count)
		for i := range indices {
			indices[i] = i
		}
		return indices
	}
	candidates := []int{0, (count - 1) / 4, (count - 1) / 2, 3 * (count - 1) / 4, count - 1}
	indices := make([]int, 0, len(candidates))
	for _, candidate := range candidates {
		if len(indices) == 0 || indices[len(indices)-1] != candidate {
			indices = append(indices, candidate)
		}
	}
	return indices
}

func Run(ctx context.Context, backend Backend, capacity uint64, config Config) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("qualification context is nil")
	}
	if backend == nil {
		return Report{}, fmt.Errorf("qualification backend is nil")
	}
	if config.Profile == "" {
		config.Profile = ProfileQuick
	}
	if config.RegionSize == 0 {
		config.RegionSize = DefaultRegionSize
	}
	if config.BufferSize == 0 {
		config.BufferSize = DefaultBufferSize
	}
	if config.BufferSize < 4096 || config.BufferSize > 64*1024*1024 {
		return Report{}, fmt.Errorf("buffer size %d is outside the 4 KiB to 64 MiB contract", config.BufferSize)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if len(config.Patterns) == 0 {
		patterns, err := DefaultPatterns(config.Profile)
		if err != nil {
			return Report{}, err
		}
		config.Patterns = patterns
	}
	if err := validatePatterns(config.Patterns); err != nil {
		return Report{}, err
	}
	plan, err := BuildPlan(capacity, config.RegionSize, config.Profile)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		Schema:        1,
		Profile:       plan.Profile,
		Capacity:      plan.Capacity,
		RegionSize:    plan.RegionSize,
		RegionCount:   len(plan.Regions),
		SentinelCount: len(plan.SentinelIndices),
		PatternCount:  len(config.Patterns),
		PlannedBytes:  plan.PlannedBytes,
		Status:        StatusPassed,
		Passes:        make([]PassReport, 0, len(config.Patterns)),
	}

	buffer := make([]byte, config.BufferSize)
	for passIndex, pattern := range config.Patterns {
		pass := PassReport{Number: passIndex + 1, Pattern: pattern.ID}
		started := config.Now()
		if err := checkContext(ctx); err != nil {
			return finishCancelled(report, pass, passIndex, pattern, started, config.Now(), err)
		}
		for _, region := range plan.Regions {
			written, writeErr := writeRegion(ctx, backend, region, pattern, buffer, passIndex+1, plan.PlannedBytes, config.Progress)
			pass.WrittenBytes += written
			report.CompletedBytes += written
			if writeErr != nil {
				failure := failureFromError("write", passIndex+1, pattern.ID, region, region.Offset+written, writeErr)
				return finishFailed(report, pass, failure, started, config.Now(), false)
			}
		}
		if err := backend.Sync(); err != nil {
			failure := &Failure{Kind: "sync", Pass: passIndex + 1, Pattern: pattern.ID, RegionIndex: -1, Message: fmt.Sprintf("flush qualification writes: %v", err)}
			return finishFailed(report, pass, failure, started, config.Now(), false)
		}

		expected, owners, digestErr := expectedRegionDigests(plan.Regions, pattern, buffer)
		if digestErr != nil {
			failure := &Failure{Kind: "internal", Pass: passIndex + 1, Pattern: pattern.ID, RegionIndex: -1, Message: digestErr.Error()}
			return finishFailed(report, pass, failure, started, config.Now(), false)
		}
		order := verificationOrder(len(plan.Regions), plan.SentinelIndices)
		for _, regionIndex := range order {
			region := plan.Regions[regionIndex]
			verified, failure, verifyErr := verifyRegion(ctx, backend, region, pattern, buffer, expected[region.Offset], owners, passIndex+1, plan.PlannedBytes, config.Progress)
			pass.VerifiedBytes += verified
			report.CompletedBytes += verified
			if verifyErr != nil {
				if errors.Is(verifyErr, context.Canceled) || errors.Is(verifyErr, context.DeadlineExceeded) {
					return finishCancelled(report, pass, passIndex, pattern, started, config.Now(), verifyErr)
				}
				if failure == nil {
					failure = failureFromError("read", passIndex+1, pattern.ID, region, region.Offset+verified, verifyErr)
				}
				return finishFailed(report, pass, failure, started, config.Now(), failure.Kind == "alias")
			}
		}
		finishPassTiming(&pass, started, config.Now())
		report.Passes = append(report.Passes, pass)
	}
	return report, nil
}

func validatePatterns(patterns []Pattern) error {
	seen := make(map[string]struct{}, len(patterns))
	for index, pattern := range patterns {
		if pattern.ID == "" {
			return fmt.Errorf("pattern %d has an empty identifier", index+1)
		}
		if _, exists := seen[pattern.ID]; exists {
			return fmt.Errorf("duplicate qualification pattern %q", pattern.ID)
		}
		seen[pattern.ID] = struct{}{}
	}
	return nil
}

func writeRegion(ctx context.Context, backend Backend, region Region, pattern Pattern, buffer []byte, pass int, total uint64, progress ProgressFunc) (uint64, error) {
	var written uint64
	for written < region.Length {
		if err := checkContext(ctx); err != nil {
			return written, err
		}
		chunk := uint64(len(buffer))
		if remaining := region.Length - written; remaining < chunk {
			chunk = remaining
		}
		absolute := region.Offset + written
		FillPattern(buffer[:int(chunk)], absolute, pattern)
		n, err := backend.WriteAt(buffer[:int(chunk)], int64(absolute))
		if err != nil {
			return written + uint64(n), err
		}
		if n != int(chunk) {
			return written + uint64(n), io.ErrShortWrite
		}
		written += uint64(n)
		emit(progress, Progress{Stage: "write", Pass: pass, Pattern: pattern.ID, Done: written, Total: total, Offset: absolute + uint64(n)})
	}
	return written, nil
}

func expectedRegionDigests(regions []Region, pattern Pattern, buffer []byte) (map[uint64]string, map[string]uint64, error) {
	expected := make(map[uint64]string, len(regions))
	owners := make(map[string]uint64, len(regions))
	for _, region := range regions {
		hasher := sha256.New()
		var done uint64
		for done < region.Length {
			chunk := uint64(len(buffer))
			if remaining := region.Length - done; remaining < chunk {
				chunk = remaining
			}
			FillPattern(buffer[:int(chunk)], region.Offset+done, pattern)
			if _, err := hasher.Write(buffer[:int(chunk)]); err != nil {
				return nil, nil, fmt.Errorf("hash expected region at %d: %w", region.Offset, err)
			}
			done += chunk
		}
		digest := hex.EncodeToString(hasher.Sum(nil))
		expected[region.Offset] = digest
		owners[digest] = region.Offset
	}
	return expected, owners, nil
}

func verificationOrder(regionCount int, sentinels []int) []int {
	order := make([]int, 0, regionCount)
	seen := make([]bool, regionCount)
	for _, index := range sentinels {
		if index >= 0 && index < regionCount && !seen[index] {
			seen[index] = true
			order = append(order, index)
		}
	}
	for index := 0; index < regionCount; index++ {
		if !seen[index] {
			order = append(order, index)
		}
	}
	return order
}

func verifyRegion(ctx context.Context, backend Backend, region Region, pattern Pattern, buffer []byte, expectedDigest string, owners map[string]uint64, pass int, total uint64, progress ProgressFunc) (uint64, *Failure, error) {
	actualHasher := sha256.New()
	expectedHasher := sha256.New()
	expectedBuffer := make([]byte, len(buffer))
	var verified uint64
	firstMismatch := uint64(0)
	mismatch := false
	for verified < region.Length {
		if err := checkContext(ctx); err != nil {
			return verified, nil, err
		}
		chunk := uint64(len(buffer))
		if remaining := region.Length - verified; remaining < chunk {
			chunk = remaining
		}
		absolute := region.Offset + verified
		n, err := backend.ReadAt(buffer[:int(chunk)], int64(absolute))
		if err != nil && !errors.Is(err, io.EOF) {
			return verified + uint64(n), nil, err
		}
		if n != int(chunk) {
			return verified + uint64(n), nil, io.ErrUnexpectedEOF
		}
		FillPattern(expectedBuffer[:int(chunk)], absolute, pattern)
		if _, err := actualHasher.Write(buffer[:int(chunk)]); err != nil {
			return verified, nil, err
		}
		if _, err := expectedHasher.Write(expectedBuffer[:int(chunk)]); err != nil {
			return verified, nil, err
		}
		if !mismatch {
			for index := 0; index < int(chunk); index++ {
				if buffer[index] != expectedBuffer[index] {
					firstMismatch = absolute + uint64(index)
					mismatch = true
					break
				}
			}
		}
		verified += uint64(n)
		emit(progress, Progress{Stage: "verify", Pass: pass, Pattern: pattern.ID, Done: verified, Total: total, Offset: absolute + uint64(n)})
	}
	actualDigest := hex.EncodeToString(actualHasher.Sum(nil))
	calculatedExpected := hex.EncodeToString(expectedHasher.Sum(nil))
	if calculatedExpected != expectedDigest {
		return verified, nil, fmt.Errorf("expected digest changed for region at %d", region.Offset)
	}
	if !mismatch && actualDigest == expectedDigest {
		return verified, nil, nil
	}
	failure := &Failure{
		Kind:           "mismatch",
		Pass:           pass,
		Pattern:        pattern.ID,
		RegionIndex:    region.Index,
		RegionOffset:   region.Offset,
		ByteOffset:     firstMismatch,
		ExpectedSHA256: expectedDigest,
		ActualSHA256:   actualDigest,
		Message:        fmt.Sprintf("verification mismatch in region at byte %d", region.Offset),
	}
	if owner, exists := owners[actualDigest]; exists && owner != region.Offset {
		failure.Kind = "alias"
		failure.AliasedWithOffset = owner
		failure.Message = fmt.Sprintf("region at byte %d contains the address pattern for byte %d", region.Offset, owner)
	}
	return verified, failure, ErrVerification
}

func FillPattern(destination []byte, absoluteOffset uint64, pattern Pattern) {
	for index := 0; index < len(destination); {
		position := absoluteOffset + uint64(index)
		word := splitMix64(pattern.Seed ^ (position / 8))
		byteIndex := int(position % 8)
		for byteIndex < 8 && index < len(destination) {
			destination[index] = byte(word >> (8 * byteIndex))
			index++
			byteIndex++
		}
	}
}

func splitMix64(value uint64) uint64 {
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	return value ^ (value >> 31)
}

func emit(progress ProgressFunc, event Progress) {
	if progress != nil {
		progress(event)
	}
}

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func failureFromError(kind string, pass int, pattern string, region Region, offset uint64, err error) *Failure {
	return &Failure{
		Kind:         kind,
		Pass:         pass,
		Pattern:      pattern,
		RegionIndex:  region.Index,
		RegionOffset: region.Offset,
		ByteOffset:   offset,
		Message:      err.Error(),
	}
}

func finishFailed(report Report, pass PassReport, failure *Failure, started, finished time.Time, alias bool) (Report, error) {
	pass.Failure = failure
	finishPassTiming(&pass, started, finished)
	report.Passes = append(report.Passes, pass)
	report.Status = StatusFailed
	report.Failure = failure
	report.AliasingDetected = alias
	return report, ErrVerification
}

func finishCancelled(report Report, pass PassReport, passIndex int, pattern Pattern, started, finished time.Time, err error) (Report, error) {
	failure := &Failure{Kind: "cancelled", Pass: passIndex + 1, Pattern: pattern.ID, RegionIndex: -1, Message: err.Error()}
	pass.Failure = failure
	finishPassTiming(&pass, started, finished)
	report.Passes = append(report.Passes, pass)
	report.Status = StatusCancelled
	report.Failure = failure
	return report, err
}

func finishPassTiming(pass *PassReport, started, finished time.Time) {
	elapsed := finished.Sub(started)
	if elapsed < 0 {
		elapsed = 0
	}
	pass.DurationMillis = elapsed.Milliseconds()
	bytes := pass.WrittenBytes + pass.VerifiedBytes
	if elapsed > 0 {
		pass.BytesPerSecond = uint64(float64(bytes) / elapsed.Seconds())
	}
}
