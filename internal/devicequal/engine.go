package devicequal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	DefaultRegionSize = 4 * 1024 * 1024
	DefaultBufferSize = 1024 * 1024
	QuickRegionCount  = 32
	MaxRegions        = 1 << 20
	maxBufferSize     = 64 * 1024 * 1024
	maxRegionSize     = 1<<31 - 1
	maxRandomOffset   = uint64(1<<63 - 1)
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

// Backend is the ordinary-file and simulation surface used by this foundation.
// Opening a removable block device belongs to a separate privileged layer.
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
	Kind              string  `json:"kind"`
	Pass              int     `json:"pass"`
	Pattern           string  `json:"pattern"`
	RegionIndex       int     `json:"region_index"`
	RegionOffset      uint64  `json:"region_offset"`
	ByteOffset        uint64  `json:"byte_offset"`
	ExpectedSHA256    string  `json:"expected_sha256,omitempty"`
	ActualSHA256      string  `json:"actual_sha256,omitempty"`
	AliasedWithOffset *uint64 `json:"aliased_with_offset,omitempty"`
	Message           string  `json:"message"`
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
	if capacity > maxRandomOffset {
		return Plan{}, fmt.Errorf("capacity %d exceeds random-access offset limits", capacity)
	}
	if regionSize == 0 {
		regionSize = DefaultRegionSize
	}
	if regionSize > maxRegionSize {
		return Plan{}, fmt.Errorf("region size %d exceeds the bounded buffer contract", regionSize)
	}

	totalRegions := capacity / regionSize
	if capacity%regionSize != 0 {
		totalRegions++
	}
	if totalRegions == 0 || totalRegions > MaxRegions {
		return Plan{}, fmt.Errorf("qualification plan requires %d regions; maximum is %d", totalRegions, MaxRegions)
	}

	indices, err := regionIndices(totalRegions, profile)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Profile:    profile,
		Capacity:   capacity,
		RegionSize: regionSize,
		Regions:    make([]Region, 0, len(indices)),
	}
	for _, sourceIndex := range indices {
		offset := sourceIndex * regionSize
		length := regionSize
		if remaining := capacity - offset; remaining < length {
			length = remaining
		}
		if plan.PlannedBytes > ^uint64(0)-length {
			return Plan{}, fmt.Errorf("planned-byte total overflow")
		}
		plan.Regions = append(plan.Regions, Region{
			Index:  len(plan.Regions),
			Offset: offset,
			Length: length,
		})
		plan.PlannedBytes += length
	}
	plan.SentinelIndices = makeSentinelIndices(len(plan.Regions), profile)
	return plan, nil
}

func regionIndices(total uint64, profile Profile) ([]uint64, error) {
	switch profile {
	case ProfileQuick:
		count := uint64(QuickRegionCount)
		if total < count {
			count = total
		}
		indices := make([]uint64, 0, int(count))
		for sample := uint64(0); sample < count; sample++ {
			index := uint64(0)
			if count > 1 {
				index = (total - 1) * sample / (count - 1)
			}
			if len(indices) == 0 || indices[len(indices)-1] != index {
				indices = append(indices, index)
			}
		}
		return indices, nil
	case ProfileFull:
		indices := make([]uint64, int(total))
		for index := range indices {
			indices[index] = uint64(index)
		}
		return indices, nil
	default:
		return nil, fmt.Errorf("unsupported qualification profile %q", profile)
	}
}

func makeSentinelIndices(count int, profile Profile) []int {
	if count == 0 {
		return nil
	}
	if profile == ProfileQuick {
		indices := make([]int, count)
		for index := range indices {
			indices[index] = index
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
	if config.BufferSize < 4096 || config.BufferSize > maxBufferSize {
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

	writeBuffer := make([]byte, config.BufferSize)
	readBuffer := make([]byte, config.BufferSize)
	expectedBuffer := make([]byte, config.BufferSize)
	for patternIndex, pattern := range config.Patterns {
		passNumber := patternIndex + 1
		pass := PassReport{Number: passNumber, Pattern: pattern.ID}
		started := config.Now()
		if err := ctx.Err(); err != nil {
			return cancelReport(report, pass, passNumber, pattern.ID, started, config.Now(), err)
		}

		for _, region := range plan.Regions {
			written, writeErr := writeRegion(ctx, backend, region, pattern, writeBuffer, pass.WrittenBytes, passNumber, plan.PlannedBytes, config.Progress)
			pass.WrittenBytes += written
			report.CompletedBytes += written
			if writeErr != nil {
				if errors.Is(writeErr, context.Canceled) || errors.Is(writeErr, context.DeadlineExceeded) {
					return cancelReport(report, pass, passNumber, pattern.ID, started, config.Now(), writeErr)
				}
				failure := ioFailure("write", passNumber, pattern.ID, region, region.Offset+written, writeErr)
				return failReport(report, pass, failure, started, config.Now())
			}
		}
		if syncErr := backend.Sync(); syncErr != nil {
			failure := &Failure{
				Kind:        "sync",
				Pass:        passNumber,
				Pattern:     pattern.ID,
				RegionIndex: -1,
				Message:     fmt.Sprintf("flush qualification writes: %v", syncErr),
			}
			return failReport(report, pass, failure, started, config.Now())
		}

		expected, owners := expectedDigests(plan.Regions, pattern, expectedBuffer)
		for _, regionIndex := range verificationOrder(len(plan.Regions), plan.SentinelIndices) {
			region := plan.Regions[regionIndex]
			verified, failure, verifyErr := verifyRegion(
				ctx,
				backend,
				region,
				pattern,
				readBuffer,
				expectedBuffer,
				expected[region.Offset],
				owners,
				pass.VerifiedBytes,
				passNumber,
				plan.PlannedBytes,
				config.Progress,
			)
			pass.VerifiedBytes += verified
			report.CompletedBytes += verified
			if verifyErr != nil {
				if errors.Is(verifyErr, context.Canceled) || errors.Is(verifyErr, context.DeadlineExceeded) {
					return cancelReport(report, pass, passNumber, pattern.ID, started, config.Now(), verifyErr)
				}
				if failure == nil {
					failure = ioFailure("read", passNumber, pattern.ID, region, region.Offset+verified, verifyErr)
				}
				return failReport(report, pass, failure, started, config.Now())
			}
		}
		setTiming(&pass, started, config.Now())
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

func writeRegion(ctx context.Context, backend Backend, region Region, pattern Pattern, buffer []byte, completedBefore uint64, pass int, total uint64, progress ProgressFunc) (uint64, error) {
	var written uint64
	for written < region.Length {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		chunk := chunkSize(region.Length-written, len(buffer))
		absolute := region.Offset + written
		FillPattern(buffer[:chunk], absolute, pattern)
		n, err := backend.WriteAt(buffer[:chunk], int64(absolute))
		written += uint64(n)
		if err != nil {
			return written, err
		}
		if n != chunk {
			return written, io.ErrShortWrite
		}
		emit(progress, Progress{
			Stage:   "write",
			Pass:    pass,
			Pattern: pattern.ID,
			Done:    completedBefore + written,
			Total:   total,
			Offset:  absolute + uint64(n),
		})
	}
	return written, nil
}

func expectedDigests(regions []Region, pattern Pattern, buffer []byte) (map[uint64]string, map[string]uint64) {
	byOffset := make(map[uint64]string, len(regions))
	owners := make(map[string]uint64, len(regions))
	for _, region := range regions {
		digest := expectedDigest(region, pattern, buffer)
		byOffset[region.Offset] = digest
		owners[digest] = region.Offset
	}
	return byOffset, owners
}

func expectedDigest(region Region, pattern Pattern, buffer []byte) string {
	hasher := sha256.New()
	for done := uint64(0); done < region.Length; {
		chunk := chunkSize(region.Length-done, len(buffer))
		FillPattern(buffer[:chunk], region.Offset+done, pattern)
		_, _ = hasher.Write(buffer[:chunk])
		done += uint64(chunk)
	}
	return hex.EncodeToString(hasher.Sum(nil))
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

func verifyRegion(ctx context.Context, backend Backend, region Region, pattern Pattern, readBuffer, expectedBuffer []byte, expectedDigest string, owners map[string]uint64, completedBefore uint64, pass int, total uint64, progress ProgressFunc) (uint64, *Failure, error) {
	hasher := sha256.New()
	var verified uint64
	var firstMismatch uint64
	mismatch := false
	for verified < region.Length {
		if err := ctx.Err(); err != nil {
			return verified, nil, err
		}
		chunk := chunkSize(region.Length-verified, len(readBuffer))
		absolute := region.Offset + verified
		n, readErr := backend.ReadAt(readBuffer[:chunk], int64(absolute))
		verified += uint64(n)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return verified, nil, readErr
		}
		if n != chunk {
			return verified, nil, io.ErrUnexpectedEOF
		}

		FillPattern(expectedBuffer[:chunk], absolute, pattern)
		_, _ = hasher.Write(readBuffer[:chunk])
		if !mismatch {
			for index := 0; index < chunk; index++ {
				if readBuffer[index] != expectedBuffer[index] {
					firstMismatch = absolute + uint64(index)
					mismatch = true
					break
				}
			}
		}
		emit(progress, Progress{
			Stage:   "verify",
			Pass:    pass,
			Pattern: pattern.ID,
			Done:    completedBefore + verified,
			Total:   total,
			Offset:  absolute + uint64(n),
		})
	}

	actualDigest := hex.EncodeToString(hasher.Sum(nil))
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
		aliasOffset := owner
		failure.Kind = "alias"
		failure.AliasedWithOffset = &aliasOffset
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

func chunkSize(remaining uint64, bufferSize int) int {
	if remaining < uint64(bufferSize) {
		return int(remaining)
	}
	return bufferSize
}

func emit(progress ProgressFunc, event Progress) {
	if progress != nil {
		progress(event)
	}
}

func ioFailure(kind string, pass int, pattern string, region Region, byteOffset uint64, err error) *Failure {
	return &Failure{
		Kind:         kind,
		Pass:         pass,
		Pattern:      pattern,
		RegionIndex:  region.Index,
		RegionOffset: region.Offset,
		ByteOffset:   byteOffset,
		Message:      err.Error(),
	}
}

func failReport(report Report, pass PassReport, failure *Failure, started, finished time.Time) (Report, error) {
	pass.Failure = failure
	setTiming(&pass, started, finished)
	report.Passes = append(report.Passes, pass)
	report.Status = StatusFailed
	report.Failure = failure
	report.AliasingDetected = failure.Kind == "alias"
	return report, ErrVerification
}

func cancelReport(report Report, pass PassReport, passNumber int, pattern string, started, finished time.Time, err error) (Report, error) {
	failure := &Failure{
		Kind:        "cancelled",
		Pass:        passNumber,
		Pattern:     pattern,
		RegionIndex: -1,
		Message:     err.Error(),
	}
	pass.Failure = failure
	setTiming(&pass, started, finished)
	report.Passes = append(report.Passes, pass)
	report.Status = StatusCancelled
	report.Failure = failure
	return report, err
}

func setTiming(pass *PassReport, started, finished time.Time) {
	elapsed := finished.Sub(started)
	if elapsed < 0 {
		elapsed = 0
	}
	pass.DurationMillis = elapsed.Milliseconds()
	if elapsed > 0 {
		pass.BytesPerSecond = uint64(float64(pass.WrittenBytes+pass.VerifiedBytes) / elapsed.Seconds())
	}
}
