#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "internal/imaging/input.go"
text = path.read_text(encoding="utf-8")


def replace(old, new):
    global text
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"input.go: expected block not found: {old[:100]!r}")
    text = text.replace(old, new, 1)


replace(
    '''	if candidate == nil {
		return errors.New("ZIP image contains no regular file")
	}
	reader, err := candidate.Open()
''',
    '''	if candidate == nil {
		return errors.New("ZIP image contains no regular file")
	}
	if err := requireHostFileSize("expanded ZIP image", candidate.UncompressedSize64); err != nil {
		return err
	}
	reader, err := candidate.Open()
''',
)
replace(
    '''	if details.VirtualSize == 0 {
		return errors.New("virtual disk reports a zero logical size")
	}
	if maxSize > 0 && details.VirtualSize > maxSize {
''',
    '''	if details.VirtualSize == 0 {
		return errors.New("virtual disk reports a zero logical size")
	}
	if err := requireHostFileSize("virtual disk logical size", details.VirtualSize); err != nil {
		return err
	}
	if maxSize > 0 && details.VirtualSize > maxSize {
''',
)
replace(
    '''		if n > 0 {
			if maxSize > 0 && done+uint64(n) > maxSize {
				return fmt.Errorf("expanded image exceeds the selected target size of %s", humanInputBytes(maxSize))
			}
			if _, err := writeFull(out, buffer[:n]); err != nil {
				return fmt.Errorf("write prepared image: %w", err)
			}
			done += uint64(n)
''',
    '''		if n > 0 {
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
''',
)
replace(
    '''func (w *sizeLimitWriter) Write(data []byte) (int, error) {
	if w.Max > 0 && w.Written+uint64(len(data)) > w.Max {
		w.Exceeded = true
		allowed := int(w.Max - w.Written)
		if allowed > 0 {
			n, err := w.Writer.Write(data[:allowed])
			w.Written += uint64(n)
			if err != nil {
				return n, err
			}
		}
		return allowed, errors.New("expanded image size limit exceeded")
	}
	n, err := w.Writer.Write(data)
	w.Written += uint64(n)
	return n, err
}
''',
    '''func (w *sizeLimitWriter) Write(data []byte) (int, error) {
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
''',
)

path.write_text(text, encoding="utf-8")
