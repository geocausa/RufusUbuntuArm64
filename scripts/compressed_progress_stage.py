#!/usr/bin/env python3
"""Apply the exact compressed-preparation progress integration."""

from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, found {count}")
    path.write_text(source.replace(old, new), encoding="utf-8")


path = Path("internal/imaging/input.go")
replace_once(
    path,
    '''\tstreamingAuthentication := sourceLease != nil && sequential
\tif streamingAuthentication {
\t\tpreparationReader = io.TeeReader(src, streamingHash)
\t}

\tvar rawDigest [sha256.Size]byte
''',
    '''\tstreamingAuthentication := sourceLease != nil && sequential
\tif streamingAuthentication {
\t\tpreparationReader = io.TeeReader(src, streamingHash)
\t}
\tvar containerProgress *compressedContainerProgressReader
\tpreparationProgress := progress
\tif sequential {
\t\tcontainerProgress = newCompressedContainerProgressReader(preparationReader, uint64(expected.Size), progress)
\t\tpreparationReader = containerProgress
\t\t// Expanded size is deliberately not guessed for streaming formats. The
\t\t// compressed-container channel supplies a trustworthy percentage, and the
\t\t// final expanded-byte event is emitted after authenticated materialization.
\t\tpreparationProgress = nil
\t}

\tvar rawDigest [sha256.Size]byte
''',
    "compressed progress reader integration",
)

source = path.read_text(encoding="utf-8")
start = source.find("\tcase InputGZIP:")
end = source.find("\tcase InputVHD, InputVHDX, InputQCOW2, InputVMDK:", start)
if start < 0 or end < 0:
    raise SystemExit("sequential compression switch boundary is missing")
segment = source[start:end]
if segment.count(", progress)") != 5:
    raise SystemExit(
        f"sequential compression progress calls: expected 5 anchors, found {segment.count(', progress)')}"
    )
segment = segment.replace(", progress)", ", preparationProgress)")
path.write_text(source[:start] + segment + source[end:], encoding="utf-8")

replace_once(
    path,
    '''\tif !containerDigestBound {
\t\treturn cleanup(errors.New("image container authentication digest is unavailable"))
\t}

\traw, err := os.Open(rawPath)
''',
    '''\tif !containerDigestBound {
\t\treturn cleanup(errors.New("image container authentication digest is unavailable"))
\t}
\tif containerProgress != nil {
\t\tcontainerProgress.Complete()
\t}

\traw, err := os.Open(rawPath)
''',
    "authenticated compressed progress completion",
)
