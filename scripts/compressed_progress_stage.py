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

replace_once(
    path,
    '''\tcase InputGZIP:
\t\trawDigest, err = prepareStream(ctx, preparationReader, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
\t\t\tdecoder, openErr := gzip.NewReader(r)
\t\t\treturn decoder, decoder, openErr
\t\t}, progress)
''',
    '''\tcase InputGZIP:
\t\trawDigest, err = prepareStream(ctx, preparationReader, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
\t\t\tdecoder, openErr := gzip.NewReader(r)
\t\t\treturn decoder, decoder, openErr
\t\t}, preparationProgress)
''',
    "gzip preparation progress",
)
replace_once(
    path,
    '''\tcase InputBZIP2:
\t\trawDigest, err = prepareStream(ctx, preparationReader, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
\t\t\treturn bzip2.NewReader(r), nil, nil
\t\t}, progress)
''',
    '''\tcase InputBZIP2:
\t\trawDigest, err = prepareStream(ctx, preparationReader, rawPath, options.MaxPreparedSize, func(r io.Reader) (io.Reader, io.Closer, error) {
\t\t\treturn bzip2.NewReader(r), nil, nil
\t\t}, preparationProgress)
''',
    "bzip2 preparation progress",
)
for label, old in (
    (
        "xz preparation progress",
        '\t\trawDigest, err = prepareExternalDecompress(ctx, preparationReader, rawPath, "xz", []string{"--decompress", "--stdout"}, options.MaxPreparedSize, progress)',
    ),
    (
        "lzma preparation progress",
        '\t\trawDigest, err = prepareExternalDecompress(ctx, preparationReader, rawPath, "xz", []string{"--format=lzma", "--decompress", "--stdout"}, options.MaxPreparedSize, progress)',
    ),
    (
        "zstd preparation progress",
        '\t\trawDigest, err = prepareExternalDecompress(ctx, preparationReader, rawPath, "zstd", []string{"--decompress", "--stdout", "--quiet"}, options.MaxPreparedSize, progress)',
    ),
):
    replace_once(path, old, old[:-len("progress)")] + "preparationProgress)", label)

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
