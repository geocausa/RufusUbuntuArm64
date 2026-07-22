from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


tree_path = Path("internal/runtimeintegrity/tree_linux.go")
tree = tree_path.read_text()

tree = replace_once(
    tree,
    "type hashedEntry struct {\n\tEntry\n\tidentity fileIdentity\n}\n",
    "type treeSnapshot struct {\n\tmanifestIdentity fileIdentity\n}\n\ntype hashedEntry struct {\n\tEntry\n\tidentity fileIdentity\n}\n",
    "tree snapshot type",
)
tree = replace_once(
    tree,
    "enumerateTree(ctx, root, opts, hook, false)",
    "enumerateTree(ctx, root, opts, hook, false, nil)",
    "generate enumerate call",
)
tree = replace_once(
    tree,
    "func verify(ctx context.Context, root string, opts Options, hook treeHook) (VerificationResult, error) {\n\tresolved, rootFile, rootIdentity, entries, total, err := enumerateTree(ctx, root, opts, hook, true)",
    "func verify(ctx context.Context, root string, opts Options, hook treeHook) (VerificationResult, error) {\n\tvar snapshot treeSnapshot\n\tresolved, rootFile, rootIdentity, entries, total, err := enumerateTree(ctx, root, opts, hook, true, &snapshot)",
    "verify enumerate call",
)
tree = replace_once(
    tree,
    "\tdefer rootFile.Close()\n\tmanifestData, err := readManifest(rootFile)\n",
    "\tdefer rootFile.Close()\n\tif hook != nil {\n\t\thook(\"manifest-before-open\", ManifestName)\n\t}\n\tmanifestData, err := readManifest(rootFile, snapshot.manifestIdentity)\n",
    "verify manifest open",
)
tree = replace_once(
    tree,
    "func enumerateTree(ctx context.Context, root string, opts Options, hook treeHook, requireManifest bool) (string, *os.File, fileIdentity, []treeEntry, uint64, error) {",
    "func enumerateTree(ctx context.Context, root string, opts Options, hook treeHook, requireManifest bool, snapshot *treeSnapshot) (string, *os.File, fileIdentity, []treeEntry, uint64, error) {",
    "enumerate tree signature",
)
tree = replace_once(
    tree,
    "enumerateDirectory(ctx, rootFile, \"\", maxFiles, hook, &entries, &total, &manifestCount)",
    "enumerateDirectory(ctx, rootFile, \"\", maxFiles, hook, &entries, &total, &manifestCount, snapshot)",
    "root enumerate directory call",
)
tree = replace_once(
    tree,
    "func enumerateDirectory(ctx context.Context, directory *os.File, prefix string, maxFiles int, hook treeHook, entries *[]treeEntry, total *uint64, manifestCount *int) error {",
    "func enumerateDirectory(ctx context.Context, directory *os.File, prefix string, maxFiles int, hook treeHook, entries *[]treeEntry, total *uint64, manifestCount *int, snapshot *treeSnapshot) error {",
    "enumerate directory signature",
)
tree = replace_once(
    tree,
    "enumerateDirectory(ctx, child, relative, maxFiles, hook, entries, total, manifestCount)",
    "enumerateDirectory(ctx, child, relative, maxFiles, hook, entries, total, manifestCount, snapshot)",
    "recursive enumerate directory call",
)
tree = replace_once(
    tree,
    "\t\tif prefix == \"\" && strings.EqualFold(name, ManifestName) {\n\t\t\t*manifestCount++\n\t\t\tif name != ManifestName {\n\t\t\t\treturn fmt.Errorf(\"root manifest name %q must use exact lowercase spelling %q\", name, ManifestName)\n\t\t\t}\n\t\t\tcontinue\n\t\t}\n",
    "\t\tif prefix == \"\" && strings.EqualFold(name, ManifestName) {\n\t\t\t*manifestCount++\n\t\t\tif name != ManifestName {\n\t\t\t\treturn fmt.Errorf(\"root manifest name %q must use exact lowercase spelling %q\", name, ManifestName)\n\t\t\t}\n\t\t\tif snapshot != nil {\n\t\t\t\tidentity, identityErr := identityFromInfo(info)\n\t\t\t\tif identityErr != nil {\n\t\t\t\t\treturn identityErr\n\t\t\t\t}\n\t\t\t\tsnapshot.manifestIdentity = identity\n\t\t\t}\n\t\t\tcontinue\n\t\t}\n",
    "manifest snapshot capture",
)
tree = replace_once(
    tree,
    "func readManifest(root *os.File) ([]byte, error) {\n\tfd, err := syscall.Openat(int(root.Fd()), ManifestName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)",
    "func readManifest(root *os.File, expected fileIdentity) ([]byte, error) {\n\tfd, err := syscall.Openat(int(root.Fd()), ManifestName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)",
    "manifest read signature",
)
tree = replace_once(
    tree,
    "\tbefore, err := identityFromOpenFile(file)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tif before.mode&syscall.S_IFMT != syscall.S_IFREG || before.size <= 0 || before.size > MaximumManifestSize {",
    "\tbefore, err := identityFromOpenFile(file)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tif !sameStableObject(expected, before) {\n\t\treturn nil, fmt.Errorf(\"%s changed between enumeration and read\", ManifestName)\n\t}\n\tif before.mode&syscall.S_IFMT != syscall.S_IFREG || before.size <= 0 || before.size > MaximumManifestSize {",
    "manifest initial identity",
)
tree = replace_once(
    tree,
    "\tif !sameStableObject(before, after) || int64(len(data)) != before.size {\n\t\treturn nil, fmt.Errorf(\"%s changed while it was being read\", ManifestName)\n\t}",
    "\tif !sameStableObject(expected, after) || !sameStableObject(before, after) || int64(len(data)) != before.size {\n\t\treturn nil, fmt.Errorf(\"%s changed while it was being read\", ManifestName)\n\t}",
    "manifest final identity",
)
tree_path.write_text(tree)

transaction_path = Path("internal/runtimeintegrity/transaction_linux.go")
transaction = transaction_path.read_text()
transaction = replace_once(
    transaction,
    "\tmanifestCount := 0\n\tif err := enumerateDirectory(ctx, scan, \"\", maxFiles, nil, &entries, &total, &manifestCount); err != nil {\n\t\treturn Manifest{}, err\n\t}\n\tif manifestCount != 0 {",
    "\tmanifestCount := 0\n\tif err := enumerateDirectory(ctx, scan, \"\", maxFiles, nil, &entries, &total, &manifestCount, nil); err != nil {\n\t\treturn Manifest{}, err\n\t}\n\tif manifestCount != 0 {",
    "transaction generation enumeration",
)
transaction = replace_once(
    transaction,
    "\tvar entries []treeEntry\n\tvar total uint64\n\tmanifestCount := 0\n\tif err := enumerateDirectory(ctx, scan, \"\", maxFiles, nil, &entries, &total, &manifestCount); err != nil {\n\t\treturn VerificationResult{}, err\n\t}\n\tif manifestCount != 1 {\n\t\treturn VerificationResult{}, errors.New(\"installed media must contain exactly one root md5sum.txt\")\n\t}\n\tmanifestData, err := readManifest(scan)",
    "\tvar entries []treeEntry\n\tvar total uint64\n\tvar snapshot treeSnapshot\n\tmanifestCount := 0\n\tif err := enumerateDirectory(ctx, scan, \"\", maxFiles, nil, &entries, &total, &manifestCount, &snapshot); err != nil {\n\t\treturn VerificationResult{}, err\n\t}\n\tif manifestCount != 1 {\n\t\treturn VerificationResult{}, errors.New(\"installed media must contain exactly one root md5sum.txt\")\n\t}\n\tmanifestData, err := readManifest(scan, snapshot.manifestIdentity)",
    "transaction verification manifest",
)
transaction_path.write_text(transaction)
