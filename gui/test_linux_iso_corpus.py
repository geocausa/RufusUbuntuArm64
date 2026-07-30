import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "linux_iso_corpus.py"
SPEC = importlib.util.spec_from_file_location("linux_iso_corpus_test", SCRIPT)
CORPUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORPUS)


class LinuxISOCorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.helper = self.root / "helper"
        self.helper.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                from pathlib import Path
                import sys

                path = Path(sys.argv[sys.argv.index("--image") + 1])
                data = path.read_bytes()
                if data[:4] == b"hsqs":
                    print("error: image is not usable: the selected file is a recognized SquashFS filesystem image but not a complete ISOHybrid, GPT, or MBR disk image", file=sys.stderr)
                    raise SystemExit(1)
                if b"RufusArm64 corpus: deliberately unrecognized input" in data:
                    print("error: image is not usable: the selected file is not a recognized ISOHybrid, GPT, MBR, or supported direct-filesystem image", file=sys.stderr)
                    raise SystemExit(1)
                has_mbr = len(data) >= 512 and data[510:512] == b"\\x55\\xaa"
                has_iso = any(
                    len(data) >= (sector + 1) * 2048
                    and data[sector * 2048] == 1
                    and data[sector * 2048 + 1 : sector * 2048 + 6] == b"CD001"
                    and data[sector * 2048 + 6] == 1
                    for sector in range(16, 65)
                )
                recognized = has_mbr or has_iso
                print(json.dumps({
                    "mode": "raw" if recognized else "unknown",
                    "recognized": recognized,
                    "partition_scheme": "From image" if recognized else "",
                    "target_system": "From image" if recognized else "",
                    "filesystem": "From image" if recognized else "",
                    "windows_options": False,
                    "description": "Raw/ISOHybrid image; embedded layout will be preserved" if recognized else "Unknown",
                    "container_format": "plain",
                }))
                """
            ),
            encoding="utf-8",
        )
        self.helper.chmod(self.helper.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def synthetic_entry(identifier, filename, generator, size, digest, decision, profile=None, refusal=None):
        expected = {"decision": decision}
        if profile is not None:
            expected["profile"] = profile
        if refusal is not None:
            expected["refusal_contains"] = refusal
        return {
            "id": identifier,
            "family": "Synthetic",
            "architecture": "fixture",
            "filename": filename,
            "qualification_state": "qualified",
            "source": {"kind": "synthetic", "project": "RufusArm64", "generator": generator},
            "size": size,
            "sha256": digest,
            "expected": expected,
        }

    def test_manifest_tracks_required_distribution_families(self):
        manifest = CORPUS.load_manifest(ROOT / "docs" / "linux-iso-corpus.json")
        families = {entry["family"] for entry in manifest["entries"]}
        for family in (
            "Ubuntu",
            "Debian",
            "Linux Mint",
            "Fedora",
            "Bazzite",
            "Nobara",
            "openSUSE",
            "Nutanix",
            "umbrelOS",
        ):
            self.assertIn(family, families)
        ubuntu = next(entry for entry in manifest["entries"] if entry["id"] == "ubuntu-26.04-desktop-arm64")
        self.assertEqual(ubuntu["qualification_state"], "qualified")
        self.assertEqual(ubuntu["expected"]["decision"], "iso-image-candidate")
        self.assertEqual(len(ubuntu["sha256"]), 64)

    def test_synthetic_candidate_dd_and_refusal_boundaries(self):
        entries = [
            self.synthetic_entry(
                "uefi",
                "uefi.iso",
                "hybrid-uefi-grub-v1",
                262144,
                "9902415b789c26c6255a77fd337557db7d9959dd5864332f5b96f02348370b94",
                "iso-image-candidate",
                {
                    "write_path": "hybrid-direct-write",
                    "hybrid": True,
                    "boot_methods": ["UEFI"],
                    "bootloaders": ["GRUB"],
                },
            ),
            self.synthetic_entry(
                "optical-uefi",
                "optical-uefi.iso",
                "optical-uefi-grub-v1",
                262144,
                "408e120504b52e6a23995cfd53e9f70d833dfab23f9acff7201d8d8ee5dca676",
                "iso-image-candidate",
                {
                    "write_path": "optical-direct-write",
                    "hybrid": False,
                    "optical": True,
                    "boot_methods": ["UEFI"],
                    "bootloaders": ["GRUB"],
                },
            ),
            self.synthetic_entry(
                "bios",
                "bios.iso",
                "hybrid-bios-isolinux-v1",
                262144,
                "2e605f0b7cbf004faff39355c1b8b81e09e5c9c8a466616db351b9d7ae04a8cd",
                "dd-only",
                {
                    "write_path": "hybrid-direct-write",
                    "hybrid": True,
                    "boot_methods": ["BIOS"],
                    "bootloaders": ["ISOLINUX"],
                },
            ),
            self.synthetic_entry(
                "squashfs",
                "bare.img",
                "bare-squashfs-v1",
                4096,
                "719cbc3103ceb5bda7ee7837616e3a7a0fb531bcd07160aa8a6d0fd1e96d822d",
                "refuse",
                refusal="recognized SquashFS filesystem image",
            ),
        ]
        manifest = {"schema": 1, "corpus_version": "test", "entries": entries}
        CORPUS.validate_manifest(manifest)
        report = CORPUS.run_corpus(manifest, [], self.helper, False)
        self.assertTrue(report["passed"], json.dumps(report, indent=2))
        self.assertEqual(
            [result["decision"] for result in report["results"]],
            ["iso-image-candidate", "iso-image-candidate", "dd-only", "refuse"],
        )

    def test_pending_missing_requires_explicit_allowance(self):
        entry = {
            "id": "pending",
            "family": "Pending",
            "architecture": "arm64",
            "filename": "missing.iso",
            "qualification_state": "pending",
            "source": {"kind": "official", "project": "Example", "url": "https://example.invalid/"},
        }
        manifest = {"schema": 1, "corpus_version": "test", "entries": [entry]}
        denied = CORPUS.run_corpus(manifest, [self.root], self.helper, False)
        allowed = CORPUS.run_corpus(manifest, [self.root], self.helper, True)
        self.assertFalse(denied["passed"])
        self.assertTrue(allowed["passed"])
        self.assertEqual(allowed["results"][0]["status"], "missing")

    def test_qualified_hash_mismatch_fails_before_claiming_success(self):
        image = self.root / "candidate.iso"
        CORPUS.materialize_fixture("hybrid-uefi-grub-v1", image)
        entry = self.synthetic_entry(
            "candidate",
            image.name,
            "hybrid-uefi-grub-v1",
            image.stat().st_size,
            "0" * 64,
            "iso-image-candidate",
        )
        entry["source"] = {"kind": "official", "project": "Fixture", "url": "https://example.invalid/"}
        manifest = {"schema": 1, "corpus_version": "test", "entries": [entry]}
        report = CORPUS.run_corpus(manifest, [self.root], self.helper, False)
        self.assertFalse(report["passed"])
        self.assertIn("sha256 expected", report["results"][0]["failures"][0])

    def test_bound_pending_partial_is_rejected_before_inspection(self):
        image = self.root / "pending.iso"
        image.write_bytes(b"partial download with a plausible filename")
        entry = {
            "id": "pending-bound",
            "family": "Pending",
            "architecture": "arm64",
            "filename": image.name,
            "qualification_state": "pending",
            "source": {"kind": "official", "project": "Example", "url": "https://example.invalid/"},
            "size": 4096,
            "sha256": "0" * 64,
        }
        manifest = {"schema": 1, "corpus_version": "test", "entries": [entry]}
        CORPUS.validate_manifest(manifest)
        report = CORPUS.run_corpus(manifest, [self.root], self.helper, True)
        result = report["results"][0]
        self.assertFalse(report["passed"])
        self.assertFalse(result["passed"])
        self.assertNotIn("inspection", result)
        self.assertTrue(any(failure.startswith("size expected") for failure in result["failures"]))
        self.assertNotIn("sha256", result)

    def test_manifest_rejects_duplicate_ids_and_unbound_qualified_entries(self):
        base = {
            "id": "same",
            "family": "Example",
            "architecture": "arm64",
            "filename": "example.iso",
            "qualification_state": "pending",
            "source": {"kind": "official", "project": "Example", "url": "https://example.invalid/"},
        }
        with self.assertRaisesRegex(CORPUS.CorpusError, "duplicate corpus id"):
            CORPUS.validate_manifest(
                {"schema": 1, "corpus_version": "test", "entries": [base, dict(base, filename="other.iso")]}
            )
        qualified = dict(base, qualification_state="qualified", size=1, sha256="bad", expected={"decision": "refuse"})
        with self.assertRaisesRegex(CORPUS.CorpusError, "qualified sha256"):
            CORPUS.validate_manifest({"schema": 1, "corpus_version": "test", "entries": [qualified]})


if __name__ == "__main__":
    unittest.main()
