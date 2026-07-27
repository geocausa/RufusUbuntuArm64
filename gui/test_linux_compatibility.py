import ast
import os
import pathlib
import struct
import tempfile
import unittest


class LinuxCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source_path = pathlib.Path(__file__).with_name("rufusarm64_integrated.py")
        cls.source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(cls.source)
        names = {
            "ISO_SECTOR_SIZE",
            "FIRST_ISO_DESCRIPTOR",
            "LAST_ISO_DESCRIPTOR",
            "MAX_BOOT_CATALOGUE_BYTES",
            "MAX_BOOT_IMAGE_PROBE_BYTES",
            "MAX_BOOT_ENTRIES",
            "_read_at",
            "_has_disk_layout",
            "_iso_boot_catalogue",
            "_valid_catalogue_validation",
            "_platform_name",
            "_catalogue_boot_entries",
            "_bootloader_fingerprints",
            "_snapshot_from_metadata",
            "_source_snapshot",
            "linux_compatibility_profile",
            "enrich_linux_inspection",
            "install_linux_compatibility",
        }
        body = []
        for node in tree.body:
            if isinstance(node, ast.Import) and any(alias.name in {"os", "stat", "struct"} for alias in node.names):
                body.append(node)
            elif isinstance(node, ast.Assign):
                targets = {target.id for target in node.targets if isinstance(target, ast.Name)}
                if targets & names:
                    body.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in names:
                body.append(node)
        namespace = {}
        exec(compile(ast.Module(body=body, type_ignores=[]), str(source_path), "exec"), namespace)
        cls.profile = staticmethod(namespace["linux_compatibility_profile"])
        cls.enrich = staticmethod(namespace["enrich_linux_inspection"])
        cls.snapshot = staticmethod(namespace["_source_snapshot"])
        cls.install = staticmethod(namespace["install_linux_compatibility"])

    @staticmethod
    def _catalogue_validation(platform=0):
        entry = bytearray(32)
        entry[0] = 1
        entry[1] = platform
        entry[30:32] = b"\x55\xaa"
        words = list(struct.unpack("<16H", entry))
        words[14] = (-sum(words)) & 0xFFFF
        return struct.pack("<16H", *words)

    @classmethod
    def _write_iso(cls, path, *, hybrid=True, valid_catalogue=True, optical=True):
        data = bytearray(256 * 1024)
        if hybrid:
            data[510:512] = b"\x55\xaa"
            data[446 + 4] = 0x17
            struct.pack_into("<I", data, 446 + 8, 1)
            struct.pack_into("<I", data, 446 + 12, 100)
        if optical:
            boot = 16 * 2048
            data[boot] = 0
            data[boot + 1 : boot + 6] = b"CD001"
            data[boot + 6] = 1
            data[boot + 7 : boot + 7 + len(b"EL TORITO SPECIFICATION")] = b"EL TORITO SPECIFICATION"
            struct.pack_into("<I", data, boot + 71, 20)
            primary = 17 * 2048
            data[primary] = 1
            data[primary + 1 : primary + 6] = b"CD001"
            data[primary + 6] = 1
            terminator = 18 * 2048
            data[terminator] = 255
            data[terminator + 1 : terminator + 6] = b"CD001"
            data[terminator + 6] = 1

            catalogue = 20 * 2048
            validation = bytearray(cls._catalogue_validation(0))
            if not valid_catalogue:
                validation[4] ^= 0x01
            data[catalogue : catalogue + 32] = validation
            data[catalogue + 32] = 0x88
            struct.pack_into("<I", data, catalogue + 32 + 8, 30)
            data[catalogue + 64] = 0x91
            data[catalogue + 65] = 0xEF
            data[catalogue + 66] = 1
            data[catalogue + 96] = 0x88
            struct.pack_into("<I", data, catalogue + 96 + 8, 40)
            data[30 * 2048 : 30 * 2048 + 8] = b"ISOLINUX"
            data[40 * 2048 : 40 * 2048 + 4] = b"GRUB"
        path.write_bytes(data)

    @staticmethod
    def _inspection(**updates):
        value = {
            "recognized": True,
            "mode": "raw",
            "container_format": "plain",
            "description": "Raw/ISOHybrid image; embedded layout will be preserved",
        }
        value.update(updates)
        return value

    def test_hybrid_dual_firmware_catalogue_and_bootloaders(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "dual.iso"
            self._write_iso(path)
            profile = self.profile(path, self._inspection())
        self.assertEqual(profile["write_path"], "hybrid-direct-write")
        self.assertEqual(profile["boot_methods"], ["BIOS", "UEFI"])
        self.assertEqual(profile["bootloaders"], ["GRUB", "ISOLINUX"])
        self.assertTrue(profile["hybrid"])
        self.assertIn("preserves its partition and boot structures byte-for-byte", profile["summary"])
        self.assertIn("does not prove", profile["summary"])

    def test_optical_only_media_explains_firmware_usb_cd_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "optical.iso"
            self._write_iso(path, hybrid=False)
            profile = self.profile(path, self._inspection())
        self.assertEqual(profile["write_path"], "optical-direct-write")
        self.assertFalse(profile["hybrid"])
        self.assertIn("USB-CD emulation", profile["summary"])

    def test_invalid_catalogue_is_not_reported_as_a_boot_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "invalid.iso"
            self._write_iso(path, valid_catalogue=False)
            profile = self.profile(path, self._inspection())
        self.assertEqual(profile["boot_methods"], [])
        self.assertEqual(profile["bootloaders"], [])
        self.assertIn("No valid El Torito", profile["summary"])

    def test_raw_disk_layout_is_reported_without_optical_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "disk.img"
            self._write_iso(path, optical=False)
            profile = self.profile(path, self._inspection())
        self.assertEqual(profile["write_path"], "raw-direct-write")
        self.assertFalse(profile["optical"])
        self.assertEqual(profile["boot_methods"], [])

    def test_non_raw_or_prepared_inputs_are_left_to_existing_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "input.gz"
            path.write_bytes(b"not opened")
            self.assertEqual(self.profile(path, self._inspection(mode="windows")), {})
            self.assertEqual(self.profile(path, self._inspection(needs_preparation=True, container_format="gzip")), {})

    def test_enrichment_is_idempotent_and_retains_existing_description(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "dual.iso"
            self._write_iso(path)
            original = self._inspection()
            snapshot = self.snapshot(path)
            enriched = self.enrich(path, original, snapshot)
            repeated = self.enrich(path, enriched, snapshot)
        self.assertIsNot(enriched, original)
        self.assertIs(repeated, enriched)
        self.assertIn(original["description"], enriched["description"])
        self.assertIn("compatibility_profile", enriched)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_retargeted_symlink_cannot_reuse_an_inspection_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first.iso"
            second = root / "second.iso"
            selected = root / "selected.iso"
            self._write_iso(first)
            self._write_iso(second, hybrid=False)
            selected.symlink_to(first)
            snapshot = self.snapshot(selected)
            selected.unlink()
            selected.symlink_to(second)
            self.assertEqual(self.profile(selected, self._inspection(), snapshot), {})

    def test_in_place_mutation_cannot_reuse_an_inspection_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "dual.iso"
            self._write_iso(path)
            snapshot = self.snapshot(path)
            with path.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"changed!")
                handle.flush()
                os.fsync(handle.fileno())
            self.assertEqual(self.profile(path, self._inspection(), snapshot), {})

    def test_window_discards_helper_result_when_source_changes_during_inspection(self):
        class Chooser:
            def __init__(self, path):
                self.path = str(path)

            def get_filename(self):
                return self.path

        class Window:
            def __init__(self, path):
                self.image_chooser = Chooser(path)
                self.closed = False
                self.inspection_generation = 1
                self.inspection = {}
                self.busy = False
                self.logs = []

            def _run_image_inspection(self, _path, _generation):
                return None

            def _finish_image_inspection(self, _path, _generation, inspection):
                self.inspection = inspection
                return False

            def update_layout(self, _inspection):
                return None

            def set_busy(self, _busy):
                return None

            def append_log(self, text):
                self.logs.append(text)

        self.install(Window)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "dual.iso"
            self._write_iso(path)
            window = Window(path)
            window._run_image_inspection(str(path), 1)
            path.write_bytes(b"replacement")
            window._finish_image_inspection(str(path), 1, self._inspection())
        self.assertFalse(window.inspection["recognized"])
        self.assertIn("changed while", window.inspection["description"])
        self.assertTrue(any("discarded" in line for line in window.logs))

    def test_source_boundary_is_read_only_bounded_and_installed(self):
        self.assertIn("MAX_BOOT_CATALOGUE_BYTES = 2048", self.source)
        self.assertIn("MAX_BOOT_IMAGE_PROBE_BYTES = 64 * 1024", self.source)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', self.source)
        self.assertIn('getattr(os, "O_NONBLOCK", 0)', self.source)
        self.assertIn("stat.S_ISREG", self.source)
        self.assertIn("_snapshot_from_metadata(resolved, os.fstat(descriptor))", self.source)
        self.assertIn("window_class._run_image_inspection = integrated_run_image_inspection", self.source)
        self.assertIn("install_linux_compatibility(RufusWindow)", self.source)
        self.assertNotIn("subprocess", self.source)
        self.assertNotIn("mount", self.source.lower())
        self.assertNotIn("pkexec", self.source.lower())


if __name__ == "__main__":
    unittest.main()
