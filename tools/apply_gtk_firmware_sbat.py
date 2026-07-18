from pathlib import Path


def replace_once(path, old, new):
    text = Path(path).read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected one replacement, found {text.count(old)}")
    Path(path).write_text(text.replace(old, new, 1), encoding="utf-8")


logic = "gui/rufusarm64_logic.py"
replace_once(logic,
'''    dbx_file="",
    firmware=False,
):
''',
'''    dbx_file="",
    firmware=False,
    sbat_level_file="",
    firmware_sbat=False,
):
''')
replace_once(logic,
'''    dbx_file = str(dbx_file or "").strip()
    if not helper:
''',
'''    dbx_file = str(dbx_file or "").strip()
    sbat_level_file = str(sbat_level_file or "").strip()
    if not helper:
''')
replace_once(logic,
'''    if dbx_file and firmware:
        raise ValueError("Choose either a local DBX file or the running firmware DBX, not both.")
    command = [
''',
'''    if dbx_file and firmware:
        raise ValueError("Choose either a local DBX file or the running firmware DBX, not both.")
    if sbat_level_file and firmware_sbat:
        raise ValueError("Choose either a local SBAT level or the running firmware SBAT level, not both.")
    command = [
''')
replace_once(logic,
'''    if dbx_file:
        command.extend(["--dbx", dbx_file])
    elif firmware:
        command.append("--firmware")
    command.append("--json")
''',
'''    if dbx_file:
        command.extend(["--dbx", dbx_file])
    elif firmware:
        command.append("--firmware")
    if sbat_level_file:
        command.extend(["--sbat-level", sbat_level_file])
    elif firmware_sbat:
        command.append("--firmware-sbat")
    command.append("--json")
''')
replace_once(logic,
'''            "x509_certificate_revoked": bool(item.get("x509_certificate_revoked")),
            "embedded_certificates": max(0, certificates),
            "sbat_records": sbat_count,
''',
'''            "x509_certificate_revoked": bool(item.get("x509_certificate_revoked")),
            "sbat_revoked": bool(item.get("sbat_revoked")),
            "sbat_revocations": list(item.get("sbat_revocations") or []),
            "embedded_certificates": max(0, certificates),
            "sbat_records": sbat_count,
''')
replace_once(logic,
'''        "dbx_checked": bool(payload.get("dbx_checked")),
        "valid": bool(payload.get("valid")),
        "revoked": bool(payload.get("revoked")),
''',
'''        "dbx_checked": bool(payload.get("dbx_checked")),
        "sbat_level_checked": bool(payload.get("sbat_level_checked")),
        "sbat_level_source": str(payload.get("sbat_level_source") or "").strip(),
        "sbat_level_datestamp": str(payload.get("sbat_level_datestamp") or "").strip(),
        "sbat_revoked": bool(payload.get("sbat_revoked")),
        "valid": bool(payload.get("valid")),
        "revoked": bool(payload.get("revoked")),
''')
replace_once(logic,
'''        f"DBX revocations checked: {'yes' if result['dbx_checked'] else 'no'}",
        f"EFI executables checked: {len(result['files'])}",
''',
'''        f"DBX revocations checked: {'yes' if result['dbx_checked'] else 'no'}",
        f"SBAT level checked: {'yes' if result['sbat_level_checked'] else 'no'}",
        f"EFI executables checked: {len(result['files'])}",
    ]
    if result["sbat_level_checked"]:
        lines.append(
            f"SBAT source: {result['sbat_level_source']}"
            + (f" (datestamp {result['sbat_level_datestamp']})" if result['sbat_level_datestamp'] else "")
        )
    lines.extend([
''')
replace_once(logic,
'''        status = "OK"
        if item["direct_hash_revoked"] or item["x509_certificate_revoked"]:
            status = "REVOKED"
''',
'''        status = "OK"
        if item["direct_hash_revoked"] or item["x509_certificate_revoked"] or item["sbat_revoked"]:
            status = "REVOKED"
''')
replace_once(logic,
'''        for warning in item["warnings"]:
            lines.append(f"  Warning: {warning}")
''',
'''        for revocation in item["sbat_revocations"]:
            if isinstance(revocation, dict):
                lines.append(
                    "  SBAT revoked: "
                    f"{revocation.get('component', 'unknown')} generation "
                    f"{revocation.get('image_generation', '?')} is below trusted minimum "
                    f"{revocation.get('minimum_generation', '?')}"
                )
        for warning in item["warnings"]:
            lines.append(f"  Warning: {warning}")
''')

ui = "gui/rufusarm64.py"
replace_once(ui,
'''        self.firmware.connect("toggled", self.firmware_toggled)
        grid.attach(self.firmware, 1, 4, 1, 1)
        self.firmware_toggled()

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
''',
'''        self.firmware.connect("toggled", self.firmware_toggled)
        grid.attach(self.firmware, 1, 4, 1, 1)
        self.firmware_toggled()

        self._attach_label(grid, "SBAT trust", 5)
        self.sbat_source = Gtk.ComboBoxText()
        self.sbat_source.append("none", "Do not compare against an SBAT level")
        self.sbat_source.append("local", "Use a trusted local SbatLevel CSV")
        self.sbat_source.append("firmware", "Use the running shim firmware SBAT level")
        saved_sbat_source = settings.get("uefi_validation_sbat_source", "none")
        if saved_sbat_source not in {"none", "local", "firmware"}:
            saved_sbat_source = "none"
        self.sbat_source.set_active_id(saved_sbat_source)
        self.sbat_source.connect("changed", self.sbat_source_changed)
        grid.attach(self.sbat_source, 1, 5, 1, 1)

        self._attach_label(grid, "Local SBAT level", 6)
        self.sbat_level = Gtk.FileChooserButton(
            title="Choose a trusted shim-compatible SbatLevel CSV",
            action=Gtk.FileChooserAction.OPEN,
        )
        sbat_filter = Gtk.FileFilter()
        sbat_filter.set_name("SBAT level CSV files")
        sbat_filter.add_pattern("*.csv")
        self.sbat_level.add_filter(sbat_filter)
        saved_sbat = settings.get("uefi_validation_sbat_level", "")
        if saved_sbat and os.path.isfile(saved_sbat):
            self.sbat_level.set_filename(saved_sbat)
        grid.attach(self.sbat_level, 1, 6, 1, 1)
        self.sbat_source_changed()

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
''')
replace_once(ui,
'''    def firmware_toggled(self, *_):
        self.dbx.set_sensitive(not self.running and not self.firmware.get_active())

    def on_delete_event(self, *_):
''',
'''    def firmware_toggled(self, *_):
        self.dbx.set_sensitive(not self.running and not self.firmware.get_active())

    def sbat_source_changed(self, *_):
        source = self.sbat_source.get_active_id() or "none"
        self.sbat_level.set_sensitive(not self.running and source == "local")

    def on_delete_event(self, *_):
''')
replace_once(ui,
'''        self.firmware.set_sensitive(not self.running)
        self.firmware_toggled()
        if self.running:
''',
'''        self.firmware.set_sensitive(not self.running)
        self.sbat_source.set_sensitive(not self.running)
        self.firmware_toggled()
        self.sbat_source_changed()
        if self.running:
''')
replace_once(ui,
'''                self.dbx.get_filename() or "",
                self.firmware.get_active(),
            )
''',
'''                self.dbx.get_filename() or "",
                self.firmware.get_active(),
                self.sbat_level.get_filename() or "" if (self.sbat_source.get_active_id() == "local") else "",
                self.sbat_source.get_active_id() == "firmware",
            )
''')
replace_once(ui,
'''        self.settings["uefi_validation_dbx"] = self.dbx.get_filename() or ""
        self.settings["uefi_validation_firmware"] = self.firmware.get_active()
''',
'''        self.settings["uefi_validation_dbx"] = self.dbx.get_filename() or ""
        self.settings["uefi_validation_firmware"] = self.firmware.get_active()
        self.settings["uefi_validation_sbat_source"] = self.sbat_source.get_active_id() or "none"
        self.settings["uefi_validation_sbat_level"] = self.sbat_level.get_filename() or ""
''')
replace_once(ui,
'''        self.status.set_text("Validating EFI executables, fallback loader, SBAT metadata, and optional DBX revocations…")
''',
'''        self.status.set_text("Validating EFI executables, fallback loader, SBAT metadata, and selected trust policies…")
''')

tests = "gui/test_logic.py"
replace_once(tests,
'''        with self.assertRaises(ValueError):
            build_uefi_validate_command("/helper", "/mnt/usb", max_files=4097)
''',
'''        with self.assertRaises(ValueError):
            build_uefi_validate_command("/helper", "/mnt/usb", max_files=4097)
        firmware_sbat = build_uefi_validate_command(
            "/helper", "/mnt/usb", firmware_sbat=True
        )
        self.assertIn("--firmware-sbat", firmware_sbat)
        local_sbat = build_uefi_validate_command(
            "/helper", "/mnt/usb", sbat_level_file="/trust/SbatLevel.csv"
        )
        self.assertEqual(local_sbat[local_sbat.index("--sbat-level") + 1], "/trust/SbatLevel.csv")
        with self.assertRaises(ValueError):
            build_uefi_validate_command(
                "/helper", "/mnt/usb", sbat_level_file="local.csv", firmware_sbat=True
            )
''')
replace_once(tests,
'''            "dbx_checked": True,
            "valid": True,
''',
'''            "dbx_checked": True,
            "sbat_level_checked": True,
            "sbat_level_source": "/sys/firmware/efi/efivars/SbatLevelRT-605dab50-e046-4300-abb6-3dd810dd8b23",
            "sbat_level_datestamp": "2025051000",
            "valid": True,
''')
replace_once(tests,
'''                "sbat": [{"component": "shim"}],
            }],
''',
'''                "sbat": [{"component": "shim"}],
                "sbat_revoked": True,
                "sbat_revocations": [{
                    "component": "shim",
                    "image_generation": 3,
                    "minimum_generation": 4,
                }],
            }],
''')
replace_once(tests,
'''        self.assertIn("BOOTAA64.EFI", summary)
        self.assertIn("does not prove", summary)
''',
'''        self.assertIn("BOOTAA64.EFI", summary)
        self.assertIn("SBAT source:", summary)
        self.assertIn("SBAT revoked: shim generation 3", summary)
        self.assertIn("does not prove", summary)
''')

readme = "README.md"
replace_once(readme,
'''The single visible graphical application entry supplies the ordinary writer and the persistent-live action while retaining separate guarded helpers internally. The main window also provides a read-only **Validate UEFI Media…** dialog for mounted or extracted media; it reports fallback-loader, PE/EFI, SBAT, and optional DBX results without changing the write path.
''',
'''The single visible graphical application entry supplies the ordinary writer and the persistent-live action while retaining separate guarded helpers internally. The main window also provides a read-only **Validate UEFI Media…** dialog for mounted or extracted media; it reports fallback-loader, PE/EFI, DBX, and SBAT results, and can compare against either a trusted local SbatLevel CSV or the running shim firmware SBAT level without changing the write path.
''')

parity = "docs/upstream-rufus-parity.json"
replace_once(parity,
'''"notes": "The 0.11 development line exposes descriptor-rooted CLI and GTK validation of fallback loaders, PE architecture and EFI subsystem fields, bounded SBAT metadata, optional DBX hash/certificate revocations, and shim-compatible comparison against an explicitly supplied trusted local SbatLevel. Firmware SbatLevel acquisition and complete boot-chain reference resolution remain planned."
''',
'''"notes": "The 0.11 development line exposes descriptor-rooted CLI and GTK validation of fallback loaders, PE architecture and EFI subsystem fields, bounded SBAT metadata, optional DBX hash/certificate revocations, and shim-compatible comparison against a trusted local or running-firmware SbatLevel. Complete boot-chain reference resolution remains planned."
''')
