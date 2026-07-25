#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} anchor count is {count}, expected 1")
    return text.replace(old, new, 1)


logic = Path("gui/rufusarm64_logic.py")
text = logic.read_text()
text = replace_once(
    text,
    '''    trust_activation = _ffu_sha256(
        payload.get("trust_activation_sha256"), "trust activation"
    )
    descriptor_digest = _ffu_sha256(
''',
    '''    trust_activation = _ffu_sha256(
        payload.get("trust_activation_sha256"), "trust activation"
    )
    trust_store_root = _ffu_absolute_path(payload.get("trust_store_root"), "trust store")
    trust_generation = str(payload.get("trust_generation") or "").strip()
    if not trust_generation:
        raise ValueError("The FFU review returned an invalid trust generation.")
    trust_sequence = _ffu_positive_int(payload, "trust_sequence", "trust sequence")
    trust_bundle = _ffu_sha256(payload.get("trust_bundle_sha256"), "trust bundle")
    metadata_policy_path = _ffu_absolute_path(
        payload.get("trust_metadata_policy_path"), "trust-metadata policy"
    )
    publisher_policy_path = _ffu_absolute_path(
        payload.get("publisher_policy_path"), "publisher policy"
    )
    review_binding = _ffu_sha256(payload.get("review_binding_sha256"), "review binding")
    descriptor_digest = _ffu_sha256(
''',
    "stable review binding fields",
)
text = replace_once(
    text,
    '''    source_identity = _ffu_mapping(payload.get("source_identity"), "source identity")
    source_size = _ffu_positive_int(source_identity, "Size", "source identity size")
    for key, label in (("Device", "source device"), ("Inode", "source inode")):
        _ffu_positive_int(source_identity, key, label)
    for key, label in (("ModifiedNS", "source modification time"), ("ChangedNS", "source change time")):
        _ffu_positive_int(source_identity, key, label, allow_zero=True)

    target = _ffu_mapping(payload.get("target_plan"), "target plan")
''',
    '''    source_identity = _ffu_mapping(payload.get("source_identity"), "source identity")
    source_size = _ffu_positive_int(source_identity, "Size", "source identity size")
    policy_identities = (
        (source_identity, "source"),
        (_ffu_mapping(payload.get("trust_metadata_policy_identity"), "trust-metadata policy identity"), "trust-metadata policy"),
        (_ffu_mapping(payload.get("publisher_policy_identity"), "publisher policy identity"), "publisher policy"),
    )
    for identity, label in policy_identities:
        _ffu_positive_int(identity, "Size", f"{label} identity size")
        for key, field in (("Device", "device"), ("Inode", "inode")):
            _ffu_positive_int(identity, key, f"{label} {field}")
        for key, field in (("ModifiedNS", "modification time"), ("ChangedNS", "change time")):
            _ffu_positive_int(identity, key, f"{label} {field}", allow_zero=True)

    target = _ffu_mapping(payload.get("target_plan"), "target plan")
''',
    "policy identity normalization",
)
text = replace_once(
    text,
    '''        "trust_activation_sha256": trust_activation,
        "source_path": source_path,
''',
    '''        "trust_activation_sha256": trust_activation,
        "trust_store_root": trust_store_root,
        "trust_generation": trust_generation,
        "trust_sequence": trust_sequence,
        "trust_bundle_sha256": trust_bundle,
        "trust_metadata_policy_path": metadata_policy_path,
        "publisher_policy_path": publisher_policy_path,
        "review_binding_sha256": review_binding,
        "source_path": source_path,
''',
    "normalized stable binding output",
)
text = replace_once(
    text,
    '''        f"Planned changed bytes: {human_bytes(review['mutation_bytes'])}",
    ]
''',
    '''        f"Planned changed bytes: {human_bytes(review['mutation_bytes'])}",
        f"Reviewed-input binding: {review['review_binding_sha256']}",
        f"Trust generation: {review['trust_generation']} (sequence {review['trust_sequence']})",
    ]
''',
    "review binding summary",
)
logic.write_text(text)


tests = Path("gui/test_logic.py")
text = tests.read_text()
text = replace_once(
    text,
    '''        "trust_activation_sha256": "a" * 64,
        "source_path": "/images/device.ffu",
''',
    '''        "trust_activation_sha256": "a" * 64,
        "trust_store_root": "/var/lib/rufusarm64/ffu-trust",
        "trust_generation": "generation-1",
        "trust_sequence": 1,
        "trust_bundle_sha256": "1" * 64,
        "trust_metadata_policy_path": "/etc/rufusarm64/trust-metadata.json",
        "trust_metadata_policy_identity": {
            "Device": 5, "Inode": 6, "Size": 100, "ModifiedNS": 7, "ChangedNS": 8,
        },
        "publisher_policy_path": "/etc/rufusarm64/publishers.json",
        "publisher_policy_identity": {
            "Device": 9, "Inode": 10, "Size": 100, "ModifiedNS": 11, "ChangedNS": 12,
        },
        "review_binding_sha256": "2" * 64,
        "source_path": "/images/device.ffu",
''',
    "test stable binding fixture",
)
text = replace_once(
    text,
    '''        self.assertFalse(review["unmount_required"])
        summary = ffu_review_summary(payload)
''',
    '''        self.assertFalse(review["unmount_required"])
        self.assertEqual(review["review_binding_sha256"], "2" * 64)
        self.assertEqual(review["trust_generation"], "generation-1")
        summary = ffu_review_summary(payload)
''',
    "review binding assertion",
)
text = replace_once(
    text,
    '''        self.assertIn(payload["exact_confirmation_phrase"], summary)
        self.assertIn("read-only", summary)
''',
    '''        self.assertIn(payload["exact_confirmation_phrase"], summary)
        self.assertIn(payload["review_binding_sha256"], summary)
        self.assertIn("read-only", summary)
''',
    "review binding summary assertion",
)
text = replace_once(
    text,
    '''        changed = copy.deepcopy(payload)
        changed["execution_attempted"] = True
        mutations.append(changed)
''',
    '''        changed = copy.deepcopy(payload)
        changed["execution_attempted"] = True
        mutations.append(changed)
        changed = copy.deepcopy(payload)
        changed["review_binding_sha256"] = "A" * 64
        mutations.append(changed)
        changed = copy.deepcopy(payload)
        changed["publisher_policy_identity"]["Inode"] = 0
        mutations.append(changed)
''',
    "binding substitution fixtures",
)
tests.write_text(text)


main = Path("gui/rufusarm64.py")
text = main.read_text()
text = replace_once(
    text,
    '''from rufusarm64_device_qualify_dialog import DeviceQualificationDialog
''',
    '''from rufusarm64_device_qualify_dialog import DeviceQualificationDialog
from rufusarm64_ffu_dialog import FFUReviewDialog
''',
    "FFU dialog import",
)
text = replace_once(
    text,
    '''        self.checksum_button.connect("clicked", self.open_checksum_dialog)
        image_row.pack_start(self.checksum_button, False, False, 0)
        grid.attach(image_row, 1, 0, 2, 1)
''',
    '''        self.checksum_button.connect("clicked", self.open_checksum_dialog)
        image_row.pack_start(self.checksum_button, False, False, 0)
        self.ffu_review_button = Gtk.Button(label="Review FFU…")
        self.ffu_review_button.set_sensitive(False)
        self.ffu_review_button.set_tooltip_text(
            "Authenticate a Full Flash Update and review the exact removable target without modifying it"
        )
        self.ffu_review_button.connect("clicked", self.open_ffu_review)
        image_row.pack_start(self.ffu_review_button, False, False, 0)
        grid.attach(image_row, 1, 0, 2, 1)
''',
    "FFU review button",
)
text = replace_once(
    text,
    '''        self.checksum_button.set_sensitive(
            not busy and background_idle and bool(selected_image) and os.path.isfile(selected_image)
        )
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
''',
    '''        self.checksum_button.set_sensitive(
            not busy and background_idle and bool(selected_image) and os.path.isfile(selected_image)
        )
        self.update_ffu_review_button()
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
''',
    "FFU button busy update",
)
text = replace_once(
    text,
    '''    def open_checksum_dialog(self, *_):
''',
    '''    def selected_ffu_review_inputs(self):
        image = self.image_chooser.get_filename() or ""
        index = self.target_combo.get_active()
        if self.busy or not image.lower().endswith(".ffu") or not os.path.isfile(image):
            return None
        if not (0 <= index < len(self.devices)):
            return None
        device = self.devices[index]
        required = (
            str(device.get("path") or ""),
            str(device.get("identity") or ""),
            int(device.get("size") or 0),
            int(device.get("logical_sector_size") or 0),
            int(device.get("physical_sector_size") or 0),
        )
        if not all(required):
            return None
        return image, device

    def update_ffu_review_button(self):
        if getattr(self, "ffu_review_button", None) is not None:
            self.ffu_review_button.set_sensitive(self.selected_ffu_review_inputs() is not None)

    def open_ffu_review(self, *_):
        selected = self.selected_ffu_review_inputs()
        if selected is None:
            self.message(
                "Choose a .ffu image and refresh/select a removable drive with complete identity and sector geometry first.",
                Gtk.MessageType.INFO,
            )
            return
        image, device = selected
        dialog = FFUReviewDialog(self, helper_path(), image, device)
        dialog.run()
        if dialog.running:
            return
        dialog.closed = True
        dialog.generation += 1
        dialog.destroy()

    def open_checksum_dialog(self, *_):
''',
    "FFU review window methods",
)
text = replace_once(
    text,
    '''        if getattr(self, "inspection", {}).get("recognized"):
            self.update_layout(self.inspection)
''',
    '''        self.update_ffu_review_button()
        if getattr(self, "inspection", {}).get("recognized"):
            self.update_layout(self.inspection)
''',
    "FFU selection sensitivity",
)
main.write_text(text)


source_test = Path("gui/test_source_structure.py")
text = source_test.read_text()
text = replace_once(
    text,
    '''            "rufusarm64.py": {
                "AcquisitionDialog": {
''',
    '''            "rufusarm64.py": {
                "AcquisitionDialog": {
''',
    "source test stable anchor",
)
# Add the new file/class beside existing slow-worker contracts.
text = replace_once(
    text,
    '''            "rufusarm64_persistence.py": {
''',
    '''            "rufusarm64_ffu_dialog.py": {
                "FFUReviewDialog": {
                    "start_review": ("threading.Thread(",),
                    "_run_review": ("subprocess.run(", "timeout=300"),
                    "_finish_review": ("generation != self.generation", "self.closed"),
                },
            },
            "rufusarm64_persistence.py": {
''',
    "FFU dialog worker contract",
)
text = replace_once(
    text,
    '''                    if method_name in {"verify_catalog", "image_changed", "refresh_devices"} and "subprocess.run(" in body:
''',
    '''                    if method_name in {"verify_catalog", "image_changed", "refresh_devices", "start_review"} and "subprocess.run(" in body:
''',
    "FFU GTK-thread blocking contract",
)
source_test.write_text(text)
