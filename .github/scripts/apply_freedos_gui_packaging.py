#!/usr/bin/env python3
"""Apply the reviewed graphical FreeDOS package and audit integration once."""

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    build_path = Path("scripts/build-deb.sh")
    build = build_path.read_text(encoding="utf-8")
    build = replace_once(
        build,
        '''grep -Fq 'Gtk.Button(label="Non bootable…")' "${ROOT_DIR}/gui/rufusarm64_nonbootable_dialog.py"
grep -Fq 'install_nonbootable(RufusWindow)' "${ROOT_DIR}/gui/rufusarm64_integrated.py"
''',
        '''grep -Fq 'Gtk.Button(label="Non bootable…")' "${ROOT_DIR}/gui/rufusarm64_nonbootable_dialog.py"
grep -Fq 'install_nonbootable(RufusWindow)' "${ROOT_DIR}/gui/rufusarm64_integrated.py"
grep -Fq 'Gtk.Button(label="FreeDOS…")' "${ROOT_DIR}/gui/rufusarm64_freedos_dialog.py"
grep -Fq 'install_freedos(RufusWindow)' "${ROOT_DIR}/gui/rufusarm64_integrated.py"
''',
        "FreeDOS GUI source gates",
    )
    build = replace_once(
        build,
        '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_nonbootable_dialog.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_nonbootable_dialog.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_integrated.py" \\
''',
        '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_nonbootable_dialog.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_nonbootable_dialog.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_freedos.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_freedos.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_freedos_dialog.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_freedos_dialog.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_integrated.py" \\
''',
        "FreeDOS GUI installation",
    )
    build = replace_once(
        build,
        '''install -Dm644 "${ROOT_DIR}/docs/freedos-linux-backend.md" \\
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/freedos-linux-backend.md"
install -Dm644 "${ROOT_DIR}/NOTICE" \\
''',
        '''install -Dm644 "${ROOT_DIR}/docs/freedos-linux-backend.md" \\
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/freedos-linux-backend.md"
install -Dm644 "${ROOT_DIR}/docs/freedos-user-guide.md" \\
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/freedos-user-guide.md"
install -Dm644 "${ROOT_DIR}/NOTICE" \\
''',
        "FreeDOS user guide installation",
    )
    build_path.write_text(build, encoding="utf-8")

    test_path = Path("scripts/test.sh")
    test = test_path.read_text(encoding="utf-8")
    test = replace_once(
        test,
        '''  gui/rufusarm64_nonbootable.py gui/rufusarm64_nonbootable_dialog.py \\
  gui/rufusarm64_integrated.py gui/rufusarm64_persistence.py gui/rufusarm64_persistence_logic.py
''',
        '''  gui/rufusarm64_nonbootable.py gui/rufusarm64_nonbootable_dialog.py \\
  gui/rufusarm64_freedos.py gui/rufusarm64_freedos_dialog.py \\
  gui/rufusarm64_integrated.py gui/rufusarm64_persistence.py gui/rufusarm64_persistence_logic.py
''',
        "FreeDOS Python compilation",
    )
    test = replace_once(
        test,
        '''[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_device_qualify_dialog.py" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_persistence.py" ]]
''',
        '''[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_device_qualify_dialog.py" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_freedos.py" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_freedos_dialog.py" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_persistence.py" ]]
''',
        "FreeDOS installed Python checks",
    )
    test = replace_once(
        test,
        '''[[ -f "${extract_dir}/usr/share/doc/rufusarm64/persistence-qualification.md" ]]
[[ ! -e "${extract_dir}/usr/bin/rufus-channel-admin" ]]
''',
        '''[[ -f "${extract_dir}/usr/share/doc/rufusarm64/persistence-qualification.md" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/freedos-user-guide.md" ]]
[[ ! -e "${extract_dir}/usr/bin/rufus-channel-admin" ]]
''',
        "FreeDOS installed guide check",
    )
    test_path.write_text(test, encoding="utf-8")


if __name__ == "__main__":
    main()
