#!/usr/bin/env python3
"""Add package validators and source/package semantic-equivalence checks."""

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/test.sh"
text = path.read_text(encoding="utf-8")


def replace(old: str, new: str) -> None:
    global text
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"scripts/test.sh: expected block not found: {old[:100]!r}")
    text = text.replace(old, new, 1)


replace(
    'for script in scripts/*.sh; do bash -n "${script}"; done\nsh -n packaging/rufusarm64\n',
    '''for script in scripts/*.sh; do bash -n "${script}"; done
sh -n packaging/rufusarm64
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x scripts/*.sh packaging/rufusarm64
fi
''',
)
replace(
    "PY\n\nVERSION=\"${VERSION}\" scripts/build-deb.sh\n",
    '''PY

if command -v desktop-file-validate >/dev/null 2>&1; then
  desktop-file-validate packaging/io.github.geocausa.RufusArm64.desktop
  desktop-file-validate packaging/io.github.geocausa.RufusArm64.Persistence.desktop
fi
if command -v appstreamcli >/dev/null 2>&1; then
  appstreamcli validate --no-net packaging/io.github.geocausa.RufusArm64.metainfo.xml
fi

VERSION="${VERSION}" scripts/build-deb.sh
''',
)
replace(
    'dpkg-deb --info "${PACKAGE}" >/dev/null\ndpkg-deb --contents "${PACKAGE}" >/dev/null\n',
    '''dpkg-deb --info "${PACKAGE}" >/dev/null
dpkg-deb --contents "${PACKAGE}" >/dev/null
if command -v lintian >/dev/null 2>&1; then
  lintian --fail-on error "${PACKAGE}"
fi
''',
)
replace(
    'grep -Fxq "VERSION = \\"${VERSION}\\"" "${installed_gui}"\ngrep -Fxq "Version: ${VERSION}" "${extract_dir}/DEBIAN/control"\n',
    '''grep -Fxq "VERSION = \\"${VERSION}\\"" "${installed_gui}"
python3 - "gui/rufusarm64.py" "${installed_gui}" "${VERSION}" <<'PYGUI'
import pathlib, re, sys
source_path, installed_path, version = sys.argv[1:]
source = pathlib.Path(source_path).read_text(encoding="utf-8")
installed = pathlib.Path(installed_path).read_text(encoding="utf-8")
expected, count = re.subn(r'^VERSION = "[^"]+"$', f'VERSION = "{version}"', source, count=1, flags=re.MULTILINE)
if count != 1 or expected != installed:
    raise SystemExit("installed GUI differs from the tested source beyond canonical version stamping")
PYGUI
grep -Fxq "Version: ${VERSION}" "${extract_dir}/DEBIAN/control"
''',
)
replace(
    '[[ -f "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop" ]]\n',
    '''[[ -f "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop" ]]
grep -q '^NoDisplay=true$' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop"
grep -q '^Actions=.*Persistence' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"
grep -q 'Open Persistent USB Creator' "${installed_gui}"
''',
)
replace(
    "grep -q '<allow_active>auth_admin</allow_active>' \"${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy\"\n! grep -q 'auth_admin_keep' \"${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy\"\n",
    '''grep -q '<allow_active>auth_admin</allow_active>' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
grep -q '<allow_any>no</allow_any>' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
grep -q '<allow_inactive>no</allow_inactive>' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
! grep -q 'auth_admin_keep' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
''',
)

path.write_text(text, encoding="utf-8")
