#!/usr/bin/env python3
"""Apply the audited Rufus localized Windows account-name protections."""

from pathlib import Path


GO_SOURCE = Path("internal/windowsconfig/config.go")
GO_TEST = Path("internal/windowsconfig/config_test.go")
PY_SOURCE = Path("gui/rufusarm64_logic.py")
PY_TEST = Path("gui/test_windows_username_validation.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old in text:
        return text.replace(old, new, 1)
    if new in text:
        return text
    raise SystemExit(f"missing {label} replacement anchor")


def update_go_source() -> None:
    text = GO_SOURCE.read_text(encoding="utf-8")
    old = '''var reservedUsers = map[string]struct{}{
\t"administrator": {}, "guest": {}, "defaultaccount": {}, "wdagutilityaccount": {},
\t"helpassistant": {}, "krbtgt": {}, "local": {}, "none": {}, "system": {},
}
'''
    new = '''// reservedUsers mirrors Rufus's localized built-in account-name guard.
// Windows Setup must not be asked to create an account that collides with a
// localized Administrator account or another reserved system account.
var reservedUsers = []string{
\t"Administrator",
\t"Järjestelmänvalvoja",
\t"Administrateur",
\t"Rendszergazda",
\t"Administrador",
\t"Администратор",
\t"Administratör",
\t"Guest",
\t"DefaultAccount",
\t"WDAGUtilityAccount",
\t"HelpAssistant",
\t"KRBTGT",
\t"Local",
\t"NONE",
\t"SYSTEM",
}

func isReservedWindowsUsername(value string) bool {
\tfor _, reserved := range reservedUsers {
\t\tif strings.EqualFold(value, reserved) {
\t\t\treturn true
\t\t}
\t}
\treturn false
}
'''
    text = replace_once(text, old, new, "Go reserved-name table")
    text = replace_once(
        text,
        '''\t\tif _, reserved := reservedUsers[strings.ToLower(username)]; reserved {
\t\t\treturn fmt.Errorf("%q is a reserved Windows account name", username)
\t\t}
''',
        '''\t\tif isReservedWindowsUsername(username) {
\t\t\treturn fmt.Errorf("%q is a reserved Windows account name", username)
\t\t}
''',
        "Go reserved-name check",
    )
    GO_SOURCE.write_text(text, encoding="utf-8")


def update_go_test() -> None:
    text = GO_TEST.read_text(encoding="utf-8")
    old = '''\tbad := []string{"Administrator", "a/b", "Geo & Co", "percent%name", "caret^name", "bang!name", " leading", "trailing ", strings.Repeat("x", 21), "trailing."}
'''
    new = '''\tbad := []string{
\t\t"Administrator",
\t\t"ADMINISTRATEUR",
\t\t"JÄRJESTELMÄNVALVOJA",
\t\t"Rendszergazda",
\t\t"Administrador",
\t\t"АДМИНИСТРАТОР",
\t\t"Administratör",
\t\t"a/b",
\t\t"Geo & Co",
\t\t"percent%name",
\t\t"caret^name",
\t\t"bang!name",
\t\t" leading",
\t\t"trailing ",
\t\tstrings.Repeat("x", 21),
\t\t"trailing.",
\t}
'''
    text = replace_once(text, old, new, "Go username regression cases")
    GO_TEST.write_text(text, encoding="utf-8")


def update_python_source() -> None:
    text = PY_SOURCE.read_text(encoding="utf-8")
    old = '''RESERVED_USERS = {
    "administrator",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
    "helpassistant",
    "krbtgt",
    "local",
    "none",
    "system",
}
'''
    new = '''# Keep this table aligned with Rufus's localized built-in account-name guard.
# casefold() gives the Python UI the same Unicode-insensitive behaviour as the
# Go generator's strings.EqualFold enforcement.
RESERVED_USERS = frozenset(name.casefold() for name in (
    "Administrator",
    "Järjestelmänvalvoja",
    "Administrateur",
    "Rendszergazda",
    "Administrador",
    "Администратор",
    "Administratör",
    "Guest",
    "DefaultAccount",
    "WDAGUtilityAccount",
    "HelpAssistant",
    "KRBTGT",
    "Local",
    "NONE",
    "SYSTEM",
))
'''
    text = replace_once(text, old, new, "Python reserved-name table")
    text = replace_once(
        text,
        '''    if value.lower() in RESERVED_USERS:
        raise ValueError(f'"{value}" is a reserved Windows account name.')
''',
        '''    if value.casefold() in RESERVED_USERS:
        raise ValueError(f'"{value}" is a reserved Windows account name.')
''',
        "Python reserved-name check",
    )
    PY_SOURCE.write_text(text, encoding="utf-8")


def write_python_test() -> None:
    content = '''import unittest

from rufusarm64_logic import validate_local_username


class LocalizedWindowsUsernameTests(unittest.TestCase):
    def test_rejects_upstream_localized_reserved_names_case_insensitively(self):
        for name in (
            "Administrator",
            "ADMINISTRATEUR",
            "JÄRJESTELMÄNVALVOJA",
            "Rendszergazda",
            "Administrador",
            "АДМИНИСТРАТОР",
            "Administratör",
            "Guest",
            "DefaultAccount",
            "WDAGUtilityAccount",
            "HelpAssistant",
            "KRBTGT",
            "Local",
            "NONE",
            "SYSTEM",
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "reserved Windows account name"):
                    validate_local_username(name)

    def test_accepts_non_reserved_unicode_account_name(self):
        self.assertEqual(validate_local_username("Zoë User"), "Zoë User")


if __name__ == "__main__":
    unittest.main()
'''
    if PY_TEST.exists() and PY_TEST.read_text(encoding="utf-8") == content:
        return
    PY_TEST.write_text(content, encoding="utf-8")


def main() -> None:
    update_go_source()
    update_go_test()
    update_python_source()
    write_python_test()


if __name__ == "__main__":
    main()
