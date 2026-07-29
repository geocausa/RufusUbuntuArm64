import unittest

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
