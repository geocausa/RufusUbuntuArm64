#!/usr/bin/env python3
from pathlib import Path

path = Path("internal/windowsmedia/ca2023_test.go")
text = path.read_text(encoding="utf-8")
text = text.replace("WindowsCA2023Signed:", "WindowsCA2023CertificateEvidence:")
path.write_text(text, encoding="utf-8")
