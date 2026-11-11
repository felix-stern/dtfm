#!/usr/bin/env python3
"""Tests for extract-changelog.py."""

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Load extract_notes using importlib.util (clean Python 3.12+ compatible)
SCRIPT_PATH = Path(__file__).parent / "extract-changelog.py"
spec = importlib.util.spec_from_file_location("extract_changelog", SCRIPT_PATH)
extract_changelog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract_changelog)


SAMPLE_CHANGELOG = """# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Unreleased feature

## [0.3.0] - 2026-11-20

## [0.2.0] - 2026-11-15

### Added
- Feature 2A
- Feature 2B
Note: Mentioning ## [0.1.0] inline in text should not break extraction.

### Fixed
- Bug 123

## [0.1.0] - 2026-11-10

### Added
- Feature 1A
- Feature 1B

[Unreleased]: https://github.com/example/repo/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/example/repo/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/example/repo/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/example/repo/releases/tag/v0.1.0
[0.2.0+build.1]: https://example.com/build
"""


class TestExtractChangelog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False)
        self.tmp.write(SAMPLE_CHANGELOG)
        self.tmp.flush()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_extract_v0_2_0(self):
        notes = extract_changelog.extract_notes(self.path, "v0.2.0")
        self.assertIn("### Added", notes)
        self.assertIn("- Feature 2A", notes)
        self.assertIn("Mentioning ## [0.1.0] inline", notes)
        self.assertIn("### Fixed", notes)
        self.assertNotIn("Feature 1A", notes)
        self.assertNotIn("Unreleased", notes)
        self.assertNotIn("[0.2.0]: https://", notes)

    def test_extract_v0_1_0_without_v_prefix(self):
        notes = extract_changelog.extract_notes(self.path, "0.1.0")
        self.assertIn("### Added", notes)
        self.assertIn("- Feature 1A", notes)
        self.assertNotIn("Feature 2A", notes)
        self.assertNotIn("[0.1.0]: https://", notes)
        self.assertNotIn("[0.2.0+build.1]:", notes)

    def test_extract_empty_adjacent_section(self):
        notes = extract_changelog.extract_notes(self.path, "v0.3.0")
        self.assertEqual(notes, "")

    def test_extract_zero_blank_line_adjacent_headers(self):
        changelog = "## [0.2.0] - 2026-11-15\n## [0.1.0] - 2026-11-10\n### Added\n- Item A\n"
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as f:
            f.write(changelog)
            f.flush()
            path = Path(f.name)
        try:
            self.assertEqual(extract_changelog.extract_notes(path, "v0.2.0"), "")
            notes = extract_changelog.extract_notes(path, "v0.1.0")
            self.assertIn("### Added", notes)
            self.assertIn("- Item A", notes)
        finally:
            path.unlink(missing_ok=True)

    def test_reject_unreleased_tag(self):
        self.assertEqual(extract_changelog.extract_notes(self.path, "Unreleased"), "")
        self.assertEqual(extract_changelog.extract_notes(self.path, "vUnreleased"), "")
        self.assertEqual(extract_changelog.extract_notes(self.path, "v"), "")
        self.assertEqual(extract_changelog.extract_notes(self.path, ""), "")

    def test_extract_non_existent_tag(self):
        notes = extract_changelog.extract_notes(self.path, "v9.9.9")
        self.assertEqual(notes, "")

    def test_cli_execution_and_stale_output_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            output_file = Path(td) / "RELEASE_NOTES.md"

            # 1. Successful extraction creates file
            cmd = [sys.executable, str(SCRIPT_PATH), "v0.1.0", str(self.path), str(output_file)]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertTrue(output_file.is_file())
            self.assertIn("Feature 1A", output_file.read_text(encoding="utf-8"))

            # 2. Subsequent query for non-existent tag unlinks stale file
            cmd = [sys.executable, str(SCRIPT_PATH), "v9.9.9", str(self.path), str(output_file)]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertFalse(output_file.is_file())


if __name__ == "__main__":
    unittest.main()
