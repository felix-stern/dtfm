#!/usr/bin/env python3
"""Tests for finalize-changelog.py."""

import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_PATH = Path(__file__).parent / "finalize-changelog.py"
spec = importlib.util.spec_from_file_location("finalize_changelog", SCRIPT_PATH)
finalize_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalize_mod)

EXTRACT_SCRIPT_PATH = Path(__file__).parent / "extract-changelog.py"
spec_extract = importlib.util.spec_from_file_location("extract_changelog", EXTRACT_SCRIPT_PATH)
extract_mod = importlib.util.module_from_spec(spec_extract)
spec_extract.loader.exec_module(extract_mod)

SAMPLE_CHANGELOG = """# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Shiny new relay feature ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).
- Additional cryptographic tests.

### Fixed
- Fixed critical race condition in prompter.

## [0.2.0] - 2026-11-11

### Added
- Initial release automation.

## [0.1.0] - 2026-11-10

### Added
- Core execution engine.

[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/iinozemtsev-lab/dtfm/compare/6d8f9d2...v0.2.0
[0.1.0]: https://github.com/iinozemtsev-lab/dtfm/commit/6d8f9d2
"""


class TestFinalizeChangelog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False)
        self.tmp.write(SAMPLE_CHANGELOG)
        self.tmp.flush()
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_finalize_with_v_prefix(self):
        updated = finalize_mod.finalize_changelog(
            changelog_path=self.path,
            version="v0.3.0",
            release_date="2026-11-20",
        )

        expected_header = "## [Unreleased]\n\n## [0.3.0] - 2026-11-20\n\n### Added"
        self.assertIn(expected_header, updated)
        self.assertIn("Shiny new relay feature", updated)

        expected_links = (
            "[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.3.0...HEAD\n"
            "[0.3.0]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...v0.3.0\n"
            "[0.2.0]: https://github.com/iinozemtsev-lab/dtfm/compare/6d8f9d2...v0.2.0"
        )
        self.assertIn(expected_links, updated)

        disk_content = self.path.read_text(encoding="utf-8")
        self.assertEqual(disk_content, updated)

    def test_finalize_without_v_prefix(self):
        updated = finalize_mod.finalize_changelog(
            changelog_path=self.path,
            version="0.3.0",
            release_date="2026-11-20",
        )
        self.assertIn("## [0.3.0] - 2026-11-20", updated)
        self.assertIn(
            "[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.3.0...HEAD",
            updated,
        )
        self.assertIn(
            "[0.3.0]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...v0.3.0",
            updated,
        )

    def test_finalize_prerelease(self):
        updated = finalize_mod.finalize_changelog(
            changelog_path=self.path,
            version="v0.3.0-rc.1",
            release_date="2026-11-20",
        )
        self.assertIn("## [0.3.0-rc.1] - 2026-11-20", updated)
        self.assertIn(
            "[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.3.0-rc.1...HEAD",
            updated,
        )
        self.assertIn(
            "[0.3.0-rc.1]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...v0.3.0-rc.1",
            updated,
        )

    def test_default_date_is_utc_today(self):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        updated = finalize_mod.finalize_changelog(
            changelog_path=self.path,
            version="v0.3.0",
        )
        self.assertIn(f"## [0.3.0] - {today}", updated)

    def test_invalid_date_format_fails(self):
        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(
                changelog_path=self.path,
                version="v0.3.0",
                release_date="2026/11/20",
            )
        self.assertIn("invalid", str(ctx.exception).lower())

    def test_empty_unreleased_fails(self):
        empty_changelog = SAMPLE_CHANGELOG.replace(
            "### Added\n- Shiny new relay feature ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).\n- Additional cryptographic tests.\n\n### Fixed\n- Fixed critical race condition in prompter.",
            "",
        )
        self.path.write_text(empty_changelog, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_comment_only_unreleased_fails(self):
        comment_only = SAMPLE_CHANGELOG.replace(
            "### Added\n- Shiny new relay feature ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).\n- Additional cryptographic tests.\n\n### Fixed\n- Fixed critical race condition in prompter.",
            "<!-- Nothing here yet -->",
        )
        self.path.write_text(comment_only, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_empty_subheadings_unreleased_fails(self):
        headings_only = SAMPLE_CHANGELOG.replace(
            "### Added\n- Shiny new relay feature ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).\n- Additional cryptographic tests.\n\n### Fixed\n- Fixed critical race condition in prompter.",
            "### Added\n\n### Fixed\n",
        )
        self.path.write_text(headings_only, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_missing_unreleased_header_fails(self):
        no_unreleased = SAMPLE_CHANGELOG.replace("## [Unreleased]\n", "")
        self.path.write_text(no_unreleased, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("missing", str(ctx.exception).lower())

    def test_duplicate_version_with_unreleased_fails(self):
        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(self.path, "v0.2.0")
        self.assertIn("already exists", str(ctx.exception).lower())
        self.assertIn("unreleased changes", str(ctx.exception).lower())

    def test_already_finalized_idempotent_success(self):
        # 1. Finalize v0.3.0
        first_result = finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )
        # 2. Re-finalize v0.3.0 (now [Unreleased] is empty and ## [0.3.0] exists)
        second_result = finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )
        self.assertEqual(first_result, second_result)
        self.assertEqual(self.path.read_text(encoding="utf-8"), first_result)

    def test_cli_already_finalized_idempotent_success(self):
        # 1. First run finalizes
        cmd1 = [
            sys.executable,
            str(SCRIPT_PATH),
            "v0.3.0",
            str(self.path),
            "--date",
            "2026-11-20",
        ]
        res1 = subprocess.run(cmd1, capture_output=True, text=True)
        self.assertEqual(res1.returncode, 0)
        self.assertIn("Successfully finalized", res1.stdout)

        # 2. Second run succeeds without error and reports already finalized
        res2 = subprocess.run(cmd1, capture_output=True, text=True)
        self.assertEqual(res2.returncode, 0)
        self.assertIn("already finalized", res2.stdout)

    def test_invalid_semver_fails(self):
        invalid_tags = ["", "v", "foo", "v01.0.0", "1.0", "v1.2.3.4"]
        for tag in invalid_tags:
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    finalize_mod.finalize_changelog(self.path, tag)

    def test_missing_compare_link_fails(self):
        no_links = SAMPLE_CHANGELOG.replace(
            "[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...HEAD\n",
            "",
        )
        self.path.write_text(no_links, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("missing or malformed", str(ctx.exception).lower())

    def test_dry_run_does_not_modify_file(self):
        original = self.path.read_text(encoding="utf-8")
        updated = finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
            dry_run=True,
        )
        self.assertIn("## [0.3.0] - 2026-11-20", updated)
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_cli_execution_success(self):
        cmd = [
            sys.executable,
            str(SCRIPT_PATH),
            "v0.3.0",
            str(self.path),
            "--date",
            "2026-11-20",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Successfully finalized changelog for v0.3.0", res.stdout)
        self.assertIn("## [0.3.0] - 2026-11-20", self.path.read_text(encoding="utf-8"))

    def test_cli_execution_failure(self):
        cmd = [
            sys.executable,
            str(SCRIPT_PATH),
            "invalid-version",
            str(self.path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("Error:", res.stderr)

    def test_end_to_end_extraction_compatibility(self):
        # 1. Finalize the changelog
        finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )

        # 2. Extract notes for the finalized version using extract_notes
        notes = extract_mod.extract_notes(self.path, "v0.3.0")
        self.assertIn("### Added", notes)
        self.assertIn("Shiny new relay feature", notes)
        self.assertIn("### Fixed", notes)
        self.assertIn("Fixed critical race condition in prompter.", notes)
        self.assertNotIn("Initial release automation", notes)
        self.assertNotIn("Unreleased", notes)

        # 3. Verify directly on disk content that [Unreleased] body is now empty
        finalized_disk = self.path.read_text(encoding="utf-8")
        unreleased_match = re.search(
            r"^## \[Unreleased\][ \t]*\n(.*?)(?=^## \[0\.3\.0\])",
            finalized_disk,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(unreleased_match)
        self.assertTrue(
            finalize_mod.is_section_content_empty(unreleased_match.group(1))
        )
        self.assertNotIn("Shiny new relay feature", unreleased_match.group(1))

    def test_reject_historical_version_when_unreleased_empty(self):
        # Finalize v0.3.0 first so [Unreleased] becomes empty and 0.3.0 is topmost
        finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )
        # Attempting to finalize older historical releases (0.1.0 or 0.2.0) must fail
        for old_ver in ("v0.1.0", "0.1.0", "v0.2.0"):
            with self.subTest(version=old_ver):
                with self.assertRaises(ValueError) as ctx:
                    finalize_mod.finalize_changelog(self.path, old_ver)
                self.assertIn("historical release", str(ctx.exception).lower())

    def test_reject_topmost_version_when_bottom_links_stale_or_missing(self):
        # 1. Finalize v0.3.0 so [Unreleased] is empty and ## [0.3.0] is topmost
        finalized = finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )

        # Case A: Stale [Unreleased] compare link still pointing from v0.2.0...HEAD
        stale_unreleased = finalized.replace(
            "[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.3.0...HEAD",
            "[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...HEAD",
        )
        self.path.write_text(stale_unreleased, encoding="utf-8")
        with self.assertRaises(ValueError) as ctx_a:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("comparison link", str(ctx_a.exception).lower())

        # Case B: Missing [0.3.0] compare link
        missing_version_link = finalized.replace(
            "[0.3.0]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...v0.3.0\n",
            "",
        )
        self.path.write_text(missing_version_link, encoding="utf-8")
        with self.assertRaises(ValueError) as ctx_b:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("comparison link", str(ctx_b.exception).lower())

    def test_bare_heading_followed_by_bullet_is_not_empty(self):
        self.assertFalse(
            finalize_mod.is_section_content_empty("###\n- Security fix\n")
        )
        bare_heading_changelog = SAMPLE_CHANGELOG.replace(
            "### Added\n- Shiny new relay feature ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).\n- Additional cryptographic tests.\n\n### Fixed\n- Fixed critical race condition in prompter.",
            "###\n- Security fix",
        )
        self.path.write_text(bare_heading_changelog, encoding="utf-8")
        updated = finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )
        self.assertIn("- Security fix", updated)

    def test_invalid_calendar_date_fails(self):
        for bad_date in ("2026-02-30", "2026-99-99", "2026-00-10", "2026-04-31"):
            with self.subTest(date=bad_date):
                with self.assertRaises(ValueError) as ctx:
                    finalize_mod.finalize_changelog(
                        self.path,
                        "v0.3.0",
                        release_date=bad_date,
                    )
                self.assertIn("invalid", str(ctx.exception).lower())

        cmd = [
            sys.executable,
            str(SCRIPT_PATH),
            "v0.3.0",
            str(self.path),
            "--date",
            "2026-02-30",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("Error:", res.stderr)
        self.assertNotIn("Traceback", res.stderr)

    def test_inline_reference_links_preserved_in_release_notes(self):
        with_ref_link = SAMPLE_CHANGELOG.replace(
            "- Additional cryptographic tests.",
            "- Additional cryptographic tests per [RFC][rfc].\n\n[rfc]: https://example.com/rfc\n\n### Security\n- Hardened session binding.",
        )
        self.path.write_text(with_ref_link, encoding="utf-8")

        finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )

        notes = extract_mod.extract_notes(self.path, "v0.3.0")
        self.assertIn("[rfc]: https://example.com/rfc", notes)
        self.assertIn("### Security", notes)
        self.assertIn("- Hardened session binding.", notes)

    def test_unreleased_at_eof_without_trailing_newline_is_empty(self):
        self.path.write_text("# Changelog\n\n## [Unreleased]", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            finalize_mod.finalize_changelog(self.path, "v0.3.0")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_cli_idempotent_with_v_prefixed_section_header(self):
        finalized = finalize_mod.finalize_changelog(
            self.path,
            "v0.3.0",
            release_date="2026-11-20",
        )
        v_header_doc = finalized.replace(
            "## [0.3.0] - 2026-11-20",
            "## [v0.3.0] - 2026-11-20",
        )
        self.path.write_text(v_header_doc, encoding="utf-8")

        cmd = [
            sys.executable,
            str(SCRIPT_PATH),
            "v0.3.0",
            str(self.path),
            "--date",
            "2026-11-20",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("already finalized", res.stdout)

    def test_cli_missing_file_and_directory_error_handling(self):
        missing_path = self.path.parent / f"{self.path.name}-nonexistent"
        for bad_target in (missing_path, self.path.parent):
            with self.subTest(target=str(bad_target)):
                cmd = [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "v0.3.0",
                    str(bad_target),
                ]
                res = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(res.returncode, 1)
                self.assertIn("Error:", res.stderr)
                self.assertNotIn("Traceback", res.stderr)


if __name__ == "__main__":
    unittest.main()
