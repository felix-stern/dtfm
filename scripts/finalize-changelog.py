#!/usr/bin/env python3
"""Finalize Keep a Changelog for a new release version."""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SEMVER_REGEX = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"
)

DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")

BOTTOM_LINK_LOOKAHEAD = r"^\[(?:Unreleased|v?\d+\.\d+\.\d+[^\]]*)\]:[ \t]*https?://"


def validate_semver(version_str: str) -> tuple[str, str]:
    cleaned = version_str.strip()
    if not cleaned:
        raise ValueError("Release version/tag cannot be empty")
    plain = cleaned.removeprefix("v")
    if not plain or plain.lower() == "unreleased":
        raise ValueError(f"Invalid release version: '{version_str}'")
    if not SEMVER_REGEX.match(plain):
        raise ValueError(
            f"Version '{plain}' does not conform to strict SemVer (MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD])"
        )
    v_tag = f"v{plain}"
    return plain, v_tag


def validate_release_date(release_date: Optional[str]) -> str:
    if release_date is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cleaned = release_date.strip()
    if not DATE_REGEX.match(cleaned):
        raise ValueError(
            f"Release date '{cleaned}' is invalid; must match YYYY-MM-DD"
        )
    try:
        datetime.strptime(cleaned, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(
            f"Release date '{cleaned}' is invalid; must be a real calendar date (YYYY-MM-DD)"
        ) from exc
    return cleaned


def is_section_content_empty(body: str) -> bool:
    # Remove HTML comments (e.g. <!-- comments -->)
    no_comments = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
    # Remove Markdown headings using horizontal whitespace only so bare headings
    # (e.g. "###\n- Security fix") never consume the following line
    no_headings = re.sub(
        r"^[ \t]*#{1,6}(?:[ \t]+[^\n]*)?$", "", no_comments, flags=re.MULTILINE
    )
    # Check if remaining content has non-whitespace characters
    return len(no_headings.strip()) == 0


def _finalize_changelog(
    changelog_path: Path,
    version: str,
    release_date: Optional[str] = None,
    dry_run: bool = False,
) -> tuple[str, bool, str]:
    plain_version, v_tag = validate_semver(version)
    effective_date = validate_release_date(release_date)

    if not changelog_path.exists():
        raise FileNotFoundError(f"Changelog file not found: {changelog_path}")
    if not changelog_path.is_file():
        raise OSError(f"Changelog path is not a regular file: {changelog_path}")

    content = changelog_path.read_text(encoding="utf-8")

    # 1. Locate ## [Unreleased] header (must appear exactly once)
    unreleased_headers = list(
        re.finditer(r"^## \[Unreleased\][ \t]*$", content, flags=re.MULTILINE)
    )
    if not unreleased_headers:
        raise ValueError(
            f"Missing '## [Unreleased]' section header in {changelog_path.name}"
        )
    if len(unreleased_headers) > 1:
        raise ValueError(
            f"Multiple '## [Unreleased]' section headers found in {changelog_path.name}"
        )
    unreleased_match = unreleased_headers[0]

    # 2. Extract [Unreleased] body up to the next level-2 heading, Keep a Changelog link definition, or EOF
    section_pattern = (
        rf"^## \[Unreleased\][ \t]*(?:\n(.*?)|(?=\Z))"
        rf"(?=^## |{BOTTOM_LINK_LOOKAHEAD}|\Z)"
    )
    match = re.search(section_pattern, content, flags=re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError(
            f"Could not parse '[Unreleased]' section in {changelog_path.name}"
        )

    unreleased_body = match.group(1) or ""
    unreleased_empty = is_section_content_empty(unreleased_body)

    # 3. Check if version already exists in CHANGELOG.md
    existing_version_pattern = rf"^## \[(?:v)?{re.escape(plain_version)}\][^\n]*$"
    existing_version_matches = re.findall(
        existing_version_pattern, content, flags=re.MULTILINE
    )
    if len(existing_version_matches) > 1:
        raise ValueError(
            f"Duplicate '[{plain_version}]' release headers found in {changelog_path.name}"
        )
    has_existing_version = len(existing_version_matches) == 1

    # Check already-finalized idempotency:
    if has_existing_version:
        if not unreleased_empty:
            raise ValueError(
                f"Version '{plain_version}' already exists in {changelog_path.name}, but '[Unreleased]' also contains unreleased changes"
            )

        # Must be the first (topmost) ## [...] release section immediately following ## [Unreleased]
        remainder = content[match.end() :]
        topmost_match = re.match(
            r"^## \[([^\]]+)\][^\n]*$", remainder, flags=re.MULTILINE
        )
        if not topmost_match:
            raise ValueError(
                f"Version '{plain_version}' exists in {changelog_path.name}, but is not the topmost release section immediately following '## [Unreleased]'"
            )

        header_label = topmost_match.group(1)
        topmost_plain = header_label.removeprefix("v")
        if topmost_plain != plain_version:
            raise ValueError(
                f"Version '{plain_version}' already exists as a historical release in {changelog_path.name} (topmost release is '{header_label}')"
            )

        # Verify both bottom comparison links already exist and match <base>v<plain_version>...HEAD and <base><prev>...v<plain_version>
        idempotent_unreleased_link = re.search(
            rf"^\[Unreleased\]:[ \t]*(https?://\S+/compare/){re.escape(v_tag)}\.\.\.HEAD[ \t]*$",
            content,
            flags=re.MULTILINE,
        )
        if not idempotent_unreleased_link:
            raise ValueError(
                f"Version '{plain_version}' section exists in {changelog_path.name}, but '[Unreleased]' comparison link is missing or stale (expected '.../compare/{v_tag}...HEAD')"
            )

        compare_base = idempotent_unreleased_link.group(1)
        idempotent_version_link = re.search(
            rf"^\[(?:{re.escape(plain_version)}|{re.escape(header_label)})\]:[ \t]*{re.escape(compare_base)}(\S+?)\.\.\.{re.escape(v_tag)}[ \t]*$",
            content,
            flags=re.MULTILINE,
        )
        if not idempotent_version_link or idempotent_version_link.group(1) == v_tag:
            raise ValueError(
                f"Version '{plain_version}' section exists in {changelog_path.name}, but '[{plain_version}]' comparison link is missing or malformed"
            )

        return content, False, effective_date

    if unreleased_empty:
        raise ValueError(
            f"'[Unreleased]' section in {changelog_path.name} is empty; cannot finalize release without changes"
        )

    # Reject if a stale bottom comparison link for this version already exists without a section header
    if re.search(
        rf"^\[(?:v)?{re.escape(plain_version)}\]:[ \t]*", content, flags=re.MULTILINE
    ):
        raise ValueError(
            f"Comparison link for '{plain_version}' already exists in {changelog_path.name} without a corresponding release section"
        )

    # 4. Locate and parse bottom [Unreleased] compare link
    unreleased_link_pattern = (
        r"^\[Unreleased\]:[ \t]*(https?://\S+/compare/)(\S+?)\.\.\.HEAD[ \t]*$"
    )
    link_match = re.search(unreleased_link_pattern, content, flags=re.MULTILINE)
    if not link_match:
        raise ValueError(
            f"Missing or malformed '[Unreleased]: https://.../compare/<prev>...HEAD' link definition in {changelog_path.name}"
        )

    compare_base = link_match.group(1)
    prev_ref = link_match.group(2)
    if prev_ref == v_tag:
        raise ValueError(
            f"'[Unreleased]' comparison link in {changelog_path.name} already points from '{v_tag}...HEAD'"
        )

    # 5. Perform header replacement:
    # Replace:
    # ## [Unreleased]
    # with:
    # ## [Unreleased]
    #
    # ## [<VERSION>] - <YYYY-MM-DD>
    new_header = f"## [Unreleased]\n\n## [{plain_version}] - {effective_date}"
    updated = (
        content[: unreleased_match.start()]
        + new_header
        + content[unreleased_match.end() :]
    )

    # 6. Perform bottom link update:
    # Replace:
    # [Unreleased]: <base><prev_ref>...HEAD
    # with:
    # [Unreleased]: <base><v_tag>...HEAD
    # [<VERSION>]: <base><prev_ref>...<v_tag>
    new_links = (
        f"[Unreleased]: {compare_base}{v_tag}...HEAD\n"
        f"[{plain_version}]: {compare_base}{prev_ref}...{v_tag}"
    )

    # Re-locate link match in updated content to get accurate offsets
    updated_link_match = re.search(unreleased_link_pattern, updated, flags=re.MULTILINE)
    if not updated_link_match:
        raise ValueError(
            "Failed to re-locate '[Unreleased]' comparison link during update"
        )

    updated = (
        updated[: updated_link_match.start()]
        + new_links
        + updated[updated_link_match.end() :]
    )

    if not dry_run:
        changelog_path.write_text(updated, encoding="utf-8")

    return updated, True, effective_date


def finalize_changelog(
    changelog_path: Path,
    version: str,
    release_date: Optional[str] = None,
    dry_run: bool = False,
) -> str:
    updated, _, _ = _finalize_changelog(
        changelog_path=changelog_path,
        version=version,
        release_date=release_date,
        dry_run=dry_run,
    )
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Finalize Keep a Changelog for a new release version."
    )
    parser.add_argument(
        "version",
        help="Release version tag (e.g. v0.3.0 or 0.3.0)",
    )
    parser.add_argument(
        "changelog",
        nargs="?",
        default="CHANGELOG.md",
        help="Path to CHANGELOG.md (default: CHANGELOG.md)",
    )
    parser.add_argument(
        "--date",
        dest="release_date",
        help="Release date in YYYY-MM-DD format (default: current UTC date)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print finalized changelog to stdout without modifying file",
    )

    args = parser.parse_args()
    path = Path(args.changelog)

    try:
        _, v_tag = validate_semver(args.version)
        updated_content, changed, effective_date = _finalize_changelog(
            changelog_path=path,
            version=args.version,
            release_date=args.release_date,
            dry_run=args.dry_run,
        )
    except (ValueError, OSError) as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        sys.stdout.write(updated_content)
    elif not changed:
        print(
            f"Version {v_tag} is already finalized in {args.changelog}; no changes needed."
        )
    else:
        print(
            f"Successfully finalized changelog for {v_tag} ({effective_date}) in {args.changelog}"
        )


if __name__ == "__main__":
    main()
