#!/usr/bin/env python3
"""Extract release notes for a given version tag from CHANGELOG.md."""

import re
import sys
from pathlib import Path


BOTTOM_LINK_LOOKAHEAD = r"^\[(?:Unreleased|v?\d+\.\d+\.\d+[^\]]*)\]:[ \t]*https?://"


def extract_notes(changelog_path: Path, tag: str) -> str:
    if not changelog_path.is_file():
        return ""

    version = tag.strip().removeprefix("v")
    if not version or version.lower() == "unreleased":
        return ""

    content = changelog_path.read_text(encoding="utf-8")

    # Line-anchored match for ## [0.1.0] or ## [v0.1.0] header with optional release date
    # Lookahead stops cleanly at the next level-2 heading (^## ), bottom link reference definition, or EOF
    pattern = (
        rf"^## \[(?:v)?{re.escape(version)}\][^\n]*(?:\n|$)(.*?)"
        rf"(?=^## |{BOTTOM_LINK_LOOKAHEAD}|\Z)"
    )
    match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
    if match:
        return match.group(1).strip()
    return ""


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <tag> [changelog_path] [output_path]", file=sys.stderr)
        sys.exit(1)

    tag = sys.argv[1]
    changelog_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("CHANGELOG.md")
    output_path = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("RELEASE_NOTES.md")

    notes = extract_notes(changelog_path, tag)
    if notes:
        output_path.write_text(notes + "\n", encoding="utf-8")
        byte_count = len(notes.encode("utf-8"))
        print(f"Extracted {byte_count} UTF-8 bytes of release notes for {tag} to {output_path}")
    else:
        output_path.unlink(missing_ok=True)
        print(f"No release notes found for {tag} in {changelog_path}")


if __name__ == "__main__":
    main()
