# Release Process & Version Tagging

This document outlines the maintainer procedures for versioning, preparing, and publishing releases of `dtfm` and `lmdtfy`.

Releases adhere strictly to [Semantic Versioning (SemVer 2.0.0)](https://semver.org/) and follow the [Keep a Changelog](https://keepachangelog.com/) standard. All releases are hermetic, reproducible, and automated via GitHub Actions ([`.github/workflows/release.yml`](../.github/workflows/release.yml)).

---

## Prerequisites & Permissions

- Write access to the repository (`iinozemtsev-lab/dtfm`).
- Maintainer permissions to trigger GitHub Actions workflows or push tags to `upstream`.
- Local tools (optional if releasing via Web UI): `git`, Go 1.22+, `python3`, and GitHub CLI (`gh`).

---

## Step-by-Step Release Workflow

### 1. Prepare `CHANGELOG.md`

1. Move completed changes from the `## [Unreleased]` section into a new version heading:
   ```markdown
   ## [0.2.0] - 2026-11-15

   ### Added
   - Added new feature description...

   ### Fixed
   - Fixed bug description...
   ```
2. Update the comparison links at the bottom of [`CHANGELOG.md`](../CHANGELOG.md):
   ```markdown
   [Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...HEAD
   [0.2.0]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.1.0...v0.2.0
   ```
3. Submit a pull request with the changelog update against `main`. Once reviewed and approved, squash-merge it to `main` and pull the latest `main` locally.

### 2. Trigger the Release

Releases can be cut either directly from GitHub Actions (manual dispatch) or by pushing an annotated Git tag.

#### Option A: Manual Workflow Dispatch (Recommended)

Manual dispatch triggers the pipeline directly from GitHub Actions without local Git tag manipulation. The workflow enforces execution against `refs/heads/main`, validates strict SemVer format upfront, verifies commit ancestry on `main`, checks for collisions, and automatically creates the Git tag pointing to `main` upon release publication:

- **GitHub Actions Web UI**:
  1. Navigate to **Actions** &rarr; **Release**.
  2. Click **Run workflow**.
  3. Ensure **Branch: main** is selected (`Use workflow from: Branch: main`).
  4. Enter the release version tag in `version` (e.g. `v0.2.0`).
  5. Click **Run workflow**.

- **GitHub CLI (`gh`)**:
  ```bash
  gh workflow run release.yml --repo iinozemtsev-lab/dtfm --ref main -f version=v0.2.0
  ```

#### Option B: Tag Push

Alternatively, create an annotated semver tag locally and push it to `upstream` (or `origin` depending on your remote naming):

```bash
# Ensure local main is synchronized with upstream
git checkout main
git pull upstream main

# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0"

# Push tag to upstream (or origin for direct clones of iinozemtsev-lab/dtfm)
git push upstream v0.2.0
```

---

## Automated Pipeline Quality Gates & Architecture

When triggered, [`.github/workflows/release.yml`](../.github/workflows/release.yml) executes within a dedicated concurrency group (`concurrency: release` with `cancel-in-progress: false` to serialize releases and prevent race conditions):

### Phase 1: Verification & Build (`verify-and-build`)

1. **Strict SemVer Validation**:
   Validates the tag string against strict SemVer (`vMAJOR.MINOR.PATCH` with no leading zeros in major, minor, or patch components, plus optional pre-release/build metadata):
   ```bash
   semver_regex='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
   ```

2. **Branch & Commit Ancestry Guards**:
   - On manual `workflow_dispatch`, asserts `GITHUB_REF == refs/heads/main`.
   - Fetches `origin/main` without tags and runs `git merge-base --is-ancestor HEAD refs/remotes/origin/main` to confirm the commit being released is an ancestor of `main`.

3. **Fail-Closed Collision Guards**:
   - Queries `gh api -i repos/${GITHUB_REPOSITORY}/releases/tags/${TAG}`: fails closed if a published release already exists (HTTP `200`) and asserts HTTP `404` before proceeding.
   - Queries remote tags via `git ls-remote --tags https://github.com/${GITHUB_REPOSITORY}.git` to resolve the peeled tag SHA:
     - On `workflow_dispatch`: asserts that if the tag already exists on origin, it points to the exact commit SHA (`GITHUB_SHA`) being released.
     - On tag `push`: asserts that the remote tag on origin matches `GITHUB_SHA`.

4. **Pre-Release Quality Gates**:
   - `go mod verify`: Confirms module dependencies and cryptographic checksums.
   - `gofmt -s -d .`: Validates zero formatting deviations.
   - `go vet ./...`: Analyzes code constructs and suspicious patterns.
   - `go test -v -race ./...`: Runs test suite under the Go race detector.
   - `python3 -W error scripts/test_extract_changelog.py`: Verifies changelog extraction parser.

5. **Changelog Extraction**:
   Extracts release notes for the target tag from `CHANGELOG.md` via `scripts/extract-changelog.py` into `RELEASE_NOTES.md` (with automatic GitHub release notes fallback if empty).

6. **Hermetic Multi-Platform Static Compilation**:
   Cross-compiles static binaries (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w -X 'main.version=${TAG}'"`) for:
   - `darwin/arm64` (Apple Silicon)
   - `darwin/amd64` (macOS Intel)
   - `linux/amd64` (Linux x86_64)
   - `linux/arm64` (Linux ARM64 / aarch64)

7. **Static ELF Linkage Verification**:
   Inspects all compiled Linux binaries with `readelf -l` to assert zero `INTERP` or `DYNAMIC` sections, guaranteeing portable, dependency-free static binaries.

8. **Reproducible Packaging & Checksums**:
   Packages tarballs (`dtfm_<VERSION>_<OS>_<ARCH>.tar.gz`) containing `dtfm`, `lmdtfy`, `README.md`, `LICENSE`, and `CHANGELOG.md` with standardized `0:0` UID/GID ownership and `SOURCE_DATE_EPOCH` timestamps. Generates cryptographic `SHA256SUMS`.

### Phase 2: Live Release Publishing (`publish`)

1. **Re-Verification of Cryptographic Checksums**:
   Downloads release assets and re-runs `sha256sum -c SHA256SUMS` to verify integrity before publishing.

2. **Secondary Collision Check**:
   Re-verifies HTTP `404` on release existence and checks remote tag SHA against `GITHUB_SHA`.

3. **Stale Draft Cleanup**:
   Enumerates and deletes any stale draft releases matching the tag by exact release ID (`gh api -X DELETE repos/${GITHUB_REPOSITORY}/releases/${id}`).

4. **Single-Step Release Creation**:
   Publishes the release live in a single command (internally staging a draft during asset upload before publishing) using `gh release create`:
   - Passes `--target "$GITHUB_SHA"` on `workflow_dispatch` (allowing GitHub to automatically create the tag pointing to `main` at the verified commit SHA on release publish).
   - Passes `--verify-tag` on tag push events.
   - Automatically appends `--prerelease` if the tag contains a pre-release identifier (`-rc`, `-beta`).
   - Attaches all binary assets, archives, and `SHA256SUMS`.

---

## Post-Release Verification

After release publication, verify the assets:

```bash
# Inspect release metadata
gh release view v0.2.0 --repo iinozemtsev-lab/dtfm

# Download archive and checksums
curl -fLO https://github.com/iinozemtsev-lab/dtfm/releases/download/v0.2.0/dtfm_0.2.0_linux_amd64.tar.gz
curl -fLO https://github.com/iinozemtsev-lab/dtfm/releases/download/v0.2.0/SHA256SUMS

# Verify integrity
sha256sum --ignore-missing -c SHA256SUMS

# Verify version string
tar -xzf dtfm_0.2.0_linux_amd64.tar.gz
./dtfm --version
./lmdtfy --version
```
