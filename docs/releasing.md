# Release Process & Version Tagging

This document outlines the maintainer procedures for versioning, preparing, and publishing releases of `dtfm`, `lmdtfy`, and `relay`.

Releases adhere strictly to [Semantic Versioning (SemVer 2.0.0)](https://semver.org/) and follow the [Keep a Changelog](https://keepachangelog.com/) standard. All releases are hermetic, reproducible, and automated via GitHub Actions ([`.github/workflows/release.yml`](../.github/workflows/release.yml)).

---

## Prerequisites & Permissions

- Write access to the repository (`iinozemtsev-lab/dtfm`).
- Maintainer permissions to trigger GitHub Actions workflows or push tags to `upstream`.
- **Branch Protection & `GITHUB_TOKEN` Semantics**:
  - **Option A (`workflow_dispatch`)** requires `main` to permit direct fast-forward pushes from `github-actions[bot]` (`secrets.GITHUB_TOKEN`). If `main` branch protection or repository rulesets require pull requests before merging, use **Option B** via a changelog-prep pull request to `main` and then push the annotated release tag onto the merged commit.
  - Both the deferred changelog push to `main` and the `publish` job **must** continue authenticating with `secrets.GITHUB_TOKEN` (rather than a Personal Access Token or GitHub App token) so that automated commits and tag creation on release publish do not trigger recursive `ci.yml` runs or duplicate `on: push: tags:` `release.yml` runs.
  - Release commit messages intentionally omit `[skip ci]` (`chore(release): finalize changelog for <TAG>`), because GitHub Actions evaluates `[skip ci]` on `head_commit.message` for tag pushes (`on: push: tags: ['v*']`) as well and would silently skip `release.yml` under Option B.
- Local tools (optional if releasing via Web UI): `git`, Go 1.22+, `python3`, and GitHub CLI (`gh`).

---

## Step-by-Step Release Workflow

Releases can be cut either directly from GitHub Actions (manual dispatch) or by pushing an annotated Git tag.

### Option A: Manual Workflow Dispatch (Recommended)

Manual dispatch automates the entire release process from GitHub Actions without local Git tag manipulation or manual changelog editing. The workflow validates release/tag collision guards, finalizes `CHANGELOG.md` locally, runs all test/build/smoke/ELF checks, pushes the finalized changelog commit to `main` only after verification succeeds, and publishes the release:

1. **Verify Unreleased Changes**:
   Ensure `CHANGELOG.md` has all completed changes listed under `## [Unreleased]`. The workflow fails closed if `[Unreleased]` is empty or missing (unless re-running an already-finalized release commit).

2. **Trigger the Workflow**:
   - **GitHub Actions Web UI**:
     1. Navigate to **Actions** &rarr; **Release**.
     2. Click **Run workflow**.
     3. Ensure **Branch: main** is selected (`Use workflow from: Branch: main`).
     4. Enter the release version tag in `version` (e.g. `v0.3.0`).
     5. Click **Run workflow**.

   - **GitHub CLI (`gh`)**:
     ```bash
     gh workflow run release.yml --repo iinozemtsev-lab/dtfm --ref main -f version=v0.3.0
     ```

3. **Automated Finalization & Deferred Push**:
   The workflow executes `scripts/finalize-changelog.py`, creates local commit `chore(release): finalize changelog for <TAG>`, builds and verifies all distribution archives containing the finalized changelog, pushes the commit to `origin/main` once all gates pass, and publishes the GitHub Release and tag at that exact commit SHA. If a workflow run is re-triggered via GitHub Actions **Re-run jobs** after the commit reached `origin/main`, `verify-and-build` detects the exact prior finalization commit on top of `$GITHUB_SHA` and detaches onto `origin/main` idempotently.

---

### Option B: Tag Push (Manual)

Alternatively (or when `main` branch rulesets require pull requests), finalize `CHANGELOG.md` first and push an annotated semver tag onto the merged `main` commit:

1. **Prepare `CHANGELOG.md` on `main`**:
   Run the helper script locally and merge to `main` (via a changelog-prep PR if `main` requires pull requests, or direct push if permitted):
   ```bash
   python3 scripts/finalize-changelog.py v0.3.0
   git commit -m "chore(release): finalize changelog for v0.3.0" CHANGELOG.md
   git push upstream main
   ```

2. **Create and Push Annotated Tag**:
   ```bash
   git tag -a v0.3.0 -m "Release v0.3.0"
   git push upstream v0.3.0
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

2. **Least-Privilege Checkout**:
   Checks out full history with `persist-credentials: false` so `GITHUB_TOKEN` is never persisted into `.git/config` during Go module verification, unit tests, cross-compilation, or binary smoke execution. Only specific network Git steps receive step-scoped `GH_TOKEN` credentials via transient HTTP `extraheader` flags.

3. **Branch, Commit Ancestry & Re-Run Idempotency Guards**:
   - Fetches `refs/remotes/origin/main` without tags over authenticated HTTPS.
   - On manual `workflow_dispatch`: asserts `GITHUB_REF == refs/heads/main` and compares `HEAD` against `refs/remotes/origin/main`. If `origin/main` advanced by the exact single-parent commit `chore(release): finalize changelog for <TAG>` touching only `CHANGELOG.md` (e.g. during a GitHub Actions job re-run), detaches `HEAD` onto `origin/main`; otherwise fails closed if `main` moved forward since dispatch.
   - On tag `push`: runs `git merge-base --is-ancestor HEAD refs/remotes/origin/main` to confirm the tagged commit is an ancestor of `main`.

4. **Pre-Flight Release & Tag Collision Guards**:
   - Queries `gh api -i repos/${GITHUB_REPOSITORY}/releases/tags/${TAG}`: fails closed if a published release already exists (HTTP `200`) and asserts HTTP `404` before mutating or building anything.
   - Queries remote tags via authenticated `git ls-remote --tags ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}.git` to resolve the peeled tag SHA:
     - On `workflow_dispatch`: fails closed if `refs/tags/$TAG` already exists on origin pointing to a different commit (or if a new changelog commit would diverge from an existing tag).
     - On tag `push`: asserts that `refs/tags/$TAG` exists on origin and matches `HEAD`.

5. **Local Changelog Finalization (`workflow_dispatch`) & `RELEASE_SHA` Resolution**:
   - Runs `scripts/finalize-changelog.py "$TAG" CHANGELOG.md`.
   - Fails closed if `## [Unreleased]` is empty or missing (unless `$TAG` is already the topmost finalized release section with matching Keep a Changelog comparison links).
   - Rotates `[Unreleased]` entries into `## [<VERSION>] - <YYYY-MM-DD>`, creates a clean `## [Unreleased]` section, and updates bottom comparison links (`[Unreleased]...HEAD` and `[<VERSION>]...`).
   - Commits `CHANGELOG.md` locally as `github-actions[bot]` with `chore(release): finalize changelog for <TAG>` (deferring remote `git push` until all verification and build steps pass).
   - Resolves `RELEASE_SHA` (`git rev-parse HEAD`) for downstream packaging and publishing.

6. **Pre-Release Quality Gates**:
   - `go mod verify`: Confirms module dependencies and cryptographic checksums.
   - `gofmt -s -d .`: Validates zero formatting deviations.
   - `go vet ./...`: Analyzes code constructs and suspicious patterns.
   - `go test -v -race ./...`: Runs test suite under the Go race detector.
   - `python3 -W error scripts/test_extract_changelog.py`: Verifies changelog extraction parser.
   - `python3 -W error scripts/test_finalize_changelog.py`: Verifies changelog finalization, date validation, and collision/idempotency safety.

7. **Changelog Extraction**:
   Extracts release notes for the target tag from `CHANGELOG.md` via `scripts/extract-changelog.py` into `RELEASE_NOTES.md` (with automatic GitHub release notes fallback if empty).

8. **Hermetic Multi-Platform Static Compilation & Smoke Testing**:
   Cross-compiles static binaries (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w -X 'main.version=${TAG}'"`) for:
   - `darwin/arm64` (Apple Silicon)
   - `darwin/amd64` (macOS Intel)
   - `linux/amd64` (Linux x86_64)
   - `linux/arm64` (Linux ARM64 / aarch64)

   Executes `linux/amd64` smoke checks (`--version`) across `dtfm`, `lmdtfy`, and `relay`.

9. **Static ELF Linkage Verification**:
   Inspects all compiled Linux binaries with `readelf -l` to assert zero `INTERP` or `DYNAMIC` sections, guaranteeing portable, dependency-free static binaries.

10. **Reproducible Packaging & Checksums**:
    Packages tarballs (`dtfm_<VERSION>_<OS>_<ARCH>.tar.gz`) containing `dtfm`, `lmdtfy`, `relay`, `README.md`, `LICENSE`, and `CHANGELOG.md` with standardized `0:0` UID/GID ownership and `SOURCE_DATE_EPOCH` timestamps. Removes any pre-existing `SHA256SUMS` before generating and verifying cryptographic `SHA256SUMS`.

11. **Deferred Push to `origin/main` (`workflow_dispatch`)**:
    When `Finalize CHANGELOG.md locally` created a commit (`NEEDS_MAIN_PUSH == 'true'`), re-verifies that no release or remote tag for `$TAG` appeared during the build, then pushes `HEAD:refs/heads/main` right before uploading release artifacts.

### Phase 2: Live Release Publishing (`publish`)

1. **Strict `RELEASE_SHA` & Checksum Re-Verification**:
   Asserts `RELEASE_SHA` is an explicit 40-character hexadecimal commit SHA (with no fallback to pre-finalization `$GITHUB_SHA`), downloads release assets, and re-runs `sha256sum -c SHA256SUMS` to verify integrity before publishing.

2. **Secondary Collision Check**:
   Re-verifies HTTP `404` on release existence and checks remote tag SHA via authenticated `git ls-remote` against `TARGET_SHA` (`RELEASE_SHA`).

3. **Stale Draft Cleanup**:
   Enumerates and deletes any stale draft releases matching the tag by exact release ID (`gh api -X DELETE repos/${GITHUB_REPOSITORY}/releases/${id}`).

4. **Single-Step Release Creation**:
   Publishes the release live in a single command (internally staging a draft during asset upload before publishing) using `gh release create`:
   - Passes `--target "$TARGET_SHA"` on `workflow_dispatch` (allowing GitHub to automatically create the tag pointing to `main` at the finalized commit SHA on release publish).
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
./relay --version
```
