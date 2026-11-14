# Release Process & Version Tagging

This document outlines the maintainer procedures for versioning, preparing, and publishing releases of `dtfm`, `lmdtfy`, and `relay`.

Releases adhere strictly to [Semantic Versioning (SemVer 2.0.0)](https://semver.org/) and follow the [Keep a Changelog](https://keepachangelog.com/) standard. All releases are hermetic, reproducible, and automated via GitHub Actions ([`.github/workflows/release.yml`](../.github/workflows/release.yml)).

---

## Prerequisites & Permissions

- Write access to the repository (`iinozemtsev-lab/dtfm`).
- Maintainer permissions to trigger GitHub Actions workflows or push tags to `upstream`.
- **Least-Privilege Job Isolation & Sigstore Attestations**:
  - `verify` runs pre-flight guards, unit/race tests, and Python script tests with `contents: read` only (and cached Go modules), holding zero signing or repository write credentials.
  - `build` runs hermetically (`cache: false`, `-mod=readonly`) with `contents: read`, `id-token: write`, and `attestations: write` to mint ephemeral GitHub OIDC tokens and sign SLSA v1.0 build provenance attestations via Sigstore (`actions/attest-build-provenance@v4`) without repository push access.
  - `publish` runs with `contents: write` and `attestations: read` to verify `SHA256SUMS` membership and live SLSA attestations *before* pushing any deferred changelog commit to `main` or creating the GitHub Release.
- **Tag Rulesets & Protected `release` Environment (Unmerged-Branch Hardening)**:
  - Configure a repository tag ruleset protecting `refs/tags/v*` so only repository admins / designated release maintainers can create, update, or delete `v*` tags.
  - While `.github/workflows/release.yml` enforces job-level `if` guards (`workflow_dispatch` on `refs/heads/main` or `push` on `refs/tags/v*`), any collaborator with branch-push access could still push a modified workflow to an unmerged feature branch and trigger `workflow_dispatch` there (producing an attestation whose certificate `SourceRepositoryRef` is `refs/heads/<feature-branch>`). Downstream verifiers **must** therefore pass `--signer-workflow`, `--deny-self-hosted-runners`, and `--source-ref` (`refs/heads/main` or `refs/tags/<TAG>`) to `gh attestation verify` so unmerged-branch attestations are cryptographically rejected.
  - **Recommended Control-Plane Hardening (`environment: release`)**: Repository admins should create a protected `release` environment in **Settings &rarr; Environments** with **Deployment branches and tags** set to **Selected branches and tags** allowing **both** `main` and `v*` (plus optional required reviewers). Once configured, `environment: release` can be attached to `build` and/or `publish` in `.github/workflows/release.yml` so GitHub's control plane blocks unmerged branches before job execution. *(`environment: release` is not enabled in the workflow YAML by default so CI/CD neither auto-creates an unprotected environment nor breaks Option B `v*` tag pushes prior to admin setup.)*
- **Branch Protection & `GITHUB_TOKEN` Semantics**:
  - **Option A (`workflow_dispatch`)** requires `main` to permit direct fast-forward pushes from `github-actions[bot]` (`secrets.GITHUB_TOKEN`). If `main` branch protection or repository rulesets require pull requests before merging, use **Option B** via a changelog-prep pull request to `main` and then push the annotated release tag onto the merged commit.
  - Both the deferred changelog push to `main` and release creation in `publish` **must** continue authenticating with `secrets.GITHUB_TOKEN` (rather than a Personal Access Token or GitHub App token) so that automated commits and tag creation on release publish do not trigger recursive `ci.yml` runs or duplicate `on: push: tags:` `release.yml` runs.
  - Release commit messages intentionally omit `[skip ci]` (`chore(release): finalize changelog for <TAG>`), because GitHub Actions evaluates `[skip ci]` on `head_commit.message` for tag pushes (`on: push: tags: ['v*']`) as well and would silently skip `release.yml` under Option B.
- Local tools (optional if releasing via Web UI): `git`, Go 1.22+, `python3`, and GitHub CLI **`gh` v2.97.0+** (required for `gh attestation verify` so `--signer-workflow` and `--signer-repo` enforce exact regex-escaped certificate SAN matching).

---

## Step-by-Step Release Workflow

Releases can be cut either directly from GitHub Actions (manual dispatch) or by pushing an annotated Git tag.

### Option A: Manual Workflow Dispatch (Recommended)

Manual dispatch automates the entire release process from GitHub Actions without local Git tag manipulation or manual changelog editing. The pipeline validates release/tag collision guards and runs quality gates in `verify`, finalizes `CHANGELOG.md` locally and signs SLSA attestations over hermetic artifacts in `build`, and verifies attestations in `publish` before pushing the finalized changelog commit to `main` and publishing the release:

1. **Verify Unreleased Changes**:
   Ensure `CHANGELOG.md` has all completed changes listed under `## [Unreleased]`. The workflow fails closed if `[Unreleased]` is empty or missing (unless re-running an already-finalized release commit).

2. **Trigger the Workflow**:
   - **GitHub Actions Web UI**:
     1. Navigate to **Actions** &rarr; **Release**.
     2. Click **Run workflow**.
     3. Ensure **Branch: main** is selected (`Use workflow from: Branch: main`).
     4. Enter the release version tag in `version` (e.g. `v0.4.0`).
     5. Click **Run workflow**.

   - **GitHub CLI (`gh`)**:
     ```bash
     gh workflow run release.yml --repo iinozemtsev-lab/dtfm --ref main -f version=v0.4.0
     ```

3. **Automated Finalization, Attestation & Deferred Push**:
   In `build`, the workflow executes `scripts/finalize-changelog.py`, creates local commit `chore(release): finalize changelog for <TAG>` (`RELEASE_SHA`), exports a Git bundle for that commit, builds and smoke-tests all distribution archives containing the finalized changelog, and generates Sigstore / SLSA v1.0 provenance attestations. In `publish`, after checksum membership and `gh attestation verify` checks succeed across all 17 release files, the workflow fast-forward pushes `RELEASE_SHA` to `origin/main` and publishes the GitHub Release and tag at `RELEASE_SHA`. Both **Re-run all jobs** and **Re-run failed jobs** detect an already-pushed `chore(release): finalize changelog for <TAG>` commit on `origin/main` idempotently.

   > [!NOTE]
   > **SLSA Provenance Source-Commit Semantics (`GITHUB_SHA` vs. `RELEASE_SHA`)**: GitHub Actions fixes OIDC token claims (`$GITHUB_REF` and `$GITHUB_SHA`) at workflow trigger time. Under **Option A (`workflow_dispatch`)**, the Fulcio signing certificate and SLSA provenance record `SourceRepositoryRef = refs/heads/main` and `SourceRepositoryDigest = <pre-finalization GITHUB_SHA>` (the `main` commit from which all Go code was compiled, immediately preceding the automated `CHANGELOG.md`-only `RELEASE_SHA` commit). Under **Option B (Tag Push)**, `CHANGELOG.md` is already committed on `main` before tagging, so the attestation binds directly to `SourceRepositoryRef = refs/tags/<TAG>` and `SourceRepositoryDigest = <RELEASE_SHA>`.

---

### Option B: Tag Push (Manual)

Alternatively (when `main` branch rulesets require pull requests, or when you want the SLSA attestation certificate's `SourceRepositoryRef` and `SourceRepositoryDigest` to bind directly to `refs/tags/<TAG>` and the exact tagged `RELEASE_SHA`), finalize `CHANGELOG.md` first and push an annotated semver tag onto the merged `main` commit:

1. **Prepare `CHANGELOG.md` on `main`**:
   Run the helper script locally and merge to `main` (via a changelog-prep PR if `main` requires pull requests, or direct push if permitted):
   ```bash
   python3 scripts/finalize-changelog.py v0.4.0
   git commit -m "chore(release): finalize changelog for v0.4.0" CHANGELOG.md
   git push upstream main
   ```

2. **Create and Push Annotated Tag**:
   ```bash
   git tag -a v0.4.0 -m "Release v0.4.0"
   git push upstream v0.4.0
   ```

---

## Automated Pipeline Quality Gates & Architecture

When triggered, [`.github/workflows/release.yml`](../.github/workflows/release.yml) executes within a dedicated concurrency group (`concurrency: release` with `cancel-in-progress: false` to serialize releases and prevent race conditions) across three least-privilege jobs:

### Phase 1: Pre-Release Quality Gates (`verify` — `contents: read`)

1. **Job-Level Ref Guard & Strict SemVer Validation**:
   Enforces `github.repository == 'iinozemtsev-lab/dtfm'` and restricts execution to `workflow_dispatch` on `refs/heads/main` or `push` on `refs/tags/v*` before runner provisioning, then validates the tag string against strict SemVer (`vMAJOR.MINOR.PATCH` with no leading zeros in major, minor, or patch components, plus optional pre-release/build metadata):
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

5. **Dry-Run Changelog Validation (`workflow_dispatch`)**:
   Runs `scripts/finalize-changelog.py --dry-run "$TAG" CHANGELOG.md` before executing the test suite to fail fast if `## [Unreleased]` is empty/malformed or if creating a new changelog commit would conflict with an existing remote tag, while keeping the test working tree clean.

6. **Pre-Release Quality Gates**:
   - `go mod verify`: Confirms module dependencies and cryptographic checksums.
   - `gofmt -s -d .`: Validates zero formatting deviations.
   - `go vet ./...`: Analyzes code constructs and suspicious patterns.
   - `go test -v -race ./...`: Runs test suite under the Go race detector.
   - `python3 -W error scripts/test_extract_changelog.py`: Verifies changelog extraction parser.
   - `python3 -W error scripts/test_finalize_changelog.py`: Verifies changelog finalization, date validation, and collision/idempotency safety.

### Phase 2: Hermetic Build & Provenance Attestation (`build` — `contents: read`, `id-token: write`, `attestations: write`)

1. **Isolated Checkout & Guard Re-Verification**:
   Checks out the repository on a fresh runner (`persist-credentials: false`) and re-verifies branch ancestry, re-run detach state, and release/tag collision invariants without running untrusted test caches in the signing job.

2. **Local Changelog Finalization (`workflow_dispatch`), Bundle Staging & `RELEASE_SHA` Resolution**:
   - Runs `scripts/finalize-changelog.py "$TAG" CHANGELOG.md`.
   - Rotates `[Unreleased]` entries into `## [<VERSION>] - <YYYY-MM-DD>`, creates a clean `## [Unreleased]` section, and updates bottom comparison links (`[Unreleased]...HEAD` and `[<VERSION>]...`).
   - Commits `CHANGELOG.md` locally as `github-actions[bot]` with `chore(release): finalize changelog for <TAG>` and stages `staging/release-commit.bundle` (deferring any `git push` to `origin/main` until `publish` verifies all attestations).
   - Resolves `RELEASE_SHA` (`git rev-parse HEAD`) and `NEEDS_MAIN_PUSH` (`true`/`false`) for `publish`, and extracts release notes into `staging/RELEASE_NOTES.md` via `scripts/extract-changelog.py`.

3. **Uncached Go Toolchain & Hermetic Multi-Platform Static Compilation**:
   Sets up Go with `cache: false`, runs `go mod download && go mod verify`, and cross-compiles static binaries (`CGO_ENABLED=0`, `-mod=readonly`, `-trimpath`, `-ldflags="-s -w -X 'main.version=${TAG}'"`) for:
   - `darwin/arm64` (Apple Silicon)
   - `darwin/amd64` (macOS Intel)
   - `linux/amd64` (Linux x86_64)
   - `linux/arm64` (Linux ARM64 / aarch64)

   Executes `linux/amd64` smoke checks (`--version`) across `dtfm`, `lmdtfy`, and `relay`.

4. **Static ELF Linkage Verification**:
   Inspects all compiled Linux binaries with `readelf -l` to assert zero `INTERP` or `DYNAMIC` sections, guaranteeing portable, dependency-free static binaries.

5. **Reproducible Packaging & Checksums**:
   Packages tarballs (`dtfm_<VERSION>_<OS>_<ARCH>.tar.gz`) containing `dtfm`, `lmdtfy`, `relay`, `README.md`, `LICENSE`, and `CHANGELOG.md` with standardized `0:0` UID/GID ownership and `SOURCE_DATE_EPOCH` timestamps. Removes any pre-existing `SHA256SUMS` before generating and strictly verifying (`sha256sum --strict -c`) cryptographic `SHA256SUMS` across all 16 release assets.

6. **Cryptographic Artifact Attestations & SLSA Build Provenance**:
   Generates cryptographically signed SLSA v1.0 build provenance attestations for all 17 files in `artifacts/*` (4 archives, 12 standalone binaries, and `SHA256SUMS`) using `actions/attest-build-provenance@v4` *before* any mutation of `origin/main`. Uses GitHub's ephemeral OIDC tokens (`id-token: write`, `attestations: write`) for keyless Sigstore signing and public transparency log recording, cryptographically proving that the artifacts were built on GitHub-hosted runners by `.github/workflows/release.yml` in `iinozemtsev-lab/dtfm` from the attested trigger ref and commit (`refs/heads/main` at the pre-finalization parent commit `$GITHUB_SHA` under Option A, or `refs/tags/<TAG>` at the exact tagged `RELEASE_SHA` under Option B).

### Phase 3: Pre-Publish Verification, Deferred Push & Live Release Publishing (`publish` — `contents: write`, `attestations: read`)

1. **Strict `RELEASE_SHA`, Exact Asset Membership & Checksum Verification**:
   Validates `TAG`, 40-character hexadecimal `RELEASE_SHA`, and `NEEDS_MAIN_PUSH`, asserts `artifacts/` contains only the 16 expected regular asset files plus `SHA256SUMS` with exact 1-to-1 filename membership against `SHA256SUMS`, and re-runs `sha256sum --strict -c SHA256SUMS`.

2. **Pre-Release SLSA Attestation Verification**:
   Verifies live Sigstore / SLSA v1.0 build provenance attestations via `gh attestation verify` against the GitHub Attestations API for every file in `artifacts/*` (including `SHA256SUMS`, archives, and standalone binaries), enforcing `--repo`, `--deny-self-hosted-runners`, `--signer-workflow`, `--source-ref "$GITHUB_REF"`, and `--source-digest "$GITHUB_SHA"` before any remote push or release creation.

3. **Deferred Fast-Forward Push to `origin/main` (`workflow_dispatch`)**:
   When `NEEDS_MAIN_PUSH == 'true'`, re-verifies HTTP `404` on release existence and tag absence, verifies `staging/release-commit.bundle` (`git bundle verify`), asserts `RELEASE_SHA` is a single-parent fast-forward commit on top of `$GITHUB_SHA` (`origin/main`) with message `chore(release): finalize changelog for <TAG>` touching exclusively `CHANGELOG.md`, and pushes `${RELEASE_SHA}:refs/heads/main` (skipping the push idempotently if `origin/main` already points to `RELEASE_SHA` on a job re-run).

4. **Secondary Collision Check & Stale Draft Cleanup**:
   Re-verifies HTTP `404` on release existence, checks remote tag SHA via authenticated `git ls-remote` against `TARGET_SHA` (`RELEASE_SHA`), and deletes any stale draft releases matching the tag by exact release ID (`gh api -X DELETE repos/${GITHUB_REPOSITORY}/releases/${id}`).

5. **Single-Step Release Creation**:
   Publishes the release live in a single command using `gh release create`:
   - Passes `--target "$TARGET_SHA"` on `workflow_dispatch` (allowing GitHub to automatically create the tag pointing to `main` at the finalized commit SHA on release publish).
   - Passes `--verify-tag` on tag push events.
   - Automatically appends `--prerelease` if the tag contains a pre-release identifier (`-rc`, `-beta`).
   - Attaches all binary assets, archives, and `SHA256SUMS` from `artifacts/*`.

---

## Post-Release Verification

> [!NOTE]
> Cryptographic SLSA v1.0 build provenance attestations apply to releases **after `v0.3.0`** (starting with `v0.4.0`) and require GitHub CLI **`gh` v2.97.0+**. Historical releases (`v0.1.0`–`v0.3.0`) predate artifact attestations and are verified via `SHA256SUMS` only.

After release publication, verify the `SHA256SUMS` provenance attestation first, then validate checksums, archive/standalone binary attestations, and binary `--version` outputs inside an isolated temporary directory (`mktemp -d`, avoiding overwriting local `README.md`, `LICENSE`, or `CHANGELOG.md` files):

```bash
(
  set -euo pipefail
  verify_dir="$(mktemp -d)"
  trap 'rm -rf "$verify_dir"' EXIT
  cd "$verify_dir"

  # Inspect release metadata
  gh release view v0.4.0 --repo iinozemtsev-lab/dtfm

  # Download checksums, archive, and standalone binary
  curl -fLO https://github.com/iinozemtsev-lab/dtfm/releases/download/v0.4.0/SHA256SUMS
  curl -fLO https://github.com/iinozemtsev-lab/dtfm/releases/download/v0.4.0/dtfm_0.4.0_linux_amd64.tar.gz
  curl -fLO https://github.com/iinozemtsev-lab/dtfm/releases/download/v0.4.0/dtfm-linux-amd64

  # Expected source ref recorded in the Sigstore certificate:
  # - Option A (workflow_dispatch on main): refs/heads/main
  # - Option B (annotated tag push):        refs/tags/v0.4.0
  SOURCE_REF="refs/heads/main"

  # 1. Verify SLSA provenance of SHA256SUMS BEFORE trusting its digests
  gh attestation verify SHA256SUMS \
    --repo iinozemtsev-lab/dtfm \
    --deny-self-hosted-runners \
    --signer-workflow iinozemtsev-lab/dtfm/.github/workflows/release.yml \
    --source-ref "$SOURCE_REF"

  # 2. Verify SHA-256 checksums of each downloaded artifact (fails closed if an entry is missing, unlike --ignore-missing)
  grep -E '^[0-9a-f]{64}  dtfm_0\.4\.0_linux_amd64\.tar\.gz$' SHA256SUMS | sha256sum -c -
  grep -E '^[0-9a-f]{64}  dtfm-linux-amd64$' SHA256SUMS | sha256sum -c -

  # 3. Verify direct SLSA build provenance attestations on archive & standalone binary
  gh attestation verify dtfm_0.4.0_linux_amd64.tar.gz \
    --repo iinozemtsev-lab/dtfm \
    --deny-self-hosted-runners \
    --signer-workflow iinozemtsev-lab/dtfm/.github/workflows/release.yml \
    --source-ref "$SOURCE_REF"

  gh attestation verify dtfm-linux-amd64 \
    --repo iinozemtsev-lab/dtfm \
    --deny-self-hosted-runners \
    --signer-workflow iinozemtsev-lab/dtfm/.github/workflows/release.yml \
    --source-ref "$SOURCE_REF"

  # 4. Verify standalone and archived binary version strings
  chmod +x ./dtfm-linux-amd64
  ./dtfm-linux-amd64 --version

  tar -xzf dtfm_0.4.0_linux_amd64.tar.gz
  ./dtfm --version
  ./lmdtfy --version
  ./relay --version
)
```

- **Trigger-Agnostic Policy Alternative**: If a downstream verifier does not know whether a release was cut via Option A (`refs/heads/main`) or Option B (`refs/tags/v0.4.0`), replace `--signer-workflow ... --source-ref "$SOURCE_REF"` (which are mutually exclusive with `--cert-identity-regex`) with:
  ```bash
  gh attestation verify dtfm-linux-amd64 \
    --repo iinozemtsev-lab/dtfm \
    --deny-self-hosted-runners \
    --cert-identity-regex '^https://github\.com/iinozemtsev-lab/dtfm/\.github/workflows/release\.yml@(refs/heads/main|refs/tags/v0\.4\.0)$'
  ```
- **Source Commit Pinning**: Add `--source-digest <40-char-commit-sha>` to pin the exact Git commit recorded in the certificate (`$GITHUB_SHA`: the pre-finalization `main` parent commit under Option A, or the tagged `RELEASE_SHA` commit under Option B).
