# Portable Release Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pushing a tag like `v1.1` builds the portable PyInstaller app into
`unipcap-1.1-win64.zip` and attaches it to a GitHub Release, with tests and a
smoke run gating the upload.

**Architecture:** `scripts/build.ps1` stays the single packaging entry point:
it builds the one-folder PyInstaller app and now also zips it, taking the
version as a parameter. A new tag-triggered GitHub Actions workflow on
`windows-latest` validates the tag, installs dev deps and Wireshark (the tests
need a real `tshark`), runs the suite, builds, smoke-tests the built folder,
and creates or updates the release with the zip.

**Tech Stack:** PowerShell 7, PyInstaller (one-folder, `--windowed`), `uv`,
GitHub Actions on `windows-latest`, `gh` CLI (preinstalled on runners),
Chocolatey (preinstalled) for Wireshark.

**Spec:** `docs/superpowers/specs/2026-10-29-unipcap-vision.md` — the
Portability and Test data decisions. The release-pipeline requirements
themselves come from the user request of 2026-10-31 (tags v1.1, v1.2, …; zip
artifact; GitHub Release uses it); the vision doc predates them.

## Global Constraints

- Version = git tag with the leading `v` stripped: `v1.1` → `1.1`. Allowed tag
  shapes: `v<major>.<minor>` or `v<major>.<minor>.<patch>` (digits only).
- Artifact: `dist/unipcap-<version>-win64.zip`, whose root entry is the
  `unipcap/` folder (`unipcap.exe`, `_internal/`, `THIRD_PARTY.md`). Unzipping
  must produce one folder, never loose files in the current directory.
- `scripts/build.ps1` default `-Version` is `dev` (local builds produce
  `unipcap-dev-win64.zip`); the workflow always passes the tag version.
- Workflow triggers only on `push` of tags matching `v*`, runs on
  `windows-latest`, declares `permissions: contents: write`, and uses only
  `${{ github.token }}` — no other secrets.
- Wireshark must be installed on the runner **before** `pytest`: the test
  suite calls a real `tshark`. The build must not bundle tshark (vision doc,
  Decoder row).
- Use `uv sync --extra dev` in CI — a bare `uv sync` removes pytest and
  PyInstaller (both live in `[project.optional-dependencies] dev`).
- `samples/*` stays git-ignored; only `samples/README.md` and
  `samples/*.expected.json` are trackable (vision doc, Test data row).
- No application code changes. Python stays `>=3.12,<3.13`.

## Review Focus

1. A tag that matches `v*` but not the version pattern (e.g. `vfinal`) must
   fail before anything is built or released — the validation step must run
   first; pinned by the step-order assertion in Task 3.
2. Re-running the workflow for a tag whose release already exists (after a
   partial failure) must succeed by uploading with `--clobber` instead of
   failing on "release already exists"; pinned by the text assertion in Task 3.
3. The zip must extract into a single `unipcap/` folder, not scatter 200+
   files into the user's current directory; pinned by the Expand-Archive check
   in Task 2.
4. The smoke run must exercise the same artifact that gets released — build,
   then smoke `dist\unipcap`, then upload; pinned by step-order assertions in
   Task 3.
5. The uploaded asset must carry the tag's version (`unipcap-1.1-win64.zip`),
   never the `dev` default; pinned by the YAML assertions that the build step
   passes `steps.version.outputs.version` and the publish step uses the same
   output.

Known verification limit: GitHub Actions cannot run locally and this checkout
has no git remote, so the first real execution is a tag push to a GitHub repo.
Local verification is the local build + smoke (Task 2) and a YAML structure
parse (Task 3).

---

### Task 1: Track sample expectations, keep captures ignored

**Files:**
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing later tasks consume.

Captures are already ignored by `samples/*` with `!samples/README.md`. But
`samples/README.md` and the spec tell users to put a `<name>.expected.json`
next to each capture, and the current rules ignore those too — so the
`tests/test_samples.py` expectations can never be committed. Keep the
captures ignored, re-include the expectations.

- [ ] **Step 1: Confirm the current behavior**

Run:
```bash
git check-ignore -v samples/demo.pcap samples/demo.expected.json samples/README.md
```
Expected: lines for `demo.pcap` (matches `samples/*`) and
`demo.expected.json` (also matches `samples/*` — this is the defect); no line
for `README.md`.

- [ ] **Step 2: Re-include expectation files**

Edit `.gitignore`, after the existing `!samples/README.md` line, add:
```gitignore
!samples/*.expected.json
```

- [ ] **Step 3: Verify the rules**

Run:
```bash
git check-ignore -q samples/demo.pcap            # exit 0: still ignored
git check-ignore -q samples/demo.expected.json; echo $?   # exit 1: not ignored
git check-ignore -q samples/README.md; echo $?            # exit 1: not ignored
```
Expected: `0`, `1`, `1` in that order.

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: track samples/*.expected.json, keep captures ignored"
```

---

### Task 2: Version the portable build and zip it

**Files:**
- Modify: `scripts/build.ps1`

**Interfaces:**
- Consumes: the existing PyInstaller invocation in `scripts/build.ps1`
  (`--windowed --name unipcap --add-data src/unipcap/web;unipcap/web --paths src
  scripts/launch.py`, then `THIRD_PARTY.md` copied into `dist\unipcap\`).
- Produces: CLI contract consumed by Task 3 —
  `pwsh scripts/build.ps1 [-Version <v>]` builds `dist\unipcap\` and writes
  `dist\unipcap-<v>-win64.zip` (default `<v>` = `dev`), printing
  `built <zip path>`; throws (nonzero exit) on failure. Rejects a `-Version`
  that is not `^[0-9A-Za-z][0-9A-Za-z._-]*$` (it becomes a file name).

- [ ] **Step 1: Confirm the current script ignores `-Version`**

Run:
```powershell
pwsh scripts/build.ps1 -Version 1.0-test
```
Expected: fails — `A parameter cannot be found that matches parameter name
'Version'` — and `dist\unipcap-1.0-test-win64.zip` does not exist.

- [ ] **Step 2: Implement the parameter and the zip**

`param(...)` must be the first statement of the script. Resulting script
(head of file and last line shown; the PyInstaller block in the middle is
unchanged):

```powershell
param([string]$Version = "dev")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') { throw "bad version: $Version" }
$pa = @("--noconfirm", "--windowed", "--name", "unipcap",
    "--add-data", "src/unipcap/web;unipcap/web")
uv run pyinstaller @pa --paths src scripts/launch.py
if ($LASTEXITCODE) { throw "pyinstaller failed" }
Copy-Item THIRD_PARTY.md dist\unipcap\ -Force
$zip = "dist\unipcap-$Version-win64.zip"
Compress-Archive -Path dist\unipcap -DestinationPath $zip -Force
Write-Host "built $zip"
```

- [ ] **Step 3: Build with an explicit version**

Run:
```powershell
pwsh scripts/build.ps1 -Version 1.0-test
```
Expected: exit 0, last line `built dist\unipcap-1.0-test-win64.zip`, and the
file exists.

- [ ] **Step 4: Verify the archive layout**

Run:
```powershell
$d = Join-Path $env:TEMP "unipcap-zipcheck"
Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive dist\unipcap-1.0-test-win64.zip -DestinationPath $d
Test-Path (Join-Path $d "unipcap\unipcap.exe")       # True
Test-Path (Join-Path $d "unipcap\THIRD_PARTY.md")    # True
(Get-ChildItem $d).Count                              # 1 (only the unipcap folder)
```
Expected: `True`, `True`, `1`. If the count is larger, `Compress-Archive` was
given the folder's contents rather than the folder — pass `dist\unipcap` (the
directory itself), not `dist\unipcap\*`.

- [ ] **Step 5: Smoke the freshly built folder**

Run:
```powershell
pwsh scripts/smoke.ps1
```
Expected: `headless OK`, `GUI server OK`, `SMOKE PASS` (it uses
`dist\unipcap`, the same folder that was zipped).

- [ ] **Step 6: Commit**

```bash
git add scripts/build.ps1
git commit -m "build: versioned portable zip from build.ps1"
```

---

### Task 3: Tag-triggered release workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `scripts/build.ps1 -Version <v>` from Task 2; its artifact at
  `dist/unipcap-<v>-win64.zip`; `scripts/smoke.ps1`.
- Produces: a GitHub Release named after the tag with the zip attached.

- [ ] **Step 1: Confirm the workflow does not exist yet**

Run:
```bash
test -f .github/workflows/release.yml; echo $?
```
Expected: `1` (missing).

- [ ] **Step 2: Create the workflow**

Create `.github/workflows/release.yml` with exactly:

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  release:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v5

      - name: Version from tag
        id: version
        run: |
          $tag = $env:GITHUB_REF_NAME
          if ($tag -notmatch '^v(?<v>\d+\.\d+(?:\.\d+)?)$') {
            throw "Tag '$tag' is not v<major>.<minor>[.<patch>]"
          }
          "version=$($Matches['v'])" >> $env:GITHUB_OUTPUT

      - name: Install dev dependencies
        run: uv sync --extra dev

      - name: Install Wireshark (the tests need a real tshark)
        run: choco install wireshark -y --no-progress

      - name: Test
        run: uv run python -m pytest -q

      - name: Build portable zip
        run: pwsh scripts/build.ps1 -Version "${{ steps.version.outputs.version }}"

      - name: Smoke test the portable build
        run: pwsh scripts/smoke.ps1

      - name: Publish release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          $tag = $env:GITHUB_REF_NAME
          $zip = "dist/unipcap-${{ steps.version.outputs.version }}-win64.zip"
          if (gh release view $tag *> $null) {
            gh release upload $tag $zip --clobber
          } else {
            gh release create $tag $zip --title $tag --generate-notes --verify-tag
          }
```

- [ ] **Step 3: Parse and check the structure**

Run:
```bash
uv run --with pyyaml python - <<'EOF'
import yaml
d = yaml.safe_load(open(".github/workflows/release.yml", encoding="utf-8"))
text = open(".github/workflows/release.yml", encoding="utf-8").read()
assert d[True]["push"]["tags"] == ["v*"]          # PyYAML reads `on` as True
assert d["permissions"] == {"contents": "write"}
job = d["jobs"]["release"]
assert job["runs-on"] == "windows-latest"
names = [s.get("name") for s in job["steps"]]
order = names.index
assert order("Version from tag") < order("Install Wireshark (the tests need a real tshark)") < order("Test")
assert order("Test") < order("Build portable zip") < order("Smoke test the portable build") < order("Publish release")
assert 'steps.version.outputs.version' in text
assert "--clobber" in text and "gh release create" in text
print("workflow structure OK")
EOF
```
Expected: `workflow structure OK`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: tag-driven release with the portable zip attached"
```

---

## Out of scope

- Pushing the repo, creating tags, or running the first GitHub release — this
  checkout has no remote; the user does that when ready.
- Version bumping in `pyproject.toml` / the app: the tag is the source of truth
  for releases.
- Code-signing, installers, auto-update.
