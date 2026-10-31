"""Semantic checks of the release workflow's PowerShell.

The workflow cannot run locally (no remote, no GitHub), and text assertions on
the YAML cannot catch PowerShell semantics — `if (gh release view $tag *> $null)`
is always false because `if` tests emitted output, not the exit code. These
tests execute the workflow's publish block against a stub `gh` and check which
branch it takes.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "release.yml"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")

STUB_GH = (
    "@echo off\r\n"
    'echo %*>>"%~dp0calls.log"\r\n'
    'if /i "%~2"=="view" if exist "%~dp0no-release" exit /b 1\r\n'
    "exit /b 0\r\n"
)


def publish_script():
    text = WORKFLOW.read_text(encoding="utf-8")
    m = re.search(r"- name: Publish release.*?run: \|\n(.*)", text, re.S)
    assert m, "publish step not found"
    return "\n".join(
        line[10:] if line.startswith(" " * 10) else line
        for line in m.group(1).splitlines()
    ).rstrip()


def run_publish(tmp_path, release_exists):
    stub = tmp_path / "gh.cmd"
    stub.write_text(STUB_GH, encoding="ascii")
    if not release_exists:
        (tmp_path / "no-release").touch()
    script = publish_script().replace("${{ steps.version.outputs.version }}", "1.1")
    env = os.environ.copy()
    env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]
    env["GH_TOKEN"] = "x"
    env["GITHUB_REF_NAME"] = "v1.1"
    subprocess.run(["pwsh", "-NoProfile", "-Command", script], env=env, check=True,
                   capture_output=True)
    return (tmp_path / "calls.log").read_text(encoding="ascii")


def test_publish_uploads_with_clobber_when_release_exists(tmp_path):
    log = run_publish(tmp_path, release_exists=True)
    assert "upload v1.1 dist/unipcap-1.1-win64.zip --clobber" in log
    assert "create" not in log


def test_publish_creates_the_release_when_missing(tmp_path):
    log = run_publish(tmp_path, release_exists=False)
    assert ("create v1.1 dist/unipcap-1.1-win64.zip --title v1.1 "
            "--generate-notes --verify-tag") in log
    assert "upload" not in log
