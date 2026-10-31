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
