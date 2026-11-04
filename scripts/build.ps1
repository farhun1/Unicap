param([string]$Version = "dev")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') { throw "bad version: $Version" }
# PyInstaller deletes dist\unipcap first; that fails while the built app is running.
$running = @(Get-Process unipcap -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -like '*\dist\unipcap\*' })
if ($running) {
    throw "UniPCAP is running (PID $($running.Id -join ', ')); close it before building"
}
$pa = @("--noconfirm", "--windowed", "--name", "unipcap",
    "--add-data", "src/unipcap/web;unipcap/web")
uv run pyinstaller @pa --paths src scripts/launch.py
if ($LASTEXITCODE) { throw "pyinstaller failed" }
Copy-Item THIRD_PARTY.md dist\unipcap\ -Force
$zip = "dist\unipcap-$Version-win64.zip"
Compress-Archive -Path dist\unipcap -DestinationPath $zip -Force
Write-Host "built $zip"
