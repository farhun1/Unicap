Set-Location (Join-Path $PSScriptRoot "..")
function Fail($m) { Write-Host "SMOKE FAIL: $m"; throw $m }
$dir = Join-Path $env:TEMP "unipcap smoke রহিম"
$out = Join-Path $env:TEMP "smoke.json"
$port = Get-Random -Minimum 20000 -Maximum 60000
$gui = $null
$oldPath = $env:PATH
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item dist\unipcap $dir -Recurse
try {
    if (-not (Test-Path (Join-Path $dir "THIRD_PARTY.md"))) { Fail "missing THIRD_PARTY.md" }
    if (Test-Path (Join-Path $dir "_internal\vendor")) { Fail "vendor folder still bundled" }
    Remove-Item $out -ErrorAction SilentlyContinue
    # minimal PATH and no override: proves the installed Wireshark is found without a bundled copy
    $env:PATH = "C:\Windows\System32"
    Remove-Item Env:UNIPCAP_TSHARK -ErrorAction SilentlyContinue
    $p = Start-Process (Join-Path $dir unipcap.exe) -ArgumentList "--analyze", (Resolve-Path tests\fixtures\gtpv2_csr.pcap), "--out", $out -PassThru
    if (-not $p.WaitForExit(120000)) { Stop-Process $p -Force; Fail "headless run timed out" }
    if ($p.ExitCode -ne 0) { Fail "exit code $($p.ExitCode)" }
    $j = Get-Content $out -Raw -Encoding UTF8 | ConvertFrom-Json
    $n = $j.nodes | Where-Object { $_.ip -eq "10.5.0.1" }
    if (-not $n -or $n.roles -notcontains "PGW") { Fail "10.5.0.1 PGW missing" }
    Write-Host "headless OK"

    # browser UI: the loopback server must answer /ping
    $gui = Start-Process (Join-Path $dir unipcap.exe) -ArgumentList "--no-browser", "--port", $port -PassThru
    $r = $null
    $deadline = (Get-Date).AddSeconds(20)
    while (-not $r -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try { $r = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/ping" -TimeoutSec 2 } catch { }
    }
    if (-not $r -or $r.StatusCode -ne 204) { Fail "UI server did not answer /ping within 20 s" }
    Write-Host "GUI server OK"
    Write-Host "SMOKE PASS"
} catch {
    Write-Host "SMOKE FAIL: $_"
    exit 1
} finally {
    $env:PATH = $oldPath
    if ($gui) { & taskkill.exe /F /T /PID $gui.Id *> $null }
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
