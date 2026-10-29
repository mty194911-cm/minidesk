# MiniDesk relay installer for Windows Server (2016+). Run install.cmd from the unzipped package; re-run to upgrade.
#   - installs Python 3.12 for all users if no Python >= 3.9 is installed for all users (signature-checked)
#   - installs aiohttp and aioquic (UDP/WebTransport), copies the relay to C:\MiniDesk
#   - registers the startup task "MiniDeskRelay" running as LOCAL SERVICE (restarts if it crashes)
#   - opens the port in Windows Firewall (TCP and UDP), starts the relay and checks it is listening
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is very slow with the progress bar
$Dir = 'C:\MiniDesk'
$Task = 'MiniDeskRelay'
$PythonUrl = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
try {
$src = $PSScriptRoot
$conf = Get-Content (Join-Path $src 'relay.json') -Raw | ConvertFrom-Json
$port = [int]$conf.port

function Find-Python {
    # All-users installs only: the relay runs as LOCAL SERVICE, which cannot read per-user installs.
    $found = foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Python\PythonCore' -ErrorAction SilentlyContinue) {
        try { $v = [version]$k.PSChildName } catch { continue }
        $p = (Get-ItemProperty (Join-Path $k.PSPath 'InstallPath') -ErrorAction SilentlyContinue).'(default)'
        if ($v -ge [version]'3.9' -and $p -and (Test-Path (Join-Path $p 'pythonw.exe'))) { [pscustomobject]@{ V = $v; P = $p } }
    }
    ($found | Sort-Object V -Descending | Select-Object -First 1).P
}

Write-Host '[1/5] Python'
$py = Find-Python
if (-not $py) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $exe = Join-Path $env:TEMP 'python-3.12-amd64.exe'
    Write-Host "      downloading $PythonUrl"
    Invoke-WebRequest $PythonUrl -OutFile $exe -UseBasicParsing
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
        throw "Python installer signature check failed: $($sig.Status) $($sig.SignerCertificate.Subject)"
    }
    Start-Process $exe -Wait -ArgumentList '/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_test=0', 'Include_launcher=0'
    Remove-Item $exe
    $py = Find-Python
    if (-not $py) { throw 'Python installation failed' }
}
Write-Host "      $py"

Write-Host '[2/5] aiohttp, aioquic'
# aioquic pinned to versions tested with quic.py (it uses a few aioquic internals; 1.7 also changed an API)
& (Join-Path $py 'python.exe') -m pip install --quiet --disable-pip-version-check --upgrade aiohttp "aioquic>=1.3,<1.8"
if ($LASTEXITCODE) { throw 'pip install aiohttp aioquic failed' }

Write-Host "[3/5] files -> $Dir"
Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue  # upgrade: stop the old relay first
New-Item -ItemType Directory -Force (Join-Path $Dir 'logs') | Out-Null
Copy-Item -Recurse -Force (Join-Path $src 'relay.py'), (Join-Path $src 'quic.py'), (Join-Path $src 'web'), (Join-Path $src 'server.crt'), (Join-Path $src 'server.key') $Dir
# SIDs, not names: account names are localized. S-1-5-19 LOCAL SERVICE, S-1-5-18 SYSTEM, S-1-5-32-544 Administrators
icacls $Dir /grant '*S-1-5-19:(OI)(CI)RX' /Q | Out-Null
icacls (Join-Path $Dir 'logs') /grant '*S-1-5-19:(OI)(CI)M' /Q | Out-Null
icacls (Join-Path $Dir 'server.key') /inheritance:r /grant:r '*S-1-5-19:R' '*S-1-5-18:F' '*S-1-5-32-544:F' /Q | Out-Null

Write-Host "[4/5] firewall + startup task (port $port)"
for ($i = 0; $i -lt 10 -and ($busy = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue); $i++) {
    Start-Sleep -Milliseconds 500  # a stopped old relay may take a moment to release the port
}
if ($busy) {
    $owner = (Get-Process -Id $busy[0].OwningProcess -ErrorAction SilentlyContinue).Name
    throw "port $port is already used by '$owner'. Re-run deploy.py with --port 8443 (or stop that program)."
}
Remove-NetFirewallRule -DisplayName 'MiniDesk Relay' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'MiniDesk Relay' -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
New-NetFirewallRule -DisplayName 'MiniDesk Relay' -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow | Out-Null

$relayArgs = "`"$Dir\relay.py`" --port $port --token $($conf.token) --cert `"$Dir\server.crt`" " +
             "--key `"$Dir\server.key`" --log `"$Dir\logs\relay.log`""
$action = New-ScheduledTaskAction -Execute (Join-Path $py 'pythonw.exe') -Argument $relayArgs -WorkingDirectory $Dir
$trigger = New-ScheduledTaskTrigger -AtStartup
$account = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-19').Translate([Security.Principal.NTAccount]).Value
$principal = New-ScheduledTaskPrincipal -UserId $account -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host '[5/5] start'
Start-ScheduledTask -TaskName $Task
for ($i = 0; $i -lt 20 -and -not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue); $i++) {
    Start-Sleep -Milliseconds 500
}
if (-not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
    Get-Content (Join-Path $Dir 'logs\relay.log') -Tail 20 -ErrorAction SilentlyContinue
    throw "the relay did not start; see $Dir\logs\relay.log"
}
Write-Host ''
Write-Host "OK: MiniDesk relay is running on port $port and starts automatically with Windows." -ForegroundColor Green
Write-Host "Also allow TCP $port AND UDP $port in your cloud provider's security group / firewall."
Write-Host 'Delete the uploaded zip/folder: it contains the server key and token.'
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
} finally {
    Read-Host 'Press Enter to close'
}
