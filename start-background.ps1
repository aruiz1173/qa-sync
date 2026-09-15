$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StateDir = & (Join-Path $ProjectDir 'state-dir.ps1') -ProjectDir $ProjectDir
$PidFile = Join-Path $StateDir 'server.pid'
$LogFile = Join-Path $StateDir 'server.log'
$ErrorLogFile = Join-Path $StateDir 'server-error.log'
$Url = 'http://127.0.0.1:8787/'
$PowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $PowerShell -PathType Leaf)) {
  throw 'No se encontró Windows PowerShell en la ruta protegida del sistema.'
}
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

function Test-QASync {
  try {
    $Response = Invoke-WebRequest -UseBasicParsing -Uri ($Url + 'api/status') -TimeoutSec 2
    return $Response.StatusCode -eq 200
  } catch { return $false }
}

if (Test-QASync) { Start-Process $Url; exit 0 }

# El PID lo publica el propio servidor; si sigue vivo, ya hay una instancia.
if (Test-Path $PidFile) {
  $OldPid = (Get-Content $PidFile -First 1) -as [int]
  $OldProcess = if ($OldPid) { Get-CimInstance Win32_Process -Filter "ProcessId = $OldPid" -ErrorAction SilentlyContinue }
  if ($OldProcess -and $OldProcess.CommandLine -and $OldProcess.CommandLine.Contains('qasync')) {
    throw "QA Sync ya está iniciando, pero todavía no responde. Revisa $ErrorLogFile."
  }
}

$RunScriptArgument = '"' + (Join-Path $ProjectDir 'run.ps1') + '"'
$Process = Start-Process -FilePath $PowerShell -ArgumentList @(
  '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $RunScriptArgument
) -WorkingDirectory $ProjectDir -WindowStyle Hidden -RedirectStandardOutput $LogFile -RedirectStandardError $ErrorLogFile -PassThru

for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
  if (Test-QASync) { Start-Process $Url; exit 0 }
  if ($Process.HasExited) { Start-Process $ErrorLogFile; exit 1 }
  Start-Sleep -Milliseconds 200
}
Start-Process $ErrorLogFile
exit 1
