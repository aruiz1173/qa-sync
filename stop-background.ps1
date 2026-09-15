$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StateDir = & (Join-Path $ProjectDir 'state-dir.ps1') -ProjectDir $ProjectDir
$PidFile = Join-Path $StateDir 'server.pid'
if (-not (Test-Path $PidFile)) { exit 0 }
$ServerPid = (Get-Content $PidFile -First 1) -as [int]
if (-not $ServerPid) { throw 'El archivo PID no es válido.' }
# El PID es del proceso Python que tiene el socket, no del wrapper de PowerShell:
# se comprueba contra 'qasync' para no matar un PID reciclado por otro programa.
$Process = Get-CimInstance Win32_Process -Filter "ProcessId = $ServerPid" -ErrorAction SilentlyContinue
if ($Process -and $Process.CommandLine -and $Process.CommandLine.Contains('qasync')) {
  Stop-Process -Id $ServerPid
}
Remove-Item $PidFile -ErrorAction SilentlyContinue
