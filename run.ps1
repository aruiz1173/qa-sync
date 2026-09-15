$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

# Logs y salida en UTF-8 como el resto de los archivos del proyecto, no en el codepage
# ANSI heredado. Se declara antes de .env para que se pueda sobrescribir desde ahí.
$env:PYTHONUTF8 = '1'

$EnvFile = Join-Path $ProjectDir '.env'
if (Test-Path $EnvFile) {
  foreach ($Line in Get-Content $EnvFile) {
    $Trimmed = $Line.Trim()
    if (-not $Trimmed -or $Trimmed.StartsWith('#') -or -not $Trimmed.Contains('=')) { continue }
    $Name, $Value = $Trimmed.Split('=', 2)
    $ParsedValue = $Value.Trim()
    if ($ParsedValue.Length -ge 2 -and (($ParsedValue.StartsWith("'") -and $ParsedValue.EndsWith("'")) -or ($ParsedValue.StartsWith('"') -and $ParsedValue.EndsWith('"')))) {
      $ParsedValue = $ParsedValue.Substring(1, $ParsedValue.Length - 2)
    }
    [Environment]::SetEnvironmentVariable($Name.Trim(), $ParsedValue, 'Process')
  }
}

if (Get-Command py.exe -ErrorAction SilentlyContinue) {
  & py.exe -3 -m qasync @args
} elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
  & python.exe -m qasync @args
} else {
  throw 'Python 3 no está instalado o no está en PATH.'
}
exit $LASTEXITCODE
