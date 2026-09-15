# Resolves the local state directory, mirroring qasync/state.py:state_root().
# Windows cannot express private permissions with chmod, so state lives under the
# user profile unless a project directory already exists or an operator overrides it.
param([Parameter(Mandatory = $true)][string]$ProjectDir)

$Legacy = Join-Path $ProjectDir '.qa-sync'
if ($env:QA_SYNC_STATE_DIR) { return $env:QA_SYNC_STATE_DIR }
if (Test-Path -LiteralPath $Legacy -PathType Container) { return $Legacy }
if ($env:LOCALAPPDATA) { return (Join-Path $env:LOCALAPPDATA 'QA Sync') }
return $Legacy
