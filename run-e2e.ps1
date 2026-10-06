# Explicit, non-writing smoke checks for a dedicated QA TestRail sandbox.
if ($env:QA_SYNC_E2E_CONFIRM_SANDBOX -ne 'yes') {
  Write-Error 'Refusing to run. Set QA_SYNC_E2E_CONFIRM_SANDBOX=yes after confirming the configured TestRail account is a sandbox.'
  exit 2
}
if ([string]::IsNullOrWhiteSpace($env:QA_SYNC_E2E_CASE_ID)) {
  Write-Error 'Set QA_SYNC_E2E_CASE_ID to the dedicated sandbox case.'
  exit 2
}

$env:QA_SYNC_E2E = '1'
$env:QA_SYNC_WRITE_MODE = 'review_only'
python -m unittest tests.test_e2e_live -v
exit $LASTEXITCODE
