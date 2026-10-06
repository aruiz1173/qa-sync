# QA Sync security model

QA Sync is a local, single-user tool. Its HTTP server binds only to loopback and rejects non-loopback `Host`, cross-origin `Origin`, cross-site fetches and non-JSON mutation bodies. These checks mitigate DNS rebinding and browser-driven CSRF against localhost.

## Implemented controls

- Screenshots are encrypted with AES-256-GCM. Keys are stored in macOS Keychain or protected with Windows DPAPI.
- `.env` is parsed as literal data; it is never sourced by a shell and performs no expansion.
- External HTTP redirects are rejected so authorization headers cannot be forwarded to a redirected host.
- TestRail and Appium URLs reject embedded credentials, queries and fragments; remote endpoints require HTTPS.
- Codex and Claude receive an allowlisted environment instead of inheriting arbitrary secrets.
- The macOS background launcher keeps a private runtime copy of the app and `.env` under `~/Library/Application Support/QA Sync/runtimes/` because launchd cannot read this project reliably from Downloads. Runtime files and migrated state are restricted to the current user; the original state is retained for recovery.
- CLI and device-tool executables are resolved to canonical paths and rejected when the binary or a parent directory is group/world writable on POSIX; Windows launchers use the protected system PowerShell path.
- Windows executables resolved for device/provider tools must pass native Authenticode verification, or match a SHA-256 explicitly pinned by the operator in `QA_SYNC_TRUSTED_HASHES`. On POSIX, a binary below a group/world-writable directory also needs that explicit pin. The official scrcpy release for Windows ships unsigned, and Homebrew commonly uses shared directories on macOS, so a pin is the only way to trust those exact builds; the rejection message reports the binary's hash and nothing is trusted until that hash is written down.
- CLI analysis uses temporary private directories, read-only/restricted tool modes and no session persistence.
- Device XML rejects DTD/entity declarations before parsing, and TestRail/context fields are allowlisted and size-bounded before reaching a model.
- Provider prompts explicitly treat screenshots, device text, context and existing cases as untrusted data rather than instructions.
- The operator chooses per analysis whether to redact test-account passwords/codes (initial choice) or preserve them in prompts and proposals. API keys, access tokens and configured TestRail/provider keys stay redacted in text under either choice. The cache separates these policies and the prompt version invalidates older entries.
- The evidence review asks the operator to inspect selected screenshots for visible secrets before analysis. Text redaction cannot remove values embedded in pixels or unlabeled credentials.
- External error details and local diagnostic reports redact identifiable authentication values and configured API keys.
- State directories and files are written with private permissions where the operating system supports them (`0700`/`0600` on POSIX). Windows `chmod` cannot express an ACL, so state defaults to `%LOCALAPPDATA%\QA Sync`, which only the current account can read; a `QA_SYNC_STATE_DIR` override is the operator's responsibility to secure.
- The browser receives CSP, frame denial, permissions policy, no-store and MIME-sniffing protection.
- Requests, responses, image counts, recording duration and pagination are bounded.
- Python dependencies are exactly pinned in a cross-platform hash lock; CI installs with `--require-hashes` and emits a CycloneDX SBOM.
- The local server caps concurrent request threads, and device observations and CLI output have hard size limits.
- Audit and device-matrix data remain local.

## Trust boundaries and residual risk

- A user or process that can modify the installed source code can also alter these controls.
- No application-level control can isolate QA Sync from a malicious process already executing as the same OS user. Use managed endpoints, least privilege and OS malware protections for that boundary.
- A configured TestRail or Appium endpoint is trusted by the user. Remote endpoints should use valid TLS and least-privilege accounts.
- TestRail does not expose a compare-and-swap update in this client; a teammate could modify a case between the final read and write. Backups and rollback conflict checks reduce impact but cannot make that remote race atomic.
- Immediately before an update, QA Sync now refuses stale proposals by re-reading and comparing every changed field. TestRail still cannot make the following read/write pair fully atomic.
- Provider CLI executables remain trusted local software after path-permission checks. Managed installations should inventory versions; on Windows a signature is verified and an unsigned binary needs its hash pinned as described above.
- A malicious process already running as the same OS user can invoke localhost APIs and read that user's files; QA Sync does not attempt to sandbox the entire user account.
- Mobile screenshots may contain sensitive source data before redaction. Use test accounts and synthetic data.
- Model output is untrusted and never writes to TestRail without exact user confirmation.
- SSO and installer signing are intentionally outside the current scope.

Report suspected vulnerabilities privately to the owning engineering team; do not include credentials, customer data or raw screenshots in a report.
