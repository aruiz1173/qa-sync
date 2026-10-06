# QA Sync · Requirements

## Purpose

QA Sync is a standalone local application that converts a real Android or iOS test walkthrough into a reviewable proposal, and deterministically executes existing TestRail steps against a selected device.

## Required behavior

- Show TestRail projects, runs, tests, and existing test-case details.
- Let a person select Android or iOS and an available device.
- Support Android through ADB and scrcpy; support Android Wireless Debugging only with private or local IP addresses.
- Support iOS Simulator locally and Appium/XCUITest for configured iOS devices.
- Capture distinct screenshots and available accessibility metadata while a walkthrough runs.
- Offer guided interaction when possible and preserve evidence before and after guided actions.
- Use a user-selected vision provider: Codex, Claude, or OpenAI API. Never choose a provider automatically.
- Offer Efficient, High, and Maximum analysis budgets with visible frame and request usage.
- Generate a title, preconditions, ordered steps, expected results, confidence, and uncertainty warnings.
- Let the person edit, add, delete, reorder, and mark proposed steps optional before applying changes.
- Update TestRail only after explicit confirmation and stale-case verification.
- Execute existing steps through guided ADB or Appium/XCUITest control and capture the settled screen after each action.
- Compare each expected result with visible evidence, require manual review below the configured confidence threshold, and permit an explicit manual override.
- Keep encrypted before/after checkpoints per step and require a stable post-action screen plus accessibility state before accepting an automatic verdict.
- Calculate Passed, Failed, or Blocked from final per-step verdicts. Only explicitly optional steps may be skipped.
- Publish a test result only when the person opts in and types the exact test-specific confirmation; never retry an uncertain result write automatically.
- Keep local encrypted evidence, recover interrupted recordings, and preserve audit/history records.

## Safety and privacy

- The application listens only on loopback by default.
- Do not expose API keys or credentials to the browser, logs, model prompts, audit exports, or ZIP artifacts.
- Exclude `.env`, `.qa-sync`, caches, and temporary evidence from distributable archives.
- Treat OCR, accessibility text, TestRail text, and model output as untrusted data.
- Redact or avoid personal, credential, payment, and customer data in generated proposals.
- Clearing Android app data is destructive and must require an explicit per-run confirmation and package name.

## Product boundaries

- QA Sync is its own standalone UI and runtime. It must not depend on Block App Kit, Block-specific dashboards, brokers, or internal runtimes.
- Do not publish, deploy, or send changes externally unless the user explicitly requests it.
- SSO and package signing are out of scope for now.
- Live E2E tests require an explicitly configured non-production TestRail environment, provider account, and mobile device/emulator/simulator; do not run them implicitly.

## Verification

- Run `python3 scripts/ci.py` before delivery.
- Keep deterministic unit tests for validation, security controls, provider behavior, Android/iOS recording, and TestRail write guards.
- Report when live device or TestRail validation could not run because required local tools or credentials are unavailable.
