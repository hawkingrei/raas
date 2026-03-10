# AGENTS

## 2026-03-10 Retry Limit and UTC+8 Gate for High Attempts

Requirement:

1. Increase the automatic retest ceiling from 5 to 8 total attempts.
2. For PRs whose next retest would exceed 5:
   - Only allow execution within the UTC+8 `00:00-08:00` window.
   - Allow at most one `retry > 5` execution globally per hour.

## 2026-03-03 Auto `/ok-to-test` for Eligible Authors

Requirement:

1. Add a scheduled scan for recently opened PRs targeting `master`.
2. Scope:
   - PR does not have `ok-to-test` label.
   - CI has not triggered `fast_test_tiprow`.
   - PR author exists in `OWNERS_ALIASES` from `pingcap/tidb`.
3. Action:
   - Auto post `/ok-to-test` comment.
4. De-dup:
   - For the same PR, do not post duplicate `/ok-to-test` comments.

## 2026-02-02 CI Auto Retest Service (Cloudflare Worker + D1)

Goal: Build an automatic CI retest service using Cloudflare Worker and Cloudflare D1. UI and interactions should reference the existing ./raas style.

Requirements:

1. Scheduled scan of PRs updated within the last 2 days.
   - If GitHub CI status fails, post a `/retest` comment.
   - Retest is gated by a failure blacklist and backoff rules.

2. Failure blacklist:
   - If any failed check name is in the blacklist, ignore it and do not retest.
   - Hard block: if `fast_test_tiprow` fails, do not retest.
   - Current blacklist: `license/cla`, `pull-error-log-review`, `tide`, `check-issue-triage-complete`.

3. Backoff rules (per PR/CI attempt counter):
   - 1st retest: immediate.
   - 2nd: wait 10 minutes.
   - 3rd: wait 20 minutes.
   - 4th: wait 40 minutes.
   - 5th: wait 6 hours.
   - 6th and beyond: stop automatic retest.
   - If `attempt_count >= 5`, only reset to 0 after CI is confirmed recovered (no failures).
   - If latest PR head commit SHA differs from persisted state, reset `attempt_count` to 0.

4. Scan and concurrency:
   - Retest check interval is configurable.
   - Cron is supported.
   - Daytime retest concurrency is lower (per scan).
   - Nighttime retest concurrency is higher.
   - Timezone: Asia/Shanghai. Day max = 2, Night max = 5.

5. Webhook:
   - Webhook handling is paused/disabled for now.

6. UI:
   - UI should mimic ./raas style.
   - PRs must be registered via UI; unregistered PRs must not be checked.
   - Removing a PR should also delete retest_state and retest_attempts.
   - UI shows tracked PRs, last check status/time (success/failed/ignored/running), last error, and status log.

7. Tech stack:
   - Rust + TypeScript.
   - Use Wrangler.

Notes:

- When adding new requirements or context, append them to the top of this file so the latest content stays at the top.
