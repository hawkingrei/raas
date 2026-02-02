import { Hono } from 'hono';

type CheckStatus = 'ignored' | 'success' | 'failed' | 'running';
type CheckStatusWithUnknown = CheckStatus | 'unknown';

type RetestStateRow = {
  pr_number: number;
  attempt_count: number;
  next_retest_at: string | null;
  disabled_at: string | null;
  last_failure_checks: string | null;
  last_seen_updated_at: string | null;
  last_check_status: CheckStatusWithUnknown | null;
  last_check_at: string | null;
  last_error_message: string | null;
  last_status_log: string | null;
};

type RetestAttemptRow = {
  id: number;
  pr_number: number;
  attempt_index: number;
  scheduled_at: string;
};

export interface Env {
  DB: D1Database;
  GITHUB_TOKEN: string;
  CHECK_BLACKLIST: string;
  SCAN_LOOKBACK_HOURS?: string;
  SCAN_INTERVAL_MINUTES?: string;
  DAY_MAX_RETESTS?: string;
  NIGHT_MAX_RETESTS?: string;
  TIMEZONE?: string;
  GITHUB_WEBHOOK_SECRET?: string;
}

const app = new Hono<{ Bindings: Env }>();

const DEFAULT_LOOKBACK_HOURS = 48;
const DEFAULT_SCAN_INTERVAL_MINUTES = 10;
const DEFAULT_DAY_MAX_RETESTS = 2;
const DEFAULT_NIGHT_MAX_RETESTS = 5;
const BACKOFF_MINUTES = [0, 10, 20, 4, 360];
const CRON_INTERVAL_MINUTES = 5;
const REPO_OWNER = 'pingcap';
const REPO_NAME = 'tidb';
const BLOCKED_CHECK = 'fast_test_tiprow';

function nowIso(): string {
  return new Date().toISOString();
}

function parseCsv(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseNumber(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function isNightInShanghai(now: Date): boolean {
  const utcHour = now.getUTCHours();
  const shanghaiHour = (utcHour + 8) % 24;
  return shanghaiHour >= 18 || shanghaiHour < 9;
}

function getMaxRetests(now: Date, env: Env): number {
  const dayMax = parseNumber(env.DAY_MAX_RETESTS, DEFAULT_DAY_MAX_RETESTS);
  const nightMax = parseNumber(env.NIGHT_MAX_RETESTS, DEFAULT_NIGHT_MAX_RETESTS);
  return isNightInShanghai(now) ? nightMax : dayMax;
}

async function githubRequest<T>(path: string, token: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'retest-as-a-service',
      ...(init && init.headers ? init.headers : {}),
    },
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`GitHub request failed: ${response.status} ${response.statusText} ${text}`);
  }

  return (await response.json()) as T;
}

type PullItem = {
  number: number;
  updated_at: string;
  head: { sha: string };
  state: string;
};

type PullDetail = PullItem;

async function getPullByNumber(token: string, prNumber: number): Promise<PullDetail> {
  return await githubRequest<PullDetail>(
    `/repos/${REPO_OWNER}/${REPO_NAME}/pulls/${prNumber}`,
    token
  );
}

async function getTrackedPrNumbers(env: Env): Promise<number[]> {
  const rows = await env.DB.prepare('SELECT pr_number FROM tracked_prs ORDER BY pr_number ASC')
    .all<{ pr_number: number }>();
  return (rows.results || []).map((row) => row.pr_number);
}

type CommitStatusResponse = {
  statuses: Array<{ context: string; state: string }>;
};

type CheckStateSummary = {
  failed: string[];
  hasPending: boolean;
};

async function getCheckStateSummary(sha: string, token: string): Promise<CheckStateSummary> {
  const data = await githubRequest<CommitStatusResponse>(
    `/repos/${REPO_OWNER}/${REPO_NAME}/commits/${sha}/status`,
    token
  );

  const failed: string[] = [];
  let hasPending = false;
  for (const status of data.statuses) {
    if (status.state === 'failure' || status.state === 'error') {
      failed.push(status.context);
    } else if (status.state === 'pending') {
      hasPending = true;
    }
  }

  return { failed, hasPending };
}

function classifyChecks(
  failedChecks: string[],
  hasPending: boolean,
  blacklist: Set<string>
): { status: CheckStatus; shouldRetest: boolean; log: string } {
  if (failedChecks.includes(BLOCKED_CHECK)) {
    return { status: 'ignored', shouldRetest: false, log: `Blocked check: ${BLOCKED_CHECK}` };
  }
  if (failedChecks.some((name) => blacklist.has(name))) {
    return { status: 'ignored', shouldRetest: false, log: 'Ignored by blacklist' };
  }
  if (failedChecks.length === 0 && !hasPending) {
    return { status: 'success', shouldRetest: false, log: 'No failed checks' };
  }
  if (failedChecks.length === 0 && hasPending) {
    return { status: 'running', shouldRetest: false, log: 'Checks pending' };
  }
  return { status: 'failed', shouldRetest: true, log: 'Failed checks detected' };
}

async function postRetestComment(prNumber: number, token: string): Promise<void> {
  await githubRequest(
    `/repos/${REPO_OWNER}/${REPO_NAME}/issues/${prNumber}/comments`,
    token,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: '/retest' }),
    }
  );
}

async function getSetting(env: Env, key: string): Promise<string | null> {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first<{ value: string }>();
  return row?.value ?? null;
}

async function setSetting(env: Env, key: string, value: string): Promise<void> {
  await env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .bind(key, value)
    .run();
}

async function upsertRetestState(
  env: Env,
  pr: PullItem,
  failedChecks: string[],
  status: CheckStatus,
  checkedAt: string,
  statusLog: string
): Promise<void> {
  const failedJson = JSON.stringify(failedChecks);
  await env.DB.prepare(
    `INSERT INTO retest_state (pr_number, attempt_count, last_seen_updated_at, last_failure_checks, last_check_status, last_check_at, last_status_log)
     VALUES (?, 0, ?, ?, ?, ?, ?)
     ON CONFLICT(pr_number) DO UPDATE SET last_seen_updated_at = excluded.last_seen_updated_at,
       last_failure_checks = excluded.last_failure_checks,
       last_check_status = excluded.last_check_status,
       last_check_at = excluded.last_check_at,
       last_status_log = excluded.last_status_log`
  )
    .bind(pr.number, pr.updated_at, failedJson, status, checkedAt, statusLog)
    .run();
}

async function getRetestState(env: Env, prNumber: number): Promise<RetestStateRow | null> {
  const row = await env.DB.prepare(
    `SELECT pr_number, attempt_count, next_retest_at, disabled_at, last_failure_checks, last_seen_updated_at, last_check_status, last_check_at, last_error_message, last_status_log
     FROM retest_state WHERE pr_number = ?`
  )
    .bind(prNumber)
    .first<RetestStateRow>();
  return row ?? null;
}

async function deleteTrackedPrData(env: Env, prNumber: number): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM tracked_prs WHERE pr_number = ?').bind(prNumber),
    env.DB.prepare('DELETE FROM retest_attempts WHERE pr_number = ?').bind(prNumber),
    env.DB.prepare('DELETE FROM retest_state WHERE pr_number = ?').bind(prNumber),
  ]);
}

async function resetAttemptsIfRecovered(env: Env, prNumber: number): Promise<void> {
  await env.DB.prepare(
    'UPDATE retest_state SET attempt_count = 0, disabled_at = NULL, next_retest_at = NULL, last_error_message = NULL, last_status_log = ? WHERE pr_number = ?'
  )
    .bind('CI recovered, reset attempts', prNumber)
    .run();
  await env.DB.prepare('DELETE FROM retest_attempts WHERE pr_number = ? AND executed_at IS NULL')
    .bind(prNumber)
    .run();
}

async function getPendingAttempt(env: Env, prNumber: number): Promise<RetestAttemptRow | null> {
  const row = await env.DB.prepare(
    `SELECT id, pr_number, attempt_index, scheduled_at
     FROM retest_attempts
     WHERE pr_number = ? AND executed_at IS NULL
     ORDER BY scheduled_at ASC
     LIMIT 1`
  )
    .bind(prNumber)
    .first<RetestAttemptRow>();
  return row ?? null;
}

async function scheduleNextAttempt(env: Env, prNumber: number, attemptCount: number): Promise<void> {
  if (attemptCount >= BACKOFF_MINUTES.length) {
    await env.DB.prepare(
      'UPDATE retest_state SET disabled_at = ?, next_retest_at = NULL, last_status_log = ? WHERE pr_number = ?'
    )
      .bind(nowIso(), 'Reached max attempts', prNumber)
      .run();
    return;
  }

  const delayMinutes = BACKOFF_MINUTES[attemptCount];
  const scheduledAt = new Date(Date.now() + delayMinutes * 60 * 1000).toISOString();
  const attemptIndex = attemptCount + 1;

  await env.DB.prepare(
    'INSERT INTO retest_attempts (pr_number, attempt_index, scheduled_at, status) VALUES (?, ?, ?, ?)'
  )
    .bind(prNumber, attemptIndex, scheduledAt, 'scheduled')
    .run();

  await env.DB.prepare('UPDATE retest_state SET next_retest_at = ? WHERE pr_number = ?')
    .bind(scheduledAt, prNumber)
    .run();
  await env.DB.prepare('UPDATE retest_state SET last_status_log = ? WHERE pr_number = ?')
    .bind(`Scheduled retest at ${scheduledAt}`, prNumber)
    .run();
}

async function scheduleImmediateAttempt(env: Env, prNumber: number, attemptCount: number): Promise<void> {
  if (attemptCount >= BACKOFF_MINUTES.length) {
    await env.DB.prepare(
      'UPDATE retest_state SET disabled_at = ?, next_retest_at = NULL, last_status_log = ? WHERE pr_number = ?'
    )
      .bind(nowIso(), 'Reached max attempts', prNumber)
      .run();
    return;
  }

  const scheduledAt = nowIso();
  const attemptIndex = attemptCount + 1;

  await env.DB.prepare(
    'INSERT INTO retest_attempts (pr_number, attempt_index, scheduled_at, status) VALUES (?, ?, ?, ?)'
  )
    .bind(prNumber, attemptIndex, scheduledAt, 'scheduled')
    .run();

  await env.DB.prepare('UPDATE retest_state SET next_retest_at = ? WHERE pr_number = ?')
    .bind(scheduledAt, prNumber)
    .run();
  await env.DB.prepare('UPDATE retest_state SET last_status_log = ? WHERE pr_number = ?')
    .bind('Scheduled immediate retest', prNumber)
    .run();
}

async function scanAndSchedule(env: Env): Promise<void> {
  const token = env.GITHUB_TOKEN;
  const lookbackHours = parseNumber(env.SCAN_LOOKBACK_HOURS, DEFAULT_LOOKBACK_HOURS);
  const blacklist = new Set(parseCsv(env.CHECK_BLACKLIST));

  const tracked = await getTrackedPrNumbers(env);
  if (tracked.length === 0) {
    console.log('No tracked PRs, skipping scan.');
    return;
  }

  const cutoffMs = Date.now() - lookbackHours * 60 * 60 * 1000;
  const prPromises = tracked.map((prNumber) =>
    getPullByNumber(token, prNumber)
      .then((pr) => ({ status: 'fulfilled' as const, value: pr, prNumber }))
      .catch((error) => ({ status: 'rejected' as const, reason: error, prNumber }))
  );
  const results = await Promise.all(prPromises);

  for (const result of results) {
    if (result.status === 'rejected') {
      console.error(`Failed to fetch PR #${result.prNumber}:`, result.reason);
      continue;
    }
    const pr = result.value;

    if (pr.state !== 'open') {
      await deleteTrackedPrData(env, result.prNumber);
      continue;
    }

    const updatedMs = Date.parse(pr.updated_at);
    if (!Number.isFinite(updatedMs) || updatedMs < cutoffMs) continue;

    const summary = await getCheckStateSummary(pr.head.sha, token);
    const checkResult = classifyChecks(summary.failed, summary.hasPending, blacklist);
    await upsertRetestState(env, pr, summary.failed, checkResult.status, nowIso(), checkResult.log);
    const state = await getRetestState(env, pr.number);
    if (!state) continue;
    if (checkResult.status === 'success' && state.attempt_count >= BACKOFF_MINUTES.length) {
      await resetAttemptsIfRecovered(env, pr.number);
      continue;
    }
    if (!checkResult.shouldRetest) continue;
    if (state.disabled_at) continue;

    const pending = await getPendingAttempt(env, pr.number);
    if (pending) continue;

    await scheduleNextAttempt(env, pr.number, state.attempt_count);
  }
}

async function executeDueAttempts(env: Env): Promise<void> {
  const maxRetests = getMaxRetests(new Date(), env);
  const now = nowIso();

  const rows = await env.DB.prepare(
    `SELECT id, pr_number, attempt_index, scheduled_at
     FROM retest_attempts
     WHERE executed_at IS NULL AND scheduled_at <= ?
     ORDER BY scheduled_at ASC
     LIMIT ?`
  )
    .bind(now, maxRetests)
    .all<RetestAttemptRow>();

  const attempts = rows.results || [];
  for (const attempt of attempts) {
    let status = 'success';
    let errorMessage: string | null = null;
    try {
      await postRetestComment(attempt.pr_number, env.GITHUB_TOKEN);
    } catch (error) {
      status = 'error';
      errorMessage = error instanceof Error ? error.message : String(error);
    }

    await env.DB.prepare(
      'UPDATE retest_attempts SET executed_at = ?, status = ?, error_message = ? WHERE id = ?'
    )
      .bind(now, status, errorMessage, attempt.id)
      .run();

    const state = await getRetestState(env, attempt.pr_number);
    if (!state) continue;

    const nextAttemptCount = state.attempt_count + 1;
    const disable = nextAttemptCount >= BACKOFF_MINUTES.length;
    const statusLog = status === 'success' ? 'Retest comment posted' : `Retest failed: ${errorMessage ?? 'unknown'}`;
    await env.DB.prepare(
      'UPDATE retest_state SET attempt_count = ?, last_retest_at = ?, next_retest_at = NULL, disabled_at = ?, last_error_message = ?, last_status_log = ? WHERE pr_number = ?'
    )
      .bind(nextAttemptCount, now, disable ? now : null, errorMessage, statusLog, attempt.pr_number)
      .run();

  }
}

async function shouldScan(env: Env): Promise<boolean> {
  const intervalMinutes = parseNumber(env.SCAN_INTERVAL_MINUTES, DEFAULT_SCAN_INTERVAL_MINUTES);
  const lastScan = await getSetting(env, 'last_scan_at');
  if (!lastScan) return true;

  const lastMs = Date.parse(lastScan);
  if (!Number.isFinite(lastMs)) return true;
  return Date.now() - lastMs >= intervalMinutes * 60 * 1000;
}

async function handleCron(env: Env): Promise<void> {
  if (await shouldScan(env)) {
    await scanAndSchedule(env);
    await setSetting(env, 'last_scan_at', nowIso());
  }

  await executeDueAttempts(env);
}

async function recordCronRun(env: Env, runId: string, patch: { status: string; errorMessage?: string | null }): Promise<void> {
  await env.DB.prepare(
    'UPDATE cron_runs SET finished_at = ?, status = ?, error_message = ? WHERE run_id = ?'
  )
    .bind(nowIso(), patch.status, patch.errorMessage ?? null, runId)
    .run();
}

async function runCronWithMeta(event: ScheduledEvent, env: Env): Promise<void> {
  const runId = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO cron_runs (run_id, scheduled_time_ms, cron, status) VALUES (?, ?, ?, ?)'
  )
    .bind(runId, (event as unknown as { scheduledTime?: number }).scheduledTime ?? null, (event as unknown as { cron?: string }).cron ?? null, 'started')
    .run();

  try {
    await handleCron(env);
    await recordCronRun(env, runId, { status: 'success', errorMessage: null });
  } catch (error) {
    const message = error instanceof Error ? (error.stack || error.message) : String(error);
    await recordCronRun(env, runId, { status: 'error', errorMessage: message });
  }
}

function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) return false;
  const aBytes = new Uint8Array(a);
  const bBytes = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < aBytes.length; i += 1) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

async function verifyWebhookSignature(secret: string, body: ArrayBuffer, signature: string | null): Promise<boolean> {
  if (!signature || !signature.startsWith('sha256=')) return false;
  const sigHex = signature.slice('sha256='.length);
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const digest = await crypto.subtle.sign('HMAC', key, body);
  const expected = new Uint8Array(digest);
  const provided = new Uint8Array(sigHex.match(/.{1,2}/g)?.map((b) => parseInt(b, 16)) || []);
  return timingSafeEqual(expected.buffer, provided.buffer);
}

app.post('/webhook/github', async (c) => {
  return c.json({ ok: true, disabled: true });
});


app.post('/track/:num', async (c) => {
  const num = Number(c.req.param('num'));
  if (!Number.isFinite(num) || num <= 0) return c.json({ error: 'Invalid PR number' }, 400);

  try {
    const pr = await getPullByNumber(c.env.GITHUB_TOKEN, num);
    const blacklist = new Set(parseCsv(c.env.CHECK_BLACKLIST));
    const summary = await getCheckStateSummary(pr.head.sha, c.env.GITHUB_TOKEN);
    const checkResult = classifyChecks(summary.failed, summary.hasPending, blacklist);

    await c.env.DB.prepare('INSERT OR IGNORE INTO tracked_prs (pr_number) VALUES (?)').bind(num).run();
    await upsertRetestState(c.env, pr, summary.failed, checkResult.status, nowIso(), checkResult.log);

    const state = await getRetestState(c.env, num);
    if (state && checkResult.status === 'success' && state.attempt_count >= BACKOFF_MINUTES.length) {
      await resetAttemptsIfRecovered(c.env, num);
      return c.json({ ok: true, pr_number: num, status: checkResult.status });
    }

    if (checkResult.shouldRetest) {
      if (state && !state.disabled_at) {
        const pending = await getPendingAttempt(c.env, num);
        if (!pending) {
          await scheduleImmediateAttempt(c.env, num, state.attempt_count);
          await executeDueAttempts(c.env);
        }
      }
    }

    return c.json({ ok: true, pr_number: num, status: checkResult.status });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const isNotFound = message.includes('404');
    return c.json({ error: isNotFound ? 'PR not found in GitHub' : 'Failed to process PR' }, isNotFound ? 404 : 500);
  }
});

app.delete('/track/:num', async (c) => {
  const num = Number(c.req.param('num'));
  if (!Number.isFinite(num) || num <= 0) return c.json({ error: 'Invalid PR number' }, 400);
  await deleteTrackedPrData(c.env, num);
  return c.json({ ok: true, pr_number: num });
});

app.get('/prs', async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT t.pr_number,
            COALESCE(s.attempt_count, 0) AS attempt_count,
            s.next_retest_at,
            s.disabled_at,
            s.last_failure_checks,
            s.last_seen_updated_at,
            COALESCE(s.last_check_status, 'unknown') AS last_check_status,
            s.last_check_at,
            s.last_error_message,
            s.last_status_log
     FROM tracked_prs t
     LEFT JOIN retest_state s ON s.pr_number = t.pr_number
     ORDER BY t.pr_number ASC`
  )
    .all<RetestStateRow>();

  const prs = (rows.results || []).map((row) => ({
    pr_number: row.pr_number,
    attempt_count: row.attempt_count,
    next_retest_at: row.next_retest_at,
    disabled_at: row.disabled_at,
    last_seen_updated_at: row.last_seen_updated_at,
    last_check_status: row.last_check_status,
    last_check_at: row.last_check_at,
    last_error_message: row.last_error_message,
    last_status_log: row.last_status_log,
    failed_checks: row.last_failure_checks ? JSON.parse(row.last_failure_checks) : [],
  }));

  return c.json({ prs });
});

app.get('/', async (c) => {
  let lastCronIso: string | null = null;
  let lastCronStatus: string | null = null;
  let nextCronIso: string | null = null;
  let nextScanIso: string | null = null;
  let lastScanIso: string | null = null;
  const row = await c.env.DB.prepare(
    'SELECT started_at, status FROM cron_runs ORDER BY started_at DESC LIMIT 1'
  ).first<{ started_at: string; status: string }>();
  if (row) {
    lastCronIso = row.started_at;
    lastCronStatus = row.status;
    const lastMs = Date.parse(row.started_at);
    if (Number.isFinite(lastMs)) {
      const nextMs = lastMs + CRON_INTERVAL_MINUTES * 60 * 1000;
      nextCronIso = new Date(nextMs).toISOString();
    }
  }

  const scanIntervalMinutes = parseNumber(c.env.SCAN_INTERVAL_MINUTES, DEFAULT_SCAN_INTERVAL_MINUTES);
  const lastScan = await getSetting(c.env, 'last_scan_at');
  if (lastScan) {
    lastScanIso = lastScan;
    const lastScanMs = Date.parse(lastScan);
    if (Number.isFinite(lastScanMs)) {
      const nextScanMs = lastScanMs + scanIntervalMinutes * 60 * 1000;
      nextScanIso = new Date(nextScanMs).toISOString();
    }
  }

  const lastCronSpan = lastCronIso
    ? `<span id="last-cron" class="ts" data-iso="${lastCronIso}" data-suffix=" (${lastCronStatus ?? 'unknown'})"></span>`
    : '<span id="last-cron">Never</span>';
  const nextCronSpan = nextCronIso
    ? `<span id="next-cron" class="ts" data-iso="${nextCronIso}"></span>`
    : '<span id="next-cron">Unknown</span>';
  const nextScanSpan = nextScanIso
    ? `<span id="next-scan" class="ts" data-iso="${nextScanIso}"></span>`
    : '<span id="next-scan">Unknown</span>';
  const lastScanSpan = lastScanIso
    ? `<span id="last-scan" class="ts" data-iso="${lastScanIso}"></span>`
    : '<span id="last-scan">Unknown</span>';

  const html = `<!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Retest as a Service</title>
      <style>
        * { box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
          margin: 0;
          padding: 0;
          background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #111827 100%);
          min-height: 100vh;
          color: #0f172a;
        }
        .container {
          max-width: 980px;
          margin: 0 auto;
          padding: 40px 20px 80px;
        }
        h1 {
          font-size: 36px;
          color: #e2e8f0;
          margin: 0 0 8px 0;
          font-weight: 700;
        }
        .subtitle {
          color: rgba(226, 232, 240, 0.8);
          font-size: 14px;
          margin-bottom: 32px;
        }
        .card {
          background: #ffffff;
          border-radius: 12px;
          padding: 22px;
          box-shadow: 0 14px 40px rgba(15, 23, 42, 0.15);
          margin-bottom: 20px;
        }
        .add-section h2 {
          font-size: 18px;
          margin: 0 0 16px 0;
          color: #0f172a;
        }
        .row {
          display: flex;
          gap: 12px;
          align-items: stretch;
        }
        input[type="number"] {
          flex: 1;
          padding: 12px 16px;
          font-size: 15px;
          border: 2px solid #e2e8f0;
          border-radius: 8px;
          outline: none;
          transition: border-color 0.2s;
        }
        input[type="number"]:focus { border-color: #38bdf8; }
        button {
          padding: 12px 20px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          border: none;
          border-radius: 8px;
          transition: all 0.2s;
        }
        #add-btn {
          background: #0ea5e9;
          color: white;
        }
        #add-btn:hover { background: #0284c7; }
        .msg {
          margin-top: 12px;
          min-height: 20px;
          font-size: 13px;
          color: #64748b;
        }
        .error { color: #b91c1c; }
        .success { color: #166534; }
        .remove-btn {
          background: #f1f5f9;
          color: #475569;
          padding: 8px 14px;
          font-size: 12px;
        }
        .remove-btn:hover { background: #fee2e2; color: #b91c1c; }
        .copy-btn {
          background: #e0f2fe;
          color: #0369a1;
          padding: 8px 12px;
          font-size: 12px;
        }
        .copy-btn:hover { background: #bae6fd; color: #0c4a6e; }
        .list-section h2 {
          font-size: 18px;
          margin: 0 0 16px 0;
          color: #0f172a;
        }
        .pr-list {
          list-style: none;
          padding: 0;
          margin: 0;
        }
        .pr-item {
          border: 2px solid #e2e8f0;
          border-radius: 10px;
          padding: 16px;
          margin-bottom: 12px;
          transition: all 0.2s;
        }
        .pr-item:hover {
          border-color: #38bdf8;
          box-shadow: 0 4px 14px rgba(56, 189, 248, 0.18);
        }
        .pr-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 8px;
        }
        .pr-left {
          display: flex;
          align-items: center;
          gap: 12px;
          flex-wrap: wrap;
        }
        .pr-link {
          font-size: 16px;
          font-weight: 600;
          color: #0284c7;
          text-decoration: none;
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }
        .pr-link:hover { text-decoration: underline; }
        .meta {
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
          font-size: 12px;
          color: #475569;
        }
        .badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 4px 10px;
          border-radius: 999px;
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
        }
        .badge-attempt { background: #e0f2fe; color: #0369a1; }
        .badge-next { background: #dcfce7; color: #166534; }
        .badge-disabled { background: #fee2e2; color: #991b1b; }
        .badge-success { background: #dcfce7; color: #166534; }
        .badge-failed { background: #fee2e2; color: #b91c1c; }
        .badge-ignored { background: #e2e8f0; color: #475569; }
        .badge-running { background: #fef9c3; color: #92400e; }
        .badge-unknown { background: #e2e8f0; color: #475569; }
        .failures {
          margin-top: 10px;
          padding-top: 10px;
          border-top: 1px solid #e2e8f0;
        }
        .failures-title {
          font-size: 12px;
          font-weight: 700;
          color: #b91c1c;
          margin-bottom: 8px;
        }
        .failures-list {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }
        .failure-badge {
          background: #fee2e2;
          color: #991b1b;
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 12px;
          font-family: 'Consolas', 'Monaco', monospace;
        }
        .empty-state {
          text-align: center;
          padding: 32px 12px;
          color: #94a3b8;
        }
        .loading {
          text-align: center;
          padding: 20px;
          color: #94a3b8;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Retest as a Service</h1>
        <div class="subtitle">pingcap/tidb • Last cron: ${lastCronSpan} • Next cron: ${nextCronSpan} • Last scan: ${lastScanSpan} • Next check: ${nextScanSpan} • Timezone: <span id="tz-label"></span></div>

        <div class="card add-section">
          <h2>Track PR</h2>
          <div class="row">
            <input id="pr-input" type="number" placeholder="Enter PR number" min="1" />
            <button id="add-btn">Track PR</button>
          </div>
          <div id="message" class="msg"></div>
        </div>

        <div class="card list-section">
          <h2>Tracked PRs</h2>
          <ul id="pr-list" class="pr-list">
            <li class="loading">Loading...</li>
          </ul>
        </div>
      </div>

      <script>
        const msgEl = document.getElementById('message');
        const inputEl = document.getElementById('pr-input');
        const listEl = document.getElementById('pr-list');
        const timeFormatter = new Intl.DateTimeFormat(undefined, {
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
          timeZoneName: 'short',
        });

        function setMessage(text, type = '') {
          msgEl.textContent = text || '';
          msgEl.className = 'msg ' + (type || '');
        }

        function formatTimestamp(iso) {
          if (!iso) return '';
          const date = new Date(iso);
          if (Number.isNaN(date.getTime())) return iso;
          return timeFormatter.format(date);
        }

        function applyLocalTimeLabels(root = document) {
          const nodes = root.querySelectorAll('[data-iso]');
          nodes.forEach((node) => {
            const iso = node.dataset.iso;
            if (!iso) return;
            const prefix = node.dataset.prefix || '';
            const suffix = node.dataset.suffix || '';
            node.textContent = prefix + formatTimestamp(iso) + suffix;
          });
          const tzEl = document.getElementById('tz-label');
          if (tzEl) {
            tzEl.textContent = timeFormatter.resolvedOptions().timeZone || 'local';
          }
        }

        async function refreshList() {
          listEl.innerHTML = '<li class="loading">Loading...</li>';
          try {
            const res = await fetch('/prs');
            const data = await res.json();
            const prs = (data && data.prs) || [];

            if (prs.length === 0) {
              listEl.innerHTML = '<li class="empty-state">No recent failures tracked.</li>';
              return;
            }

            listEl.innerHTML = '';
            prs.forEach(({ pr_number, attempt_count, next_retest_at, disabled_at, last_seen_updated_at, last_check_status, last_check_at, last_error_message, last_status_log, failed_checks }) => {
              const li = document.createElement('li');
              li.className = 'pr-item';

              const header = document.createElement('div');
              header.className = 'pr-header';

              const left = document.createElement('div');
              left.className = 'pr-left';

              const link = document.createElement('a');
              link.href = 'https://github.com/pingcap/tidb/pull/' + pr_number;
              link.target = '_blank';
              link.className = 'pr-link';
              link.innerHTML = '#' + pr_number + ' <span style="font-size: 12px;">↗</span>';

              const meta = document.createElement('div');
              meta.className = 'meta';
              const attemptBadge = document.createElement('span');
              attemptBadge.className = 'badge badge-attempt';
              attemptBadge.textContent = 'attempts ' + attempt_count;
              meta.appendChild(attemptBadge);

              const statusBadge = document.createElement('span');
              const statusText = (last_check_status || 'unknown').toLowerCase();
              statusBadge.className = 'badge badge-' + statusText;
              statusBadge.textContent = statusText;
              meta.appendChild(statusBadge);

              if (next_retest_at) {
                const nextBadge = document.createElement('span');
                nextBadge.className = 'badge badge-next';
                nextBadge.dataset.iso = next_retest_at;
                nextBadge.dataset.prefix = 'next ';
                nextBadge.textContent = 'next ' + next_retest_at;
                meta.appendChild(nextBadge);
              }

              if (disabled_at) {
                const disabledBadge = document.createElement('span');
                disabledBadge.className = 'badge badge-disabled';
                disabledBadge.textContent = 'disabled';
                meta.appendChild(disabledBadge);
              }

              if (last_seen_updated_at) {
                const lastSeen = document.createElement('span');
                lastSeen.dataset.iso = last_seen_updated_at;
                lastSeen.dataset.prefix = 'updated ';
                lastSeen.textContent = 'updated ' + last_seen_updated_at;
                meta.appendChild(lastSeen);
              }

              if (last_check_at) {
                const lastCheck = document.createElement('span');
                lastCheck.dataset.iso = last_check_at;
                lastCheck.dataset.prefix = 'checked ';
                lastCheck.textContent = 'checked ' + last_check_at;
                meta.appendChild(lastCheck);
              }

              left.appendChild(link);
              left.appendChild(meta);
              header.appendChild(left);

              const delBtn = document.createElement('button');
              delBtn.className = 'remove-btn';
              delBtn.textContent = 'Remove';
              delBtn.addEventListener('click', async () => {
                setMessage('Removing PR #' + pr_number + '...');
                const res = await fetch('/track/' + pr_number, { method: 'DELETE' });
                if (res.ok) {
                  setMessage('Removed PR #' + pr_number, 'success');
                  refreshList();
                } else {
                  const err = await res.json().catch(() => ({}));
                  setMessage('Failed to remove: ' + (err.error || res.status), 'error');
                }
              });
              header.appendChild(delBtn);

              const copyBtn = document.createElement('button');
              copyBtn.className = 'copy-btn';
              copyBtn.textContent = 'Copy ID';
              copyBtn.addEventListener('click', async () => {
                const text = String(pr_number);
                try {
                  if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(text);
                  } else {
                    const temp = document.createElement('textarea');
                    temp.value = text;
                    temp.setAttribute('readonly', 'true');
                    temp.style.position = 'absolute';
                    temp.style.left = '-9999px';
                    document.body.appendChild(temp);
                    temp.select();
                    document.execCommand('copy');
                    document.body.removeChild(temp);
                  }
                  setMessage('Copied PR #' + pr_number, 'success');
                } catch (e) {
                  setMessage('Failed to copy PR #' + pr_number, 'error');
                }
              });
              header.appendChild(copyBtn);
              li.appendChild(header);

              if (failed_checks && failed_checks.length > 0) {
                const failDiv = document.createElement('div');
                failDiv.className = 'failures';
                const failTitle = document.createElement('div');
                failTitle.className = 'failures-title';
                failTitle.textContent = 'Failed Checks (' + failed_checks.length + ')';
                failDiv.appendChild(failTitle);

                const failList = document.createElement('div');
                failList.className = 'failures-list';
                failed_checks.forEach((check) => {
                  const failBadge = document.createElement('span');
                  failBadge.className = 'failure-badge';
                  failBadge.textContent = check;
                  failList.appendChild(failBadge);
                });
                failDiv.appendChild(failList);
                li.appendChild(failDiv);
              }

              if (last_error_message) {
                const errDiv = document.createElement('div');
                errDiv.className = 'failures';
                const errTitle = document.createElement('div');
                errTitle.className = 'failures-title';
                errTitle.textContent = 'Last Error';
                errDiv.appendChild(errTitle);
                const errText = document.createElement('div');
                errText.style.whiteSpace = 'pre-wrap';
                errText.style.fontFamily = \"'Consolas', 'Monaco', monospace\";
                errText.style.fontSize = '12px';
                errText.style.color = '#b91c1c';
                errText.textContent = last_error_message;
                errDiv.appendChild(errText);
                li.appendChild(errDiv);
              }

              if (last_status_log && failed_checks && failed_checks.length > 0) {
                const logDiv = document.createElement('div');
                logDiv.className = 'failures';
                const logTitle = document.createElement('div');
                logTitle.className = 'failures-title';
                logTitle.textContent = 'Status Log';
                logDiv.appendChild(logTitle);
                const logText = document.createElement('div');
                logText.style.whiteSpace = 'pre-wrap';
                logText.style.fontFamily = \"'Consolas', 'Monaco', monospace\";
                logText.style.fontSize = '12px';
                logText.style.color = '#475569';
                logText.textContent = last_status_log;
                logDiv.appendChild(logText);
                li.appendChild(logDiv);
              }

              listEl.appendChild(li);
            });
            applyLocalTimeLabels(listEl);
          } catch (e) {
            listEl.innerHTML = '<li class="empty-state" style="color: #b91c1c;">Failed to load PRs</li>';
          }
        }

        document.getElementById('add-btn').addEventListener('click', async () => {
          const num = Number(inputEl.value);
          if (!num || num <= 0) {
            setMessage('Please enter a valid PR number', 'error');
            return;
          }
          setMessage('Tracking PR #' + num + '...');
          try {
            const res = await fetch('/track/' + num, { method: 'POST' });
            if (res.ok) {
              setMessage('Tracking PR #' + num, 'success');
              inputEl.value = '';
              refreshList();
            } else {
              const err = await res.json().catch(() => ({}));
              setMessage('Failed to track: ' + (err.error || res.status), 'error');
            }
          } catch (e) {
            setMessage('Network error while tracking', 'error');
          }
        });

        inputEl.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
            document.getElementById('add-btn').click();
          }
        });

        refreshList();
        applyLocalTimeLabels();
        setInterval(() => applyLocalTimeLabels(), 60 * 1000);
      </script>
    </body>
  </html>`;
  return c.html(html);
});

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runCronWithMeta(event, env));
  },
};
