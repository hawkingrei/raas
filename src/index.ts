import { Hono } from 'hono';
import { BLOCKED_CHECK, classifyChecks, isTideCheck, type CheckDecision, type CheckStatus } from './checks';
import { takeScanBatch } from './scan-batch';

type CheckStatusWithUnknown = CheckStatus | 'unknown';

type RetestStateRow = {
  pr_number: number;
  attempt_count: number;
  next_retest_at: string | null;
  last_retest_at: string | null;
  disabled_at: string | null;
  last_failure_checks: string | null;
  last_seen_updated_at: string | null;
  last_seen_head_sha: string | null;
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

type OkToTestStateRow = {
  pr_number: number;
  last_seen_head_sha: string | null;
  last_action: string | null;
};

export interface Env {
  DB: D1Database;
  GITHUB_TOKEN: string;
  CHECK_BLACKLIST: string;
  SCAN_LOOKBACK_HOURS?: string;
  SCAN_INTERVAL_MINUTES?: string;
  SCAN_BATCH_SIZE?: string;
  OK_TO_TEST_LOOKBACK_MINUTES?: string;
  OK_TO_TEST_SCAN_INTERVAL_MINUTES?: string;
  DAY_MAX_RETESTS?: string;
  NIGHT_MAX_RETESTS?: string;
  TIMEZONE?: string;
  GITHUB_WEBHOOK_SECRET?: string;
}

const app = new Hono<{ Bindings: Env }>();

const DEFAULT_LOOKBACK_HOURS = 48;
const DEFAULT_SCAN_INTERVAL_MINUTES = 5;
const DEFAULT_SCAN_BATCH_SIZE = 10;
const DEFAULT_OK_TO_TEST_LOOKBACK_MINUTES = 10;
const DEFAULT_OK_TO_TEST_SCAN_INTERVAL_MINUTES = 10;
const DEFAULT_DAY_MAX_RETESTS = 2;
const DEFAULT_NIGHT_MAX_RETESTS = 5;
const BACKOFF_MINUTES = [0, 10, 20, 40, 360] as const;
const MAX_RETEST_ATTEMPTS = 8;
const HIGH_ATTEMPT_THRESHOLD = BACKOFF_MINUTES.length;
const HIGH_ATTEMPT_INTERVAL_MS = 60 * 60 * 1000;
const LAST_HIGH_ATTEMPT_EXECUTED_AT_SETTING = 'last_high_attempt_executed_at';
const UTC_PLUS_8_OFFSET_MS = 8 * 60 * 60 * 1000;
const HIGH_ATTEMPT_WINDOW_END_HOUR_UTC8 = 8;
const OK_TO_TEST_COMMENT_CLAIM_TTL_MINUTES = 15;
const CRON_INTERVAL_MINUTES = 5;
const RETEST_SCAN_CURSOR_SETTING = 'retest_scan_cursor';
const REPO_OWNER = 'pingcap';
const REPO_NAME = 'tidb';
const RETEST_REQUESTED_LOG = 'Retest comment posted; waiting for CI status update';
let retestStateColumnsEnsured = false;
let okToTestStateTableEnsured = false;

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

function formatErrorMessage(error: unknown): string {
  return error instanceof Error ? (error.stack || error.message) : String(error);
}

function getErrorLogFields(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return {
      error_name: error.name,
      error_message: error.message,
      error_stack: error.stack ?? null,
    };
  }

  return { error_message: String(error) };
}

function logErrorEvent(event: string, error: unknown, fields: Record<string, unknown> = {}): void {
  console.error({
    level: 'error',
    event,
    ...fields,
    ...getErrorLogFields(error),
  });
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function isNightInShanghai(now: Date): boolean {
  const utcPlus8 = new Date(now.getTime() + UTC_PLUS_8_OFFSET_MS);
  const utcPlus8Hour = utcPlus8.getUTCHours();
  return utcPlus8Hour >= 18 || utcPlus8Hour < 9;
}

function isInHighAttemptWindowUtcPlus8(now: Date): boolean {
  const utcPlus8 = new Date(now.getTime() + UTC_PLUS_8_OFFSET_MS);
  const utcPlus8Hour = utcPlus8.getUTCHours();
  return utcPlus8Hour < HIGH_ATTEMPT_WINDOW_END_HOUR_UTC8;
}

function getNextHighAttemptWindowStartUtcPlus8Iso(now: Date): string {
  const utcPlus8 = new Date(now.getTime() + UTC_PLUS_8_OFFSET_MS);
  const nextUtcPlus8WindowStartMs = Date.UTC(
    utcPlus8.getUTCFullYear(),
    utcPlus8.getUTCMonth(),
    utcPlus8.getUTCDate() + 1,
    0,
    0,
    0,
    0
  );
  return new Date(nextUtcPlus8WindowStartMs - UTC_PLUS_8_OFFSET_MS).toISOString();
}

function getNextAllowedHighAttemptIso(
  now: Date,
  lastHighAttemptExecutedAt: string | null
): string {
  let candidateMs = now.getTime();
  if (lastHighAttemptExecutedAt) {
    const lastExecutedMs = Date.parse(lastHighAttemptExecutedAt);
    if (Number.isFinite(lastExecutedMs)) {
      candidateMs = Math.max(candidateMs, lastExecutedMs + HIGH_ATTEMPT_INTERVAL_MS);
    }
  }

  const candidate = new Date(candidateMs);
  if (isInHighAttemptWindowUtcPlus8(candidate)) {
    return candidate.toISOString();
  }

  return getNextHighAttemptWindowStartUtcPlus8Iso(candidate);
}

function isHighAttemptIndex(attemptIndex: number): boolean {
  return attemptIndex > HIGH_ATTEMPT_THRESHOLD;
}

function hasReachedMaxAttempts(attemptCount: number): boolean {
  return attemptCount >= MAX_RETEST_ATTEMPTS;
}

function getScheduledAttemptInfo(
  state: RetestStateRow,
  now: Date,
  immediate: boolean
): { attemptIndex: number; scheduledAt: string; statusLog: string } | null {
  if (hasReachedMaxAttempts(state.attempt_count)) {
    return null;
  }

  const attemptIndex = state.attempt_count + 1;
  if (!isHighAttemptIndex(attemptIndex)) {
    const delayMinutes = immediate ? 0 : BACKOFF_MINUTES[state.attempt_count];
    const scheduledAt = new Date(now.getTime() + delayMinutes * 60 * 1000).toISOString();
    const statusLog = immediate ? 'Scheduled immediate retest' : `Scheduled retest at ${scheduledAt}`;
    return { attemptIndex, scheduledAt, statusLog };
  }

  if (isInHighAttemptWindowUtcPlus8(now)) {
    const scheduledAt = now.toISOString();
    return {
      attemptIndex,
      scheduledAt,
      statusLog: 'Scheduled high-attempt retest in UTC+8 00:00-08:00 window',
    };
  }

  const scheduledAt = getNextHighAttemptWindowStartUtcPlus8Iso(now);
  return {
    attemptIndex,
    scheduledAt,
    statusLog: `Deferred high-attempt retest until next UTC+8 00:00 window at ${scheduledAt}`,
  };
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
  created_at: string;
  updated_at: string;
  head: { sha: string };
  state: string;
  mergeable: boolean | null;
  mergeable_state: string | null;
};

type PullLabel = { name: string };

type PullDetail = PullItem & {
  labels: PullLabel[];
};

type PullListItem = PullItem & {
  base: { ref: string };
  labels: PullLabel[];
  user: { login: string } | null;
};

async function getPullByNumber(token: string, prNumber: number): Promise<PullDetail> {
  return await githubRequest<PullDetail>(
    `/repos/${REPO_OWNER}/${REPO_NAME}/pulls/${prNumber}`,
    token
  );
}

async function listOpenMasterPulls(token: string, page: number): Promise<PullListItem[]> {
  return await githubRequest<PullListItem[]>(
    `/repos/${REPO_OWNER}/${REPO_NAME}/pulls?state=open&base=master&sort=created&direction=desc&per_page=100&page=${page}`,
    token
  );
}

async function listRecentOpenMasterPulls(token: string, lookbackMinutes: number): Promise<PullListItem[]> {
  const cutoffMs = Date.now() - lookbackMinutes * 60 * 1000;
  const pulls: PullListItem[] = [];

  for (let page = 1; page <= 10; page += 1) {
    const items = await listOpenMasterPulls(token, page);
    if (items.length === 0) break;

    let reachedOlder = false;
    for (const pr of items) {
      const createdMs = Date.parse(pr.created_at);
      if (!Number.isFinite(createdMs) || createdMs < cutoffMs) {
        reachedOlder = true;
        break;
      }
      pulls.push(pr);
    }

    if (items.length < 100 || reachedOlder) break;
  }

  return pulls;
}

async function getOkToTestSkipReason(
  pr: PullListItem,
  ownersAliasesUsers: Set<string>,
  token: string
): Promise<string | null> {
  if (hasLabel(pr.labels, 'ok-to-test')) {
    return 'ok-to-test label already exists';
  }

  const authorLogin = pr.user?.login ? normalizeLogin(pr.user.login) : '';
  if (!authorLogin) {
    return 'PR author is missing';
  }
  if (!ownersAliasesUsers.has(authorLogin)) {
    return `Author ${authorLogin} is not in OWNERS_ALIASES`;
  }

  if (await hasFastTestTiprowTriggered(pr.head.sha, token)) {
    return `${BLOCKED_CHECK} already triggered`;
  }

  return null;
}

async function getTrackedPrNumbers(env: Env): Promise<number[]> {
  const rows = await env.DB.prepare('SELECT pr_number FROM tracked_prs ORDER BY pr_number ASC')
    .all<{ pr_number: number }>();
  return (rows.results || []).map((row) => row.pr_number);
}

async function getTrackedPrScanBatch(
  env: Env
): Promise<{ totalTracked: number; batch: number[]; nextCursor: number }> {
  const tracked = await getTrackedPrNumbers(env);
  if (tracked.length === 0) {
    return { totalTracked: 0, batch: [], nextCursor: 0 };
  }

  const batchSize = parseNumber(env.SCAN_BATCH_SIZE, DEFAULT_SCAN_BATCH_SIZE);
  const cursor = parseNumber((await getSetting(env, RETEST_SCAN_CURSOR_SETTING)) ?? undefined, 0);
  const selection = takeScanBatch(tracked, cursor, batchSize);

  return {
    totalTracked: tracked.length,
    batch: selection.items,
    nextCursor: selection.nextCursor,
  };
}

type CommitStatusResponse = {
  statuses: Array<{ context: string; state: string }>;
};

type CommitCheckRunsResponse = {
  check_runs: Array<{ name: string; status: string; conclusion: string | null }>;
};

type RepoFileResponse = {
  content: string;
  encoding: string;
};

type IssueComment = {
  body: string | null;
};

type CheckStateSummary = {
  failed: string[];
  pending: string[];
};

function normalizeLogin(login: string): string {
  return login.trim().replace(/^@/, '').toLowerCase();
}

function hasLabel(labels: PullLabel[], expected: string): boolean {
  const normalizedExpected = expected.toLowerCase();
  return labels.some((label) => label.name.toLowerCase() === normalizedExpected);
}

function includesFastTestTiprow(value: string): boolean {
  return value.toLowerCase().includes(BLOCKED_CHECK);
}

function isOkToTestCommentBody(body: string | null): boolean {
  return (body ?? '').trim() === '/ok-to-test';
}

async function getCheckStateSummary(sha: string, token: string): Promise<CheckStateSummary> {
  const [statusData, checkRunData] = await Promise.all([
    githubRequest<CommitStatusResponse>(
      `/repos/${REPO_OWNER}/${REPO_NAME}/commits/${sha}/status`,
      token
    ),
    githubRequest<CommitCheckRunsResponse>(
      `/repos/${REPO_OWNER}/${REPO_NAME}/commits/${sha}/check-runs?per_page=100`,
      token
    ),
  ]);

  const failed = new Set<string>();
  const pending = new Set<string>();
  for (const status of statusData.statuses) {
    if (status.state === 'failure' || status.state === 'error') {
      failed.add(status.context);
    } else if (status.state === 'pending') {
      pending.add(status.context);
    }
  }

  for (const checkRun of checkRunData.check_runs) {
    if (checkRun.status !== 'completed') {
      pending.add(checkRun.name);
      continue;
    }

    if (
      checkRun.conclusion === 'failure' ||
      checkRun.conclusion === 'timed_out' ||
      checkRun.conclusion === 'cancelled' ||
      checkRun.conclusion === 'action_required' ||
      checkRun.conclusion === 'startup_failure' ||
      checkRun.conclusion === 'stale'
    ) {
      failed.add(checkRun.name);
    }
  }

  return { failed: Array.from(failed), pending: Array.from(pending) };
}

async function hasFastTestTiprowStatusContext(sha: string, token: string): Promise<boolean> {
  const data = await githubRequest<CommitStatusResponse>(
    `/repos/${REPO_OWNER}/${REPO_NAME}/commits/${sha}/status`,
    token
  );
  return data.statuses.some((status) => includesFastTestTiprow(status.context));
}

async function hasFastTestTiprowCheckRun(sha: string, token: string): Promise<boolean> {
  const data = await githubRequest<CommitCheckRunsResponse>(
    `/repos/${REPO_OWNER}/${REPO_NAME}/commits/${sha}/check-runs?per_page=100`,
    token
  );
  return data.check_runs.some((checkRun) => includesFastTestTiprow(checkRun.name));
}

async function hasFastTestTiprowTriggered(sha: string, token: string): Promise<boolean> {
  if (await hasFastTestTiprowStatusContext(sha, token)) {
    return true;
  }
  return await hasFastTestTiprowCheckRun(sha, token);
}

function decodeBase64Utf8(encoded: string): string {
  const normalized = encoded.replace(/\s+/g, '');
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function parseOwnersAliasesUsers(content: string): Set<string> {
  const users = new Set<string>();
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('- ')) continue;
    const withoutComment = trimmed.slice(2).split('#')[0]?.trim() ?? '';
    if (!withoutComment) continue;
    const withoutQuotes = withoutComment.replace(/^['"]|['"]$/g, '');
    const login = normalizeLogin(withoutQuotes);
    if (login) {
      users.add(login);
    }
  }
  return users;
}

async function getOwnersAliasesUsers(token: string): Promise<Set<string>> {
  const response = await githubRequest<RepoFileResponse>(
    `/repos/${REPO_OWNER}/${REPO_NAME}/contents/OWNERS_ALIASES?ref=master`,
    token
  );
  if (response.encoding !== 'base64') {
    throw new Error(`Unexpected OWNERS_ALIASES encoding: ${response.encoding}`);
  }
  const content = decodeBase64Utf8(response.content);
  return parseOwnersAliasesUsers(content);
}

async function hasOkToTestComment(prNumber: number, token: string): Promise<boolean> {
  for (let page = 1; page <= 10; page += 1) {
    const comments = await githubRequest<IssueComment[]>(
      `/repos/${REPO_OWNER}/${REPO_NAME}/issues/${prNumber}/comments?per_page=100&page=${page}`,
      token
    );
    if (comments.some((comment) => isOkToTestCommentBody(comment.body))) {
      return true;
    }
    if (comments.length < 100) {
      break;
    }
  }

  return false;
}

function isMergeConflict(pr: PullItem): boolean {
  if (!pr.mergeable_state) return false;
  return pr.mergeable_state === 'dirty';
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

async function postOkToTestComment(prNumber: number, token: string): Promise<void> {
  await githubRequest(
    `/repos/${REPO_OWNER}/${REPO_NAME}/issues/${prNumber}/comments`,
    token,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: '/ok-to-test' }),
    }
  );
}

async function isPriorityRetryPr(token: string, prNumber: number): Promise<boolean> {
  const pr = await getPullByNumber(token, prNumber);
  return hasLabel(pr.labels, 'lgtm') && hasLabel(pr.labels, 'approved');
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

async function ensureRetestStateColumns(env: Env): Promise<void> {
  if (retestStateColumnsEnsured) return;

  try {
    await env.DB.prepare('ALTER TABLE retest_state ADD COLUMN last_seen_head_sha TEXT NULL').run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes('duplicate column name: last_seen_head_sha')) {
      throw error;
    }
  }

  try {
    await env.DB.prepare('ALTER TABLE retest_state ADD COLUMN last_retest_at TEXT NULL').run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes('duplicate column name: last_retest_at')) {
      throw error;
    }
  }

  retestStateColumnsEnsured = true;
}

async function ensureOkToTestStateTable(env: Env): Promise<void> {
  if (okToTestStateTableEnsured) return;

  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS ok_to_test_state (
      pr_number INTEGER PRIMARY KEY,
      last_seen_head_sha TEXT NULL,
      last_action TEXT NULL,
      last_action_at TEXT NULL,
      last_error_message TEXT NULL,
      last_status_log TEXT NULL
    )`
  ).run();

  okToTestStateTableEnsured = true;
}

async function getOkToTestState(env: Env, prNumber: number): Promise<OkToTestStateRow | null> {
  await ensureOkToTestStateTable(env);
  const row = await env.DB.prepare(
    'SELECT pr_number, last_seen_head_sha, last_action FROM ok_to_test_state WHERE pr_number = ?'
  )
    .bind(prNumber)
    .first<OkToTestStateRow>();
  return row ?? null;
}

async function upsertOkToTestState(
  env: Env,
  prNumber: number,
  headSha: string,
  action: 'commenting' | 'commented' | 'skipped' | 'error',
  statusLog: string,
  errorMessage: string | null
): Promise<void> {
  await ensureOkToTestStateTable(env);
  await env.DB.prepare(
    `INSERT INTO ok_to_test_state (pr_number, last_seen_head_sha, last_action, last_action_at, last_error_message, last_status_log)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(pr_number) DO UPDATE SET
       last_seen_head_sha = excluded.last_seen_head_sha,
       last_action = excluded.last_action,
       last_action_at = excluded.last_action_at,
       last_error_message = excluded.last_error_message,
       last_status_log = excluded.last_status_log`
  )
    .bind(prNumber, headSha, action, nowIso(), errorMessage, statusLog)
    .run();
}

async function tryClaimOkToTestComment(env: Env, prNumber: number, headSha: string): Promise<boolean> {
  await ensureOkToTestStateTable(env);

  const claimedAt = nowIso();
  const staleThreshold = new Date(Date.now() - OK_TO_TEST_COMMENT_CLAIM_TTL_MINUTES * 60 * 1000).toISOString();
  const result = await env.DB.prepare(
    `INSERT INTO ok_to_test_state (pr_number, last_seen_head_sha, last_action, last_action_at, last_error_message, last_status_log)
     VALUES (?, ?, 'commenting', ?, NULL, ?)
     ON CONFLICT(pr_number) DO UPDATE SET
       last_seen_head_sha = excluded.last_seen_head_sha,
       last_action = excluded.last_action,
       last_action_at = excluded.last_action_at,
       last_error_message = excluded.last_error_message,
       last_status_log = excluded.last_status_log
     WHERE ok_to_test_state.last_action IS NULL
       OR ok_to_test_state.last_action = 'skipped'
       OR ok_to_test_state.last_action = 'error'
       OR (
         ok_to_test_state.last_action = 'commenting'
         AND ok_to_test_state.last_action_at IS NOT NULL
         AND ok_to_test_state.last_action_at < ?
       )`
  )
    .bind(prNumber, headSha, claimedAt, 'Acquired /ok-to-test comment claim', staleThreshold)
    .run();

  const changes = Number((result.meta as { changes?: number } | undefined)?.changes ?? 0);
  return changes > 0;
}

async function upsertRetestState(
  env: Env,
  pr: PullItem,
  failedChecks: string[],
  status: CheckStatus,
  checkedAt: string,
  statusLog: string
): Promise<void> {
  await ensureRetestStateColumns(env);
  const failedJson = JSON.stringify(failedChecks);
  await env.DB.prepare(
    `INSERT INTO retest_state (pr_number, attempt_count, last_seen_updated_at, last_seen_head_sha, last_failure_checks, last_check_status, last_check_at, last_status_log)
     VALUES (?, 0, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(pr_number) DO UPDATE SET last_seen_updated_at = excluded.last_seen_updated_at,
       last_seen_head_sha = excluded.last_seen_head_sha,
       last_failure_checks = excluded.last_failure_checks,
       last_check_status = excluded.last_check_status,
       last_check_at = excluded.last_check_at,
       last_status_log = excluded.last_status_log`
  )
    .bind(pr.number, pr.updated_at, pr.head.sha, failedJson, status, checkedAt, statusLog)
    .run();
}

async function upsertRetestStateScanError(
  env: Env,
  prNumber: number,
  errorMessage: string
): Promise<void> {
  await ensureRetestStateColumns(env);
  const checkedAt = nowIso();
  await env.DB.prepare(
    `INSERT INTO retest_state (pr_number, attempt_count, last_check_status, last_check_at, last_error_message, last_status_log)
     VALUES (?, 0, 'unknown', ?, ?, ?)
     ON CONFLICT(pr_number) DO UPDATE SET
       last_check_status = excluded.last_check_status,
       last_check_at = excluded.last_check_at,
       last_error_message = excluded.last_error_message,
       last_status_log = excluded.last_status_log`
  )
    .bind(prNumber, checkedAt, errorMessage, 'Failed to refresh PR state; will retry on next cron')
    .run();
}

async function getRetestState(env: Env, prNumber: number): Promise<RetestStateRow | null> {
  await ensureRetestStateColumns(env);
  const row = await env.DB.prepare(
    `SELECT pr_number, attempt_count, next_retest_at, last_retest_at, disabled_at, last_failure_checks, last_seen_updated_at, last_seen_head_sha, last_check_status, last_check_at, last_error_message, last_status_log
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
  await resetAttempts(env, prNumber, 'CI recovered, reset attempts');
}

async function resetAttempts(env: Env, prNumber: number, statusLog: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      'UPDATE retest_state SET attempt_count = 0, disabled_at = NULL, next_retest_at = NULL, last_error_message = NULL, last_status_log = ? WHERE pr_number = ?'
    )
      .bind(statusLog, prNumber),
    env.DB.prepare('DELETE FROM retest_attempts WHERE pr_number = ? AND executed_at IS NULL')
      .bind(prNumber),
  ]);
}

async function resetAttemptsIfHeadChanged(
  env: Env,
  prNumber: number,
  previousHeadSha: string,
  latestHeadSha: string
): Promise<void> {
  await resetAttempts(
    env,
    prNumber,
    `Head changed ${previousHeadSha.slice(0, 8)} -> ${latestHeadSha.slice(0, 8)}, reset attempts`
  );
}

async function clearRetestStateError(env: Env, prNumber: number): Promise<void> {
  await env.DB.prepare('UPDATE retest_state SET last_error_message = NULL WHERE pr_number = ?')
    .bind(prNumber)
    .run();
}

async function upsertStateAndResetIfHeadChanged(
  env: Env,
  pr: PullItem,
  failedChecks: string[],
  checkResult: CheckDecision
): Promise<RetestStateRow | null> {
  const previousState = await getRetestState(env, pr.number);
  const previousHeadSha = previousState?.last_seen_head_sha;
  const headChanged = !!(previousHeadSha && previousHeadSha !== pr.head.sha);

  await upsertRetestState(env, pr, failedChecks, checkResult.status, nowIso(), checkResult.log);
  if (previousState?.last_check_status === 'unknown') {
    await clearRetestStateError(env, pr.number);
  }
  if (headChanged && previousHeadSha) {
    await resetAttemptsIfHeadChanged(env, pr.number, previousHeadSha, pr.head.sha);
  }

  return await getRetestState(env, pr.number);
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

async function markRetestStateDisabled(env: Env, prNumber: number): Promise<void> {
  await env.DB.prepare(
    'UPDATE retest_state SET disabled_at = ?, next_retest_at = NULL, last_status_log = ? WHERE pr_number = ?'
  )
    .bind(nowIso(), `Reached max attempts (${MAX_RETEST_ATTEMPTS})`, prNumber)
    .run();
}

async function enqueueRetestAttempt(
  env: Env,
  state: RetestStateRow,
  immediate: boolean
): Promise<void> {
  const schedule = getScheduledAttemptInfo(state, new Date(), immediate);
  if (!schedule) {
    await markRetestStateDisabled(env, state.pr_number);
    return;
  }

  await env.DB.prepare(
    'INSERT INTO retest_attempts (pr_number, attempt_index, scheduled_at, status) VALUES (?, ?, ?, ?)'
  )
    .bind(state.pr_number, schedule.attemptIndex, schedule.scheduledAt, 'scheduled')
    .run();

  await env.DB.prepare('UPDATE retest_state SET next_retest_at = ?, last_status_log = ? WHERE pr_number = ?')
    .bind(schedule.scheduledAt, schedule.statusLog, state.pr_number)
    .run();
}

async function scheduleNextAttempt(env: Env, state: RetestStateRow): Promise<void> {
  if (hasReachedMaxAttempts(state.attempt_count)) {
    await markRetestStateDisabled(env, state.pr_number);
    return;
  }

  await enqueueRetestAttempt(env, state, false);
}

async function scheduleImmediateAttempt(env: Env, state: RetestStateRow): Promise<void> {
  if (hasReachedMaxAttempts(state.attempt_count)) {
    await markRetestStateDisabled(env, state.pr_number);
    return;
  }

  await enqueueRetestAttempt(env, state, true);
}

async function rescheduleHighAttemptToNextUtcPlus8Midnight(
  env: Env,
  attempt: RetestAttemptRow,
  prNumber: number
): Promise<void> {
  const scheduledAt = getNextHighAttemptWindowStartUtcPlus8Iso(new Date());
  await rescheduleHighAttempt(
    env,
    attempt,
    prNumber,
    scheduledAt,
    `Deferred high-attempt retest until next UTC+8 00:00 window at ${scheduledAt}`
  );
}

async function rescheduleHighAttempt(
  env: Env,
  attempt: RetestAttemptRow,
  prNumber: number,
  scheduledAt: string,
  statusLog: string
): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      'UPDATE retest_attempts SET scheduled_at = ?, status = ? WHERE id = ?'
    )
      .bind(scheduledAt, 'scheduled', attempt.id),
    env.DB.prepare('UPDATE retest_state SET next_retest_at = ?, last_status_log = ? WHERE pr_number = ?')
      .bind(scheduledAt, statusLog, prNumber),
  ]);
}

async function scanAndSchedule(env: Env, runId: string): Promise<void> {
  const token = env.GITHUB_TOKEN;
  const lookbackHours = parseNumber(env.SCAN_LOOKBACK_HOURS, DEFAULT_LOOKBACK_HOURS);
  const blacklist = new Set(parseCsv(env.CHECK_BLACKLIST));

  const { totalTracked, batch: tracked, nextCursor } = await getTrackedPrScanBatch(env);
  if (tracked.length === 0) {
    console.log('No tracked PRs, skipping scan.');
    return;
  }

  if (totalTracked > tracked.length) {
    console.log({
      level: 'info',
      event: 'retest.scan.batch_selected',
      run_id: runId,
      total_tracked: totalTracked,
      batch_size: tracked.length,
    });
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
      logErrorEvent('retest.scan.fetch_pr_failed', result.reason, {
        run_id: runId,
        pr_number: result.prNumber,
      });
      await upsertRetestStateScanError(
        env,
        result.prNumber,
        `Failed to fetch PR from GitHub: ${formatErrorMessage(result.reason)}`
      );
      continue;
    }
    const pr = result.value;

    try {
      if (pr.state !== 'open') {
        await deleteTrackedPrData(env, result.prNumber);
        continue;
      }

      const updatedMs = Date.parse(pr.updated_at);
      if (!Number.isFinite(updatedMs) || updatedMs < cutoffMs) continue;

      let checkResult: { status: CheckStatus; shouldRetest: boolean; log: string };
      let failedChecks: string[] = [];
      if (isMergeConflict(pr)) {
        checkResult = { status: 'conflict', shouldRetest: false, log: 'Merge conflict' };
      } else {
        const summary = await getCheckStateSummary(pr.head.sha, token);
        failedChecks = summary.failed;
        checkResult = classifyChecks(summary.failed, summary.pending, blacklist);
      }
      const state = await upsertStateAndResetIfHeadChanged(env, pr, failedChecks, checkResult);
      if (!state) continue;
      if (checkResult.status === 'success' && state.attempt_count >= HIGH_ATTEMPT_THRESHOLD) {
        await resetAttemptsIfRecovered(env, pr.number);
        continue;
      }
      if (!checkResult.shouldRetest) continue;
      if (state.disabled_at) continue;

      const pending = await getPendingAttempt(env, pr.number);
      if (pending) continue;

      await scheduleNextAttempt(env, state);
    } catch (error) {
      const message = formatErrorMessage(error);
      logErrorEvent('retest.scan.pr_failed', error, {
        run_id: runId,
        pr_number: pr.number,
        head_sha: pr.head.sha,
      });
      await upsertRetestStateScanError(env, pr.number, message);
    }
  }

  await setSetting(env, RETEST_SCAN_CURSOR_SETTING, String(nextCursor));
}

async function scanAndAutoOkToTest(env: Env, runId: string): Promise<void> {
  const token = env.GITHUB_TOKEN;
  const lookbackMinutes = parseNumber(
    env.OK_TO_TEST_LOOKBACK_MINUTES,
    DEFAULT_OK_TO_TEST_LOOKBACK_MINUTES
  );
  const openMasterPrs = await listRecentOpenMasterPulls(token, lookbackMinutes);

  if (openMasterPrs.length === 0) {
    return;
  }

  const ownersAliasesUsers = await getOwnersAliasesUsers(token);
  for (const pr of openMasterPrs) {
    const previousState = await getOkToTestState(env, pr.number);
    if (previousState?.last_action === 'commented') {
      continue;
    }

    const skipReason = await getOkToTestSkipReason(pr, ownersAliasesUsers, token);
    if (skipReason) {
      await upsertOkToTestState(
        env,
        pr.number,
        pr.head.sha,
        'skipped',
        skipReason,
        null
      );
      continue;
    }

    if (await hasOkToTestComment(pr.number, token)) {
      await upsertOkToTestState(
        env,
        pr.number,
        pr.head.sha,
        'commented',
        'Detected existing /ok-to-test comment, skip posting',
        null
      );
      continue;
    }

    const claimed = await tryClaimOkToTestComment(env, pr.number, pr.head.sha);
    if (!claimed) {
      continue;
    }

    if (await hasOkToTestComment(pr.number, token)) {
      await upsertOkToTestState(
        env,
        pr.number,
        pr.head.sha,
        'commented',
        'Detected existing /ok-to-test comment after claim, skip posting',
        null
      );
      continue;
    }

    try {
      await postOkToTestComment(pr.number, token);
      await upsertOkToTestState(
        env,
        pr.number,
        pr.head.sha,
        'commented',
        'Posted /ok-to-test because author is in OWNERS_ALIASES and fast_test_tiprow is not triggered',
        null
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logErrorEvent('ok_to_test.comment_failed', error, {
        run_id: runId,
        pr_number: pr.number,
        head_sha: pr.head.sha,
      });
      await upsertOkToTestState(
        env,
        pr.number,
        pr.head.sha,
        'error',
        'Failed to post /ok-to-test',
        errorMessage
      );
    }
  }
}

async function executeDueAttempts(env: Env, runId: string): Promise<void> {
  const nowDate = new Date();
  const maxRetests = getMaxRetests(nowDate, env);
  const now = nowDate.toISOString();
  let lastHighAttemptExecutedAt = await getSetting(env, LAST_HIGH_ATTEMPT_EXECUTED_AT_SETTING);

  const rows = await env.DB.prepare(
    `SELECT id, pr_number, attempt_index, scheduled_at
     FROM retest_attempts
     WHERE executed_at IS NULL AND scheduled_at <= ?
     ORDER BY scheduled_at ASC`
  )
    .bind(now)
    .all<RetestAttemptRow>();

  const attempts = rows.results || [];
  if (attempts.length === 0) {
    return;
  }

  const priorityEntries = await Promise.all(
    Array.from(new Set(attempts.map((attempt) => attempt.pr_number))).map(async (prNumber) => {
      try {
        return [prNumber, await isPriorityRetryPr(env.GITHUB_TOKEN, prNumber)] as const;
      } catch (error) {
        logErrorEvent('retest.execute.priority_check_failed', error, {
          run_id: runId,
          pr_number: prNumber,
        });
        return [prNumber, false] as const;
      }
    })
  );
  const priorityMap = new Map<number, boolean>(priorityEntries);

  attempts.sort((left, right) => {
    const leftPriority = priorityMap.get(left.pr_number) ? 1 : 0;
    const rightPriority = priorityMap.get(right.pr_number) ? 1 : 0;
    if (leftPriority !== rightPriority) {
      return rightPriority - leftPriority;
    }

    const scheduledCompare = Date.parse(left.scheduled_at) - Date.parse(right.scheduled_at);
    if (scheduledCompare !== 0) {
      return scheduledCompare;
    }

    return left.id - right.id;
  });

  let executedAttempts = 0;
  for (const attempt of attempts) {
    if (executedAttempts >= maxRetests) break;

    const state = await getRetestState(env, attempt.pr_number);
    if (!state) continue;

    if (isHighAttemptIndex(attempt.attempt_index)) {
      if (!isInHighAttemptWindowUtcPlus8(nowDate)) {
        await rescheduleHighAttemptToNextUtcPlus8Midnight(env, attempt, attempt.pr_number);
        continue;
      }

      const nextAllowedAt = getNextAllowedHighAttemptIso(nowDate, lastHighAttemptExecutedAt);
      if (Date.parse(nextAllowedAt) > nowDate.getTime()) {
        await rescheduleHighAttempt(
          env,
          attempt,
          attempt.pr_number,
          nextAllowedAt,
          `Deferred high-attempt retest until hourly slot opens at ${nextAllowedAt}`
        );
        continue;
      }
    }
    let status = 'success';
    let errorMessage: string | null = null;
    try {
      await postRetestComment(attempt.pr_number, env.GITHUB_TOKEN);
    } catch (error) {
      status = 'error';
      errorMessage = error instanceof Error ? error.message : String(error);
      logErrorEvent('retest.execute.comment_failed', error, {
        run_id: runId,
        pr_number: attempt.pr_number,
        attempt_id: attempt.id,
        attempt_index: attempt.attempt_index,
        scheduled_at: attempt.scheduled_at,
      });
    }

    await env.DB.prepare(
      'UPDATE retest_attempts SET executed_at = ?, status = ?, error_message = ? WHERE id = ?'
    )
      .bind(now, status, errorMessage, attempt.id)
      .run();

    const nextAttemptCount = state.attempt_count + 1;
    const disable = nextAttemptCount >= MAX_RETEST_ATTEMPTS;
    const statusLog = status === 'success' ? RETEST_REQUESTED_LOG : `Retest failed: ${errorMessage ?? 'unknown'}`;
    const nextCheckStatus = status === 'success' ? 'running' : state.last_check_status;
    const nextCheckAt = status === 'success' ? now : state.last_check_at;
    await env.DB.prepare(
      'UPDATE retest_state SET attempt_count = ?, last_retest_at = ?, next_retest_at = NULL, disabled_at = ?, last_error_message = ?, last_status_log = ?, last_check_status = ?, last_check_at = ? WHERE pr_number = ?'
    )
      .bind(
        nextAttemptCount,
        now,
        disable ? now : null,
        errorMessage,
        statusLog,
        nextCheckStatus,
        nextCheckAt,
        attempt.pr_number
      )
      .run();

    if (isHighAttemptIndex(attempt.attempt_index)) {
      await setSetting(env, LAST_HIGH_ATTEMPT_EXECUTED_AT_SETTING, now);
      lastHighAttemptExecutedAt = now;
    }

    executedAttempts += 1;
  }
}

async function shouldRunByLastScan(env: Env, settingKey: string, intervalMinutes: number): Promise<boolean> {
  const lastScan = await getSetting(env, settingKey);
  if (!lastScan) return true;

  const lastMs = Date.parse(lastScan);
  if (!Number.isFinite(lastMs)) return true;
  return Date.now() - lastMs >= intervalMinutes * 60 * 1000;
}

async function shouldScanRetest(env: Env): Promise<boolean> {
  const intervalMinutes = parseNumber(env.SCAN_INTERVAL_MINUTES, DEFAULT_SCAN_INTERVAL_MINUTES);
  return await shouldRunByLastScan(env, 'last_scan_at', intervalMinutes);
}

async function shouldScanOkToTest(env: Env): Promise<boolean> {
  const intervalMinutes = parseNumber(
    env.OK_TO_TEST_SCAN_INTERVAL_MINUTES,
    DEFAULT_OK_TO_TEST_SCAN_INTERVAL_MINUTES
  );
  return await shouldRunByLastScan(env, 'last_ok_to_test_scan_at', intervalMinutes);
}

async function handleCron(env: Env, runId: string): Promise<void> {
  const stageErrors: string[] = [];

  if (await shouldScanRetest(env)) {
    try {
      await scanAndSchedule(env, runId);
      await setSetting(env, 'last_scan_at', nowIso());
    } catch (error) {
      logErrorEvent('cron.stage_failed', error, {
        run_id: runId,
        stage: 'retest_scan',
      });
      stageErrors.push(`retest scan failed: ${formatErrorMessage(error)}`);
    }
  }

  try {
    await executeDueAttempts(env, runId);
  } catch (error) {
    logErrorEvent('cron.stage_failed', error, {
      run_id: runId,
      stage: 'retest_execution',
    });
    stageErrors.push(`retest execution failed: ${formatErrorMessage(error)}`);
  }

  if (await shouldScanOkToTest(env)) {
    try {
      await scanAndAutoOkToTest(env, runId);
      await setSetting(env, 'last_ok_to_test_scan_at', nowIso());
    } catch (error) {
      logErrorEvent('cron.stage_failed', error, {
        run_id: runId,
        stage: 'ok_to_test_scan',
      });
      stageErrors.push(`ok-to-test scan failed: ${formatErrorMessage(error)}`);
    }
  }

  if (stageErrors.length > 0) {
    throw new Error(stageErrors.join('\n\n'));
  }
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
  const scheduledTimeMs = (event as unknown as { scheduledTime?: number }).scheduledTime ?? null;
  const cron = (event as unknown as { cron?: string }).cron ?? null;
  await env.DB.prepare(
    'INSERT INTO cron_runs (run_id, scheduled_time_ms, cron, status) VALUES (?, ?, ?, ?)'
  )
    .bind(runId, scheduledTimeMs, cron, 'started')
    .run();

  try {
    await handleCron(env, runId);
    await recordCronRun(env, runId, { status: 'success', errorMessage: null });
  } catch (error) {
    const message = formatErrorMessage(error);
    logErrorEvent('cron.run_failed', error, {
      run_id: runId,
      cron,
      scheduled_time_ms: scheduledTimeMs,
    });
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
    let checkResult: CheckDecision;
    let failedChecks: string[] = [];
    if (isMergeConflict(pr)) {
      checkResult = { status: 'conflict', shouldRetest: false, log: 'Merge conflict' };
    } else {
      const summary = await getCheckStateSummary(pr.head.sha, c.env.GITHUB_TOKEN);
      failedChecks = summary.failed;
      checkResult = classifyChecks(summary.failed, summary.pending, blacklist);
    }

    await c.env.DB.prepare('INSERT OR IGNORE INTO tracked_prs (pr_number) VALUES (?)').bind(num).run();
    const state = await upsertStateAndResetIfHeadChanged(c.env, pr, failedChecks, checkResult);
    if (state && checkResult.status === 'success' && state.attempt_count >= HIGH_ATTEMPT_THRESHOLD) {
      await resetAttemptsIfRecovered(c.env, num);
      return c.json({ ok: true, pr_number: num, status: checkResult.status });
    }

    if (checkResult.shouldRetest) {
      if (state && !state.disabled_at) {
        const pending = await getPendingAttempt(c.env, num);
        if (!pending) {
          await scheduleImmediateAttempt(c.env, state);
          await executeDueAttempts(c.env, `manual-track-${num}-${crypto.randomUUID()}`);
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
            s.last_retest_at,
            s.disabled_at,
            s.last_failure_checks,
            s.last_seen_updated_at,
            s.last_seen_head_sha,
            COALESCE(s.last_check_status, 'unknown') AS last_check_status,
            s.last_check_at,
            s.last_error_message,
            s.last_status_log
     FROM tracked_prs t
     LEFT JOIN retest_state s ON s.pr_number = t.pr_number
     ORDER BY
       CASE COALESCE(s.last_check_status, 'unknown')
         WHEN 'running' THEN 0
         WHEN 'failed'  THEN 1
         WHEN 'ignored' THEN 2
         ELSE 3
       END,
       COALESCE(s.attempt_count, 0) ASC,
       t.pr_number ASC`
  )
    .all<RetestStateRow>();

  const prs = (rows.results || []).map((row) => ({
    pr_number: row.pr_number,
    attempt_count: row.attempt_count,
    next_retest_at: row.next_retest_at,
    last_retest_at: row.last_retest_at,
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
  let lastCronErrorMessage: string | null = null;
  let nextCronIso: string | null = null;
  let nextScanIso: string | null = null;
  const row = await c.env.DB.prepare(
    'SELECT started_at, status, error_message FROM cron_runs ORDER BY started_at DESC LIMIT 1'
  ).first<{ started_at: string; status: string; error_message: string | null }>();
  if (row) {
    lastCronIso = row.started_at;
    lastCronStatus = row.status;
    lastCronErrorMessage = row.error_message;
    const lastMs = Date.parse(row.started_at);
    if (Number.isFinite(lastMs)) {
      const nextMs = lastMs + CRON_INTERVAL_MINUTES * 60 * 1000;
      nextCronIso = new Date(nextMs).toISOString();
    }
  }

  const scanIntervalMinutes = parseNumber(c.env.SCAN_INTERVAL_MINUTES, DEFAULT_SCAN_INTERVAL_MINUTES);
  const lastScan = await getSetting(c.env, 'last_scan_at');
  if (lastScan) {
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
  const cronErrorLine = lastCronStatus === 'error' && lastCronErrorMessage
    ? `<div class="subtitle-line subtitle-error"><details><summary>Last cron error</summary><pre>${escapeHtml(lastCronErrorMessage)}</pre></details></div>`
    : '';

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
          margin-bottom: 24px;
          display: flex;
          flex-direction: column;
          gap: 6px;
          line-height: 1.5;
        }
        .subtitle-line {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
        }
        .subtitle-error details {
          width: 100%;
          color: #fecaca;
        }
        .subtitle-error summary {
          cursor: pointer;
          font-weight: 600;
        }
        .subtitle-error pre {
          margin: 8px 0 0;
          padding: 12px;
          white-space: pre-wrap;
          word-break: break-word;
          border-radius: 8px;
          background: rgba(127, 29, 29, 0.35);
          border: 1px solid rgba(248, 113, 113, 0.35);
          color: #fee2e2;
          font-size: 12px;
          font-family: 'Consolas', 'Monaco', monospace;
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
          background: transparent;
          color: #0284c7;
          padding: 2px 6px;
          font-size: 12px;
          line-height: 1;
        }
        .copy-btn svg {
          width: 14px;
          height: 14px;
          display: block;
          stroke: currentColor;
        }
        .copy-btn:hover { color: #0ea5e9; }
        .copy-btn:active { transform: translateY(1px); }
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
        .badge-conflict { background: #fee2e2; color: #b91c1c; }
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
        <div class="subtitle">
          <div class="subtitle-line">pingcap/tidb</div>
          <div class="subtitle-line">Last cron: ${lastCronSpan} • Next cron: ${nextCronSpan}</div>
          <div class="subtitle-line">Next scan: ${nextScanSpan}</div>
          ${cronErrorLine}
        </div>

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
            prs.forEach(({ pr_number, attempt_count, next_retest_at, last_retest_at, disabled_at, last_seen_updated_at, last_check_status, last_check_at, last_error_message, last_status_log, failed_checks }) => {
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
                nextBadge.dataset.prefix = 'next retest ';
                nextBadge.textContent = 'next retest ' + next_retest_at;
                meta.appendChild(nextBadge);
              }

              if (last_retest_at) {
                const lastRetest = document.createElement('span');
                lastRetest.dataset.iso = last_retest_at;
                lastRetest.dataset.prefix = 'retest requested · ';
                lastRetest.textContent = 'retest requested ' + last_retest_at;
                meta.appendChild(lastRetest);
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
                lastSeen.dataset.prefix = 'updated · ';
                lastSeen.textContent = 'updated ' + last_seen_updated_at;
                meta.appendChild(lastSeen);
              }

              if (last_check_at) {
                const lastCheck = document.createElement('span');
                lastCheck.dataset.iso = last_check_at;
                lastCheck.dataset.prefix = 'checked · ';
                lastCheck.textContent = 'checked ' + last_check_at;
                meta.appendChild(lastCheck);
              }

              left.appendChild(link);
              header.appendChild(left);

              const delBtn = document.createElement('button');
              delBtn.className = 'remove-btn';
              delBtn.type = 'button';
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
              const copyBtn = document.createElement('button');
              copyBtn.className = 'copy-btn';
              copyBtn.type = 'button';
              copyBtn.setAttribute('aria-label', 'Copy PR ID');
              copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><rect x="4" y="4" width="11" height="11" rx="2"></rect></svg>';
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
              left.appendChild(copyBtn);
              left.appendChild(meta);
              header.appendChild(delBtn);
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

              if (last_status_log) {
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
