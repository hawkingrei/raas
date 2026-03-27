import { BLOCKED_CHECK } from './checks';

const UTC_PLUS_8_OFFSET_MS = 8 * 60 * 60 * 1000;
const OK_TO_TEST_START_HOUR_UTC8 = 16;

export type OkToTestAction = 'pending' | 'commented' | 'error';

export type OkToTestStateSnapshot = {
  last_seen_head_sha: string | null;
  last_action: OkToTestAction | null;
  last_action_at: string | null;
};

export type OkToTestDecisionInput = {
  failedChecks: readonly string[];
  labels: readonly string[];
  now: Date;
  tiprowTriggered: boolean;
  hasMergeConflict: boolean;
};

function normalizeLabel(label: string): string {
  return label.trim().toLowerCase();
}

function hasNormalizedLabel(labels: readonly string[], expected: string): boolean {
  const normalizedExpected = normalizeLabel(expected);
  return labels.some((label) => normalizeLabel(label) === normalizedExpected);
}

export function shouldEnqueueOkToTest(
  state: OkToTestStateSnapshot | null,
  headSha: string
): boolean {
  if (!state) {
    return true;
  }

  if (state.last_seen_head_sha !== headSha) {
    return true;
  }

  return state.last_action === 'error';
}

export function hasRequiredOkToTestLabels(labels: readonly string[]): boolean {
  return hasNormalizedLabel(labels, 'lgtm') && hasNormalizedLabel(labels, 'approved');
}

export function isWithinOkToTestWindowUtcPlus8(now: Date): boolean {
  const utcPlus8 = new Date(now.getTime() + UTC_PLUS_8_OFFSET_MS);
  const utcPlus8Hour = utcPlus8.getUTCHours();
  return utcPlus8Hour >= OK_TO_TEST_START_HOUR_UTC8;
}

export function getOkToTestSkipReason(input: OkToTestDecisionInput): string | null {
  if (!hasRequiredOkToTestLabels(input.labels)) {
    return 'Missing required labels: lgtm + approved';
  }

  if (!isWithinOkToTestWindowUtcPlus8(input.now)) {
    return 'Current time is outside UTC+8 16:00-00:00 window';
  }

  if (input.hasMergeConflict) {
    return 'Merge conflict';
  }

  if (input.tiprowTriggered) {
    return `${BLOCKED_CHECK} already triggered`;
  }

  if (input.failedChecks.length === 0) {
    return 'No failed checks detected';
  }

  return null;
}
