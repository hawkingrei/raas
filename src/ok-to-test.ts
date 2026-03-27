import { BLOCKED_CHECK } from './checks';

const UTC_PLUS_8_OFFSET_MS = 8 * 60 * 60 * 1000;
const OK_TO_TEST_START_HOUR_UTC8 = 16;

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

export function hasRequiredOkToTestLabels(labels: readonly string[]): boolean {
  return hasNormalizedLabel(labels, 'lgtm') && hasNormalizedLabel(labels, 'approved');
}

export function isAfterOkToTestHourUtcPlus8(now: Date): boolean {
  const utcPlus8 = new Date(now.getTime() + UTC_PLUS_8_OFFSET_MS);
  return utcPlus8.getUTCHours() >= OK_TO_TEST_START_HOUR_UTC8;
}

export function getOkToTestSkipReason(input: OkToTestDecisionInput): string | null {
  if (!hasRequiredOkToTestLabels(input.labels)) {
    return 'Missing required labels: lgtm + approved';
  }

  if (!isAfterOkToTestHourUtcPlus8(input.now)) {
    return 'Current time is before UTC+8 16:00';
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
