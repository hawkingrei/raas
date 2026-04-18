export type CheckStatus = 'ignored' | 'success' | 'failed' | 'running' | 'conflict';
export type RetestMode = 'normal' | 'immediate_no_count' | null;

export type CheckDecision = {
  status: CheckStatus;
  shouldRetest: boolean;
  log: string;
  retestMode: RetestMode;
};

export const BLOCKED_CHECK = 'fast_test_tiprow';
export const COMPANION_BLOCKED_CHECKS = [
  'idc-jenkins-ci-tidb/unit-test',
  'tidb_parser_test',
];
export const IMMEDIATE_NO_COUNT_RETEST_CHECKS = [
  BLOCKED_CHECK,
  'idc-jenkins-ci-tidb/unit-test',
];

export function isTideCheck(value: string): boolean {
  return value.trim().toLowerCase() === 'tide';
}

export function classifyChecks(
  failedChecks: string[],
  pendingChecks: string[],
  blacklist: Set<string>
): CheckDecision {
  if (failedChecks.includes(BLOCKED_CHECK)) {
    const failedCompanion = COMPANION_BLOCKED_CHECKS.find((name) =>
      failedChecks.includes(name)
    );
    if (failedCompanion) {
      return {
        status: 'ignored',
        shouldRetest: false,
        log: `Blocked checks: ${BLOCKED_CHECK} + ${failedCompanion}`,
        retestMode: null,
      };
    }
  }
  if (failedChecks.some((name) => blacklist.has(name))) {
    return { status: 'ignored', shouldRetest: false, log: 'Ignored by blacklist', retestMode: null };
  }
  if (pendingChecks.some((name) => !isTideCheck(name))) {
    return { status: 'running', shouldRetest: false, log: 'Checks running or queued', retestMode: null };
  }
  if (failedChecks.length === 0) {
    return { status: 'success', shouldRetest: false, log: 'No failed checks', retestMode: null };
  }

  const retestMode =
    failedChecks.length === 1 && IMMEDIATE_NO_COUNT_RETEST_CHECKS.includes(failedChecks[0])
      ? 'immediate_no_count'
      : 'normal';
  return { status: 'failed', shouldRetest: true, log: 'Failed checks detected', retestMode };
}
