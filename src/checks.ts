export type CheckStatus = 'ignored' | 'success' | 'failed' | 'running' | 'conflict';

export type CheckDecision = {
  status: CheckStatus;
  shouldRetest: boolean;
  log: string;
};

export const BLOCKED_CHECK = 'fast_test_tiprow';
export const COMPANION_BLOCKED_CHECKS = [
  'idc-jenkins-ci-tidb/unit-test',
  'tidb_parser_test',
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
      };
    }
  }
  if (failedChecks.some((name) => blacklist.has(name))) {
    return { status: 'ignored', shouldRetest: false, log: 'Ignored by blacklist' };
  }
  if (pendingChecks.some((name) => !isTideCheck(name))) {
    return { status: 'running', shouldRetest: false, log: 'Checks running or queued' };
  }
  if (failedChecks.length === 0) {
    return { status: 'success', shouldRetest: false, log: 'No failed checks' };
  }
  return { status: 'failed', shouldRetest: true, log: 'Failed checks detected' };
}
