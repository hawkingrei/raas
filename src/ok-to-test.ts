export type OkToTestAction = 'pending' | 'commented' | 'error';

export type OkToTestStateSnapshot = {
  last_seen_head_sha: string | null;
  last_action: OkToTestAction | null;
  last_action_at: string | null;
};

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

export function shouldRecheckCommentedState(
  state: Pick<OkToTestStateSnapshot, 'last_action' | 'last_action_at'>,
  graceMs: number,
  nowMs = Date.now()
): boolean {
  if (state.last_action !== 'commented') {
    return true;
  }

  if (!state.last_action_at) {
    return true;
  }

  const lastActionAtMs = Date.parse(state.last_action_at);
  if (!Number.isFinite(lastActionAtMs)) {
    return true;
  }

  return nowMs - lastActionAtMs >= graceMs;
}
