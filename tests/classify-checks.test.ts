import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyChecks } from '../src/checks';

test('allows retry when tide is the only pending check', () => {
  const result = classifyChecks(['unit-test'], ['tide'], new Set());

  assert.deepEqual(result, {
    status: 'failed',
    shouldRetest: true,
    log: 'Failed checks detected',
  });
});

test('blocks retry when a non-tide check is still pending', () => {
  const result = classifyChecks(['unit-test'], ['tide', 'lint'], new Set());

  assert.deepEqual(result, {
    status: 'running',
    shouldRetest: false,
    log: 'Checks running or queued',
  });
});

test('does not retry without failed checks even if tide is pending', () => {
  const result = classifyChecks([], [' tide '], new Set());

  assert.deepEqual(result, {
    status: 'success',
    shouldRetest: false,
    log: 'No failed checks',
  });
});
