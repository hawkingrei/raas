import assert from 'node:assert/strict';
import test from 'node:test';

import {
  getOkToTestSkipReason,
  hasRequiredOkToTestLabels,
  isWithinOkToTestWindowUtcPlus8,
  shouldEnqueueOkToTest,
} from '../src/ok-to-test';

test('does not enqueue the same head again while pending', () => {
  const result = shouldEnqueueOkToTest(
    {
      last_seen_head_sha: 'abc123',
      last_action: 'pending',
      last_action_at: '2026-03-12T12:00:00.000Z',
    },
    'abc123'
  );

  assert.equal(result, false);
});

test('re-enqueues the same head after an error', () => {
  const result = shouldEnqueueOkToTest(
    {
      last_seen_head_sha: 'abc123',
      last_action: 'error',
      last_action_at: '2026-03-12T12:00:00.000Z',
    },
    'abc123'
  );

  assert.equal(result, true);
});

test('re-enqueues when head sha changes', () => {
  const result = shouldEnqueueOkToTest(
    {
      last_seen_head_sha: 'abc123',
      last_action: 'commented',
      last_action_at: '2026-03-12T12:00:00.000Z',
    },
    'def456'
  );

  assert.equal(result, true);
});

test('requires both lgtm and approved labels', () => {
  assert.equal(hasRequiredOkToTestLabels(['lgtm']), false);
  assert.equal(hasRequiredOkToTestLabels(['approved']), false);
  assert.equal(hasRequiredOkToTestLabels(['lgtm', 'approved']), true);
});

test('allows auto ok-to-test at and after UTC+8 16:00', () => {
  assert.equal(isWithinOkToTestWindowUtcPlus8(new Date('2026-03-27T07:59:59Z')), false);
  assert.equal(isWithinOkToTestWindowUtcPlus8(new Date('2026-03-27T08:00:00Z')), true);
});

test('skips before UTC+8 16:00 even when labels and failed checks are present', () => {
  const reason = getOkToTestSkipReason({
    failedChecks: ['unit-test'],
    labels: ['lgtm', 'approved'],
    now: new Date('2026-03-27T07:30:00Z'),
    tiprowTriggered: false,
    hasMergeConflict: false,
  });

  assert.equal(reason, 'Current time is outside UTC+8 16:00-00:00 window');
});

test('skips when fast_test_tiprow has already been triggered', () => {
  const reason = getOkToTestSkipReason({
    failedChecks: ['unit-test'],
    labels: ['lgtm', 'approved'],
    now: new Date('2026-03-27T08:30:00Z'),
    tiprowTriggered: true,
    hasMergeConflict: false,
  });

  assert.equal(reason, 'fast_test_tiprow already triggered');
});

test('skips when there are no failed checks', () => {
  const reason = getOkToTestSkipReason({
    failedChecks: [],
    labels: ['lgtm', 'approved'],
    now: new Date('2026-03-27T08:30:00Z'),
    tiprowTriggered: false,
    hasMergeConflict: false,
  });

  assert.equal(reason, 'No failed checks detected');
});

test('skips when the PR has merge conflict', () => {
  const reason = getOkToTestSkipReason({
    failedChecks: ['unit-test'],
    labels: ['lgtm', 'approved'],
    now: new Date('2026-03-27T08:30:00Z'),
    tiprowTriggered: false,
    hasMergeConflict: true,
  });

  assert.equal(reason, 'Merge conflict');
});

test('allows auto ok-to-test after UTC+8 16:00 with labels, failures, and no tiprow', () => {
  const reason = getOkToTestSkipReason({
    failedChecks: ['unit-test'],
    labels: ['lgtm', 'approved'],
    now: new Date('2026-03-27T08:30:00Z'),
    tiprowTriggered: false,
    hasMergeConflict: false,
  });

  assert.equal(reason, null);
});
