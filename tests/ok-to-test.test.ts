import assert from 'node:assert/strict';
import test from 'node:test';

import { getOkToTestSkipReason, hasRequiredOkToTestLabels, isAfterOkToTestHourUtcPlus8 } from '../src/ok-to-test';

test('requires both lgtm and approved labels', () => {
  assert.equal(hasRequiredOkToTestLabels(['lgtm']), false);
  assert.equal(hasRequiredOkToTestLabels(['approved']), false);
  assert.equal(hasRequiredOkToTestLabels(['lgtm', 'approved']), true);
});

test('allows auto ok-to-test at and after UTC+8 16:00', () => {
  assert.equal(isAfterOkToTestHourUtcPlus8(new Date('2026-03-27T07:59:59Z')), false);
  assert.equal(isAfterOkToTestHourUtcPlus8(new Date('2026-03-27T08:00:00Z')), true);
});

test('skips before UTC+8 16:00 even when labels and failed checks are present', () => {
  const reason = getOkToTestSkipReason({
    failedChecks: ['unit-test'],
    labels: ['lgtm', 'approved'],
    now: new Date('2026-03-27T07:30:00Z'),
    tiprowTriggered: false,
    hasMergeConflict: false,
  });

  assert.equal(reason, 'Current time is before UTC+8 16:00');
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
