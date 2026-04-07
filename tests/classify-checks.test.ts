import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyChecks } from '../src/checks';

test('blocks retry when fast_test_tiprow and unit-test both fail', () => {
  const result = classifyChecks(
    ['fast_test_tiprow', 'idc-jenkins-ci-tidb/unit-test'],
    [],
    new Set()
  );

  assert.deepEqual(result, {
    status: 'ignored',
    shouldRetest: false,
    log: 'Blocked checks: fast_test_tiprow + idc-jenkins-ci-tidb/unit-test',
  });
});

test('blocks retry when fast_test_tiprow and tidb_parser_test both fail', () => {
  const result = classifyChecks(
    ['fast_test_tiprow', 'tidb_parser_test'],
    [],
    new Set()
  );

  assert.deepEqual(result, {
    status: 'ignored',
    shouldRetest: false,
    log: 'Blocked checks: fast_test_tiprow + tidb_parser_test',
  });
});

test('allows retry when fast_test_tiprow fails without unit-test', () => {
  const result = classifyChecks(['fast_test_tiprow'], [], new Set());

  assert.deepEqual(result, {
    status: 'failed',
    shouldRetest: true,
    log: 'Failed checks detected',
  });
});

test('allows retry when unit-test fails without fast_test_tiprow', () => {
  const result = classifyChecks(['idc-jenkins-ci-tidb/unit-test'], [], new Set());

  assert.deepEqual(result, {
    status: 'failed',
    shouldRetest: true,
    log: 'Failed checks detected',
  });
});

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
