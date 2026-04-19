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
    retestMode: null,
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
    retestMode: null,
  });
});

test('immediately retries without counting when fast_test_tiprow fails alone', () => {
  const result = classifyChecks(['fast_test_tiprow'], [], new Set());

  assert.deepEqual(result, {
    status: 'failed',
    shouldRetest: true,
    log: 'Failed checks detected',
    retestMode: 'immediate_no_count',
  });
});

test('immediately retries without counting when unit-test fails alone', () => {
  const result = classifyChecks(['idc-jenkins-ci-tidb/unit-test'], [], new Set());

  assert.deepEqual(result, {
    status: 'failed',
    shouldRetest: true,
    log: 'Failed checks detected',
    retestMode: 'immediate_no_count',
  });
});

test('allows retry when tide is the only pending check', () => {
  const result = classifyChecks(['unit-test'], ['tide'], new Set());

  assert.deepEqual(result, {
    status: 'failed',
    shouldRetest: true,
    log: 'Failed checks detected',
    retestMode: 'normal',
  });
});

test('blocks retry when a non-tide check is still pending', () => {
  const result = classifyChecks(['unit-test'], ['tide', 'lint'], new Set());

  assert.deepEqual(result, {
    status: 'running',
    shouldRetest: false,
    log: 'Checks running or queued',
    retestMode: null,
  });
});

test('does not retry without failed checks even if tide is pending', () => {
  const result = classifyChecks([], [' tide '], new Set());

  assert.deepEqual(result, {
    status: 'success',
    shouldRetest: false,
    log: 'No failed checks',
    retestMode: null,
  });
});
