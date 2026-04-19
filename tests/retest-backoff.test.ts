import assert from 'node:assert/strict';
import test from 'node:test';

import {
  getAttemptIndex,
  getBackoffDelayMinutes,
  getNextAttemptCount,
  HIGH_ATTEMPT_INTERVAL_MS,
  HIGH_ATTEMPT_WINDOW_END_HOUR_UTC8,
  isInHighAttemptWindowUtcPlus8,
  isInNoCountRetestWindowUtcPlus8,
  NO_COUNT_RETEST_WINDOW_END_HOUR_UTC8,
} from '../src/index';

test('uses the updated retest backoff cadence before high-attempt mode', () => {
  assert.equal(getBackoffDelayMinutes(0), 0);
  assert.equal(getBackoffDelayMinutes(1), 40);
  assert.equal(getBackoffDelayMinutes(2), 80);
  assert.equal(getBackoffDelayMinutes(3), 160);
  assert.equal(getBackoffDelayMinutes(4), 360);
});

test('returns null once high-attempt scheduling takes over', () => {
  assert.equal(getBackoffDelayMinutes(5), null);
});

test('uses a two-hour global interval for high-attempt retries', () => {
  assert.equal(HIGH_ATTEMPT_INTERVAL_MS, 2 * 60 * 60 * 1000);
});

test('uses UTC+8 00:00-08:00 as the high-attempt retry window', () => {
  assert.equal(HIGH_ATTEMPT_WINDOW_END_HOUR_UTC8, 8);
  assert.equal(isInHighAttemptWindowUtcPlus8(new Date('2026-04-17T23:59:59Z')), true);
  assert.equal(isInHighAttemptWindowUtcPlus8(new Date('2026-04-18T00:00:00Z')), false);
});

test('uses UTC+8 00:00-09:00 as the no-count retry window', () => {
  assert.equal(NO_COUNT_RETEST_WINDOW_END_HOUR_UTC8, 9);
  assert.equal(isInNoCountRetestWindowUtcPlus8(new Date('2026-04-18T00:59:59Z')), true);
  assert.equal(isInNoCountRetestWindowUtcPlus8(new Date('2026-04-18T01:00:00Z')), false);
});
test('keeps attempt index and attempt count unchanged for no-count retries', () => {
  assert.equal(getAttemptIndex(0, false), 0);
  assert.equal(getAttemptIndex(5, false), 5);
  assert.equal(getNextAttemptCount(0, false), 0);
  assert.equal(getNextAttemptCount(5, false), 5);
});

test('increments attempt index and attempt count for normal retries', () => {
  assert.equal(getAttemptIndex(0, true), 1);
  assert.equal(getAttemptIndex(5, true), 6);
  assert.equal(getNextAttemptCount(0, true), 1);
  assert.equal(getNextAttemptCount(5, true), 6);
});
