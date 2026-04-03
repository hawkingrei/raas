import assert from 'node:assert/strict';
import test from 'node:test';

import { getBackoffDelayMinutes, HIGH_ATTEMPT_INTERVAL_MS } from '../src/index';

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
