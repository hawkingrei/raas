import assert from 'node:assert/strict';
import test from 'node:test';

import { shouldEnqueueOkToTest } from '../src/ok-to-test';

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
