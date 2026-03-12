import assert from 'node:assert/strict';
import test from 'node:test';

import { takeScanBatch } from '../src/scan-batch';

test('takes a contiguous batch from the current cursor', () => {
  const result = takeScanBatch([101, 102, 103, 104], 1, 2);

  assert.deepEqual(result, {
    items: [102, 103],
    nextCursor: 3,
  });
});

test('wraps around to the beginning when the batch reaches the end', () => {
  const result = takeScanBatch([101, 102, 103, 104], 3, 3);

  assert.deepEqual(result, {
    items: [104, 101, 102],
    nextCursor: 2,
  });
});

test('caps the batch size to the available items', () => {
  const result = takeScanBatch([101, 102], 0, 10);

  assert.deepEqual(result, {
    items: [101, 102],
    nextCursor: 0,
  });
});
