export function takeScanBatch<T>(
  items: T[],
  cursor: number,
  batchSize: number
): { items: T[]; nextCursor: number } {
  if (items.length === 0) {
    return { items: [], nextCursor: 0 };
  }

  const normalizedBatchSize = Math.max(1, Math.trunc(batchSize));
  const size = Math.min(normalizedBatchSize, items.length);
  const normalizedCursor = ((Math.trunc(cursor) % items.length) + items.length) % items.length;

  const batch: T[] = [];
  for (let index = 0; index < size; index += 1) {
    batch.push(items[(normalizedCursor + index) % items.length]);
  }

  return {
    items: batch,
    nextCursor: (normalizedCursor + size) % items.length,
  };
}
