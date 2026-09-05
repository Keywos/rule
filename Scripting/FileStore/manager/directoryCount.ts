const countCache = new Map<string, { count: number; timestamp: number }>();
const countInflight = new Map<string, Promise<number>>();
const COUNT_CACHE_TTL = 1500;

/** 清除目录数量缓存；文件系统写操作后调用。 */
export function invalidateDirectoryCount(dirPath: string) {
  countCache.delete(dirPath);
  countInflight.delete(dirPath);
}

/** 清除所有目录数量缓存。 */
export function clearDirectoryCountCache() {
  countCache.clear();
  countInflight.clear();
}

/** 读取目录条目数，合并并发请求并短暂缓存结果。 */
export async function countDirectoryItems(dirPath: string, forceRefresh: boolean = false): Promise<number> {
  if (!forceRefresh) {
    const cached = countCache.get(dirPath);
    if (cached && Date.now() - cached.timestamp < COUNT_CACHE_TTL) return cached.count;
    const inflight = countInflight.get(dirPath);
    if (inflight) return inflight;
  } else {
    invalidateDirectoryCount(dirPath);
  }

  let request: Promise<number>;
  request = FileManager.readDirectory(dirPath).then((entries) => {
    const count = entries.length;
    if (countInflight.get(dirPath) === request) {
      countCache.set(dirPath, { count, timestamp: Date.now() });
    }
    return count;
  });
  countInflight.set(dirPath, request);
  try {
    return await request;
  } finally {
    if (countInflight.get(dirPath) === request) countInflight.delete(dirPath);
  }
}

/**
 * 批量读取目录条目数，并限制实际 readDirectory 的并发量。
 * 大量文件夹同时出现在列表中时，避免 Promise.all 造成瞬时 I/O 峰值；
 * 单个路径仍复用 countDirectoryItems 的缓存与进行中请求。
 */
export async function countDirectoryItemsBatch(
  dirPaths: string[],
  forceRefresh: boolean = false,
  concurrency: number = 8,
): Promise<Array<{ path: string; count: number | null }>> {
  const results = new Array<{ path: string; count: number | null }>(dirPaths.length);
  let nextIndex = 0;
  const workerCount = Math.min(Math.max(1, concurrency), dirPaths.length);

  await Promise.all(Array.from({ length: workerCount }, async () => {
    while (nextIndex < dirPaths.length) {
      const index = nextIndex++;
      const path = dirPaths[index];
      try {
        results[index] = { path, count: await countDirectoryItems(path, forceRefresh) };
      } catch {
        results[index] = { path, count: null };
      }
    }
  }));

  return results;
}
