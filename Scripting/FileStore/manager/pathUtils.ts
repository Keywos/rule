import { Path } from "scripting"

const uniqueWriteQueues = new Map<string, Promise<void>>()

/** 为同一目录串行分配不重复路径，避免并发写入互相覆盖。 */
export async function writeToUniquePath<T>(targetPath: string, write: (path: string) => Promise<T>): Promise<{ path: string; value: T }> {
  const dirPath = Path.dirname(targetPath)
  const previous = uniqueWriteQueues.get(dirPath) ?? Promise.resolve()
  let release: () => void = () => { }
  const current = new Promise<void>((resolve) => { release = resolve })
  const tail = previous.then(() => current)
  uniqueWriteQueues.set(dirPath, tail)
  await previous
  try {
    const path = await uniquePath(targetPath)
    return { path, value: await write(path) }
  } finally {
    release()
    if (uniqueWriteQueues.get(dirPath) === tail) uniqueWriteQueues.delete(dirPath)
  }
}

/** 生成不重名的路径，自动加 _01 _02 后缀。 */
export async function uniquePath(targetPath: string): Promise<string> {
  if (!(await FileManager.exists(targetPath))) return targetPath
  const ext = Path.extname(targetPath)
  const base = targetPath.slice(0, targetPath.length - ext.length)
  for (let index = 1; index <= 999; index++) {
    const candidate = `${base}_${String(index).padStart(2, "0")}${ext}`
    if (!(await FileManager.exists(candidate))) return candidate
  }
  return `${base}_${Date.now()}${ext}`
}

/** 从归档文件名生成安全的解压目录名。 */
export function sanitizeExtractDirName(archiveName: string): string {
  const knownExts = [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".rar", ".7z", ".tgz", ".tar", ".gz", ".bz2", ".xz"]
  let base = archiveName
  let removed = true
  while (removed) {
    removed = false
    const lower = base.toLowerCase()
    for (const ext of knownExts) {
      if (lower.endsWith(ext)) {
        base = base.slice(0, base.length - ext.length)
        removed = true
        break
      }
    }
  }
  const unknownExt = Path.extname(base)
  if (unknownExt && base.length > unknownExt.length) base = base.slice(0, base.length - unknownExt.length)
  base = base.replace(/[/\\:*?"<>|]/g, "_").trim()
  return !base || base === "." || base === ".." ? "extracted" : base
}
