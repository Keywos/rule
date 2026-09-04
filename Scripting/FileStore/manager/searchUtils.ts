import type { FileInfo } from "./utils"

/** 按文件名筛选目录列表。 */
export function searchFiles(files: FileInfo[], query: string): FileInfo[] {
  if (!query.trim()) return files
  const normalizedQuery = query.toLowerCase()
  return files.filter((file) => file.name.toLowerCase().includes(normalizedQuery))
}
