// 深度搜索模块 - SQLite索引（带缓存）

import { Path } from 'scripting'
import { getFileInfo, getFileCategory, readTextFile } from './utils'
import { getMaxIndexFileSizeKB } from './SearchState'

/** 深度搜索结果 */
export interface DeepSearchResult {
  path: string
  name: string
  relativePath: string
  size: number
  modificationDate: number
  isDirectory: boolean
  category: string
  icon: string
  iconColor: string
  /** 匹配到的行号（仅内容匹配时） */
  matchedLine?: number
  /** 匹配行内容 */
  matchedContent?: string
  /** 所有匹配行（含行号与内容） */
  allMatches?: { line: number; content: string }[]
  /** 标记是否为 iCloud 尚未下载到本地的云端文件 */
  isCloudPlaceholder?: boolean
}

/** 索引统计信息 */
export interface IndexStats {
  total: number
  lastUpdated: number | null
  dirPath: string
}

const dbCache = new Map<string, SQLite.Database>()
const indexStatsCache = new Map<string, IndexStats>()

function getDbPath(dirPath: string): string {
  const hash = simpleHash(dirPath)
  const dbDir = Path.join(FileManager.documentsDirectory, '.file_store', '.search-index')
  return Path.join(dbDir, `index-${hash}.sqlite`)
}

function simpleHash(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash
  }
  return Math.abs(hash).toString(36)
}

async function ensureIndexDir(): Promise<void> {
  const dbDir = Path.join(FileManager.documentsDirectory, '.file_store', '.search-index')
  const exists = await FileManager.exists(dbDir)
  if (!exists) {
    await FileManager.createDirectory(dbDir, true)
  }
}

async function openDatabase(dirPath: string): Promise<SQLite.Database> {
  if (dbCache.has(dirPath)) {
    return dbCache.get(dirPath)!
  }
  
  await ensureIndexDir()
  const dbPath = getDbPath(dirPath)
  const db = SQLite.open(dbPath)
  
  await db.createTable('files', {
    columns: [
      { name: 'path', type: 'TEXT', primaryKey: true },
      { name: 'name', type: 'TEXT', notNull: true },
      { name: 'relative_path', type: 'TEXT', notNull: true },
      { name: 'size', type: 'INTEGER', defaultValue: 0 },
      { name: 'modification_date', type: 'REAL', defaultValue: 0 },
      { name: 'is_directory', type: 'INTEGER', defaultValue: 0 },
      { name: 'category', type: 'TEXT', defaultValue: 'unknown' },
      { name: 'icon', type: 'TEXT', defaultValue: 'doc' },
      { name: 'icon_color', type: 'TEXT', defaultValue: 'systemGray' },
      { name: 'parent_path', type: 'TEXT' },
      { name: 'content', type: 'TEXT' },
    ],
    ifNotExists: true
  })
  
  await db.createTable('metadata', {
    columns: [
      { name: 'key', type: 'TEXT', primaryKey: true },
      { name: 'value', type: 'TEXT' },
    ],
    ifNotExists: true
  })
  
  await db.createIndex('idx_parent', {
    table: 'files',
    columns: ['parent_path'],
    ifNotExists: true
  })
  
  try {
    await db.execute('ALTER TABLE files ADD COLUMN content TEXT')
  } catch {}
  
  dbCache.set(dirPath, db)
  return db
}

export function closeDatabase(dirPath?: string): void {
  if (dirPath) {
    dbCache.delete(dirPath)
    indexStatsCache.delete(dirPath)
  } else {
    dbCache.clear()
    indexStatsCache.clear()
  }
}

export async function isIndexValid(dirPath: string, maxAge: number = 172800000): Promise<boolean> {
  try {
    const dbPath = getDbPath(dirPath)
    const exists = await FileManager.exists(dbPath)
    if (!exists) return false
    
    const database = await openDatabase(dirPath)
    const result = await database.fetchOne<{ value: string }>(
      "SELECT value FROM metadata WHERE key = 'last_updated'"
    )
    if (!result?.value) return false
    
    const lastUpdated = parseInt(result.value)
    return (Date.now() - lastUpdated) < maxAge
  } catch {
    return false
  }
}

export async function getIndexStats(dirPath: string): Promise<IndexStats> {
  if (indexStatsCache.has(dirPath)) {
    return indexStatsCache.get(dirPath)!
  }
  
  try {
    const database = await openDatabase(dirPath)
    const totalResult = await database.fetchOne<{ total: number }>(
      'SELECT COUNT(*) as total FROM files'
    )
    const timeResult = await database.fetchOne<{ value: string }>(
      "SELECT value FROM metadata WHERE key = 'last_updated'"
    )
    
    const stats: IndexStats = {
      total: totalResult?.total || 0,
      lastUpdated: timeResult?.value ? parseInt(timeResult.value) : null,
      dirPath
    }
    indexStatsCache.set(dirPath, stats)
    return stats
  } catch {
    return { total: 0, lastUpdated: null, dirPath }
  }
}

interface IndexTask {
  cancelled: boolean
}

let _activeIndexTask: IndexTask | null = null
// 同一时刻只允许一个索引任务接触 SQLite。新请求会取消旧任务；队列确保旧任务
// 已完全退出（包括最后一次批量写入）后，才允许新任务清空/重建索引。
let _indexBuildQueue: Promise<void> = Promise.resolve()
let _latestIndexBuildRequest = 0

function createIndexCancelledError(): Error {
  const error = new Error("索引构建已取消")
  ;(error as any).__buildCancelled = true
  return error
}

export function cancelBuildIndex(): void {
  _latestIndexBuildRequest++
  if (_activeIndexTask) _activeIndexTask.cancelled = true
}

export async function buildIndex(
  dirPath: string,
  onProgress?: (count: number, currentPath: string) => void,
  forceRebuild: boolean = false,
): Promise<number> {
  cancelBuildIndex()
  const requestId = ++_latestIndexBuildRequest
  const previous = _indexBuildQueue
  let releaseQueue: () => void = () => {}
  _indexBuildQueue = new Promise<void>((resolve) => { releaseQueue = resolve })
  await previous.catch(() => {})
  try {
    // 等待期间又出现更晚的重建请求时，直接放弃本请求，避免排队任务依次重复建库。
    if (requestId !== _latestIndexBuildRequest) throw createIndexCancelledError()
    return await buildIndexExclusive(dirPath, onProgress, forceRebuild)
  } finally {
    releaseQueue()
  }
}

async function buildIndexExclusive(
  dirPath: string,
  onProgress?: (count: number, currentPath: string) => void,
  forceRebuild: boolean = false,
): Promise<number> {
  const task: IndexTask = { cancelled: false }
  _activeIndexTask = task
  const assertTaskActive = () => {
    if (task.cancelled || _activeIndexTask !== task) throw createIndexCancelledError()
  }

  if (!forceRebuild && await isIndexValid(dirPath)) {
    assertTaskActive()
    const stats = await getIndexStats(dirPath)
    if (stats.total > 0) {
      if (_activeIndexTask === task) _activeIndexTask = null
      return stats.total
    }
  }
  
  const database = await openDatabase(dirPath)
  assertTaskActive()
  // 先废止旧完成标记，再清空旧内容。若重建取消/失败，半截索引绝不能沿用旧
  // last_updated 而被 isIndexValid 误判为 48 小时内有效。
  await database.execute("DELETE FROM metadata WHERE key = 'last_updated'")
  indexStatsCache.delete(dirPath)
  await database.execute('DELETE FROM files')
  assertTaskActive()
  
  let count = 0
  const maxIndexBytes = getMaxIndexFileSizeKB() * 1024
  const BATCH_SIZE = 80
  const INSERT_COLS = 'path, name, relative_path, size, modification_date, is_directory, category, icon, icon_color, parent_path, content'
  const INSERT_ROW = '(?,?,?,?,?,?,?,?,?,?,?)'
  let pendingRows: any[][] = []

  async function flushBatch(): Promise<void> {
    if (pendingRows.length === 0) return
    assertTaskActive()
    const batch = pendingRows
    pendingRows = []
    const placeholders = Array(batch.length).fill(INSERT_ROW).join(',')
    const flatArgs: any[] = []
    for (const row of batch) for (const v of row) flatArgs.push(v)
    try {
      await database.execute(
        `INSERT OR REPLACE INTO files (${INSERT_COLS}) VALUES ${placeholders}`,
        flatArgs
      )
      // 写入不可撤销；若此时已取消，阻止后续遍历与完成标记提交。
      assertTaskActive()
    } catch (e) {
      const wrapped = e instanceof Error ? e : new Error(String(e))
      ;(wrapped as any).__batchFlushError = true
      throw wrapped
    }
  }

  function isTextLikeFile(cat: string): boolean {
    return cat === 'text' || cat === 'code' || cat === 'data'
  }

  async function readTextContent(filePath: string, maxBytes: number): Promise<string> {
    try {
      const text = await readTextFile(filePath, maxBytes)
      if (!text) return ''
      return text.length > 51200 ? text.substring(0, 51200) : text
    } catch {
      return ''
    }
  }
// DeepSearch.ts 中的 traverse 修复

async function traverse(currentDir: string, relativePath: string): Promise<void> {
  let entries: string[] = []
  try {
    entries = await FileManager.readDirectory(currentDir)
  } catch (e) {
    console.log(`[索引] 无法读取目录 ${currentDir}:`, e)
    return
  }

  for (const entry of entries) {
    assertTaskActive()

    const diskPath = Path.join(currentDir, entry)
    
    // 识别 iCloud 未下载占位文件 .<name>.<ext>.icloud
    const isCloudPlaceholder = entry.startsWith('.') && entry.endsWith('.icloud')
    const realName = isCloudPlaceholder ? entry.slice(1, -7) : entry
    const targetPath = Path.join(currentDir, realName)
    const relPath = relativePath ? `${relativePath}/${realName}` : realName

    try {
      const ext = Path.extname(realName)
      const category = getFileCategory(ext)
      
      // 使用修复后的 getFileInfo
      const info = await getFileInfo(diskPath)
      assertTaskActive()
      
      if (!info.isDirectory && info.size > maxIndexBytes) {
        continue
      }

      // 未下载的 iCloud 文件不强行读取内容（避免卡死），只索引文件名
      // 本地文件或已下载的 iCloud 文本文件才读取内容
      let content = ''
      if (!info.isDirectory && !isCloudPlaceholder && isTextLikeFile(category)) {
        let isDownloaded = true
        // 只有文件被标记为存储在 iCloud 时，才通过 isiCloudFileDownloaded 判断是否下载；纯本地文件直接可读
        if (typeof FileManager.isFileStoredIniCloud === 'function' && typeof FileManager.isiCloudFileDownloaded === 'function') {
          try {
            if (FileManager.isFileStoredIniCloud(diskPath)) {
              isDownloaded = FileManager.isiCloudFileDownloaded(diskPath)
            }
          } catch {
            isDownloaded = true
          }
        }
        if (isDownloaded) {
          content = await readTextContent(diskPath, maxIndexBytes)
          assertTaskActive()
        }
      }

      pendingRows.push([
        targetPath,
        realName,
        relPath,
        info.size,
        info.modificationDate,
        info.isDirectory ? 1 : 0,
        category,
        info.icon,
        info.iconColor,
        currentDir,
        content
      ])

      count++
      onProgress?.(count, targetPath)
      if (pendingRows.length >= BATCH_SIZE) {
        await flushBatch()
      }

      if (info.isDirectory && !task.cancelled) {
        await traverse(diskPath, relPath)
      }
    } catch (e) {
      if (e && (e as any).__batchFlushError) throw e
    }
  }
}

  
  try {
    // 目录存在性校验：只做读取校验，不对目录执行无效的 downloadFileFromiCloud
    await FileManager.readDirectory(dirPath)
    await traverse(dirPath, '')

    assertTaskActive()
    await flushBatch()
    // flush 期间仍可能收到取消；完成时间只能由仍处于活动状态的任务写入。
    assertTaskActive()
    await database.execute(
      "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_updated', ?)",
      [String(Date.now())]
    )
    assertTaskActive()
  } catch (e) {
    console.log('建立索引失败:', e)
    // 即使取消发生在 last_updated 写入之后，也撤销完成标记，避免半截索引被复用。
    if ((e as any)?.__buildCancelled) {
      try { await database.execute("DELETE FROM metadata WHERE key = 'last_updated'") } catch { }
      indexStatsCache.delete(dirPath)
    }
    if (_activeIndexTask === task) _activeIndexTask = null
    throw e
  }
  
  assertTaskActive()
  indexStatsCache.set(dirPath, {
    total: count,
    lastUpdated: Date.now(),
    dirPath
  })
  
  if (_activeIndexTask === task) _activeIndexTask = null
  return count
}

export async function searchFromIndex(
  dirPath: string,
  query: string,
  limit: number = 100,
  offset: number = 0
): Promise<DeepSearchResult[]> {
  const database = await openDatabase(dirPath)
  if (!query.trim()) return []
  
  const esc = query.toLowerCase().replace(/[%_\\]/g, '\\$&')
  const q = `%${esc}%`
  const prefix = `${esc}%`
  
  const results = await database.fetchAll<any>(
    `SELECT path, name, relative_path as relativePath, size, modification_date as modificationDate, 
            is_directory as isDirectory, category, icon, icon_color as iconColor, content
     FROM files 
     WHERE name LIKE ? ESCAPE '\\' OR LOWER(content) LIKE ? ESCAPE '\\'
     ORDER BY 
       CASE WHEN LOWER(name) = ? THEN 0
            WHEN LOWER(name) LIKE ? ESCAPE '\\' THEN 1
            WHEN LOWER(content) LIKE ? ESCAPE '\\' THEN 2
            ELSE 3 END,
       name ASC
     LIMIT ? OFFSET ?`,
    [q, q, query.toLowerCase(), prefix, q, limit, offset]
  )
  
  return results.map((r: any) => {
    const qLower = query.toLowerCase()
    const nameLower = r.name.toLowerCase()
    let matchedLine: number | undefined
    let matchedContent: string | undefined
    let allMatches: { line: number; content: string }[] = []

    if (r.content) {
      const lines = r.content.split('\n')
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].toLowerCase().includes(qLower)) {
          allMatches.push({
            line: i + 1,
            content: lines[i].trim()
          })
        }
      }
    }

    if (!nameLower.includes(qLower) && allMatches.length > 0) {
      matchedLine = allMatches[0].line
      matchedContent = allMatches[0].content
    }

    const { content, ...rest } = r
    return {
      ...rest,
      isDirectory: Boolean(r.isDirectory),
      matchedLine,
      matchedContent,
      allMatches,
      content: undefined
    }
  })
}

export async function deleteIndex(dirPath: string): Promise<void> {
  closeDatabase(dirPath)
  const dbPath = getDbPath(dirPath)
  if (await FileManager.exists(dbPath)) {
    await FileManager.remove(dbPath)
  }
}

export async function deleteAllIndexes(): Promise<void> {
  closeDatabase()
  const dbDir = Path.join(FileManager.documentsDirectory, '.file_store', '.search-index')
  if (await FileManager.exists(dbDir)) {
    await FileManager.remove(dbDir)
  }
}

export function formatIndexTime(timestamp: number | null): string {
  if (!timestamp) return '未知'
  const now = Date.now()
  const diff = now - timestamp
  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return `${Math.floor(diff / 60000)} 分钟前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)} 小时前`
  const date = new Date(timestamp)
  return `${date.getMonth() + 1}/${date.getDate()} ${date.getHours()}:${String(date.getMinutes()).padStart(2, '0')}`
}
