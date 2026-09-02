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
}

/** 索引统计信息 */
export interface IndexStats {
  total: number
  lastUpdated: number | null
  dirPath: string
}

/** 数据库连接缓存 */
const dbCache = new Map<string, SQLite.Database>()

/** 索引状态缓存 */
const indexStatsCache = new Map<string, IndexStats>()

/** 获取数据库路径（存储在 Documents 目录，持久化） */
function getDbPath(dirPath: string): string {
  const hash = simpleHash(dirPath)
  // 使用 documentsDirectory 而不是 temporaryDirectory，确保持久化
  const dbDir = Path.join(FileManager.documentsDirectory, '.file_store', '.search-index')
  return Path.join(dbDir, `index-${hash}.sqlite`)
}

/** 简单的字符串哈希函数 */
function simpleHash(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash
  }
  return Math.abs(hash).toString(36)
}

/** 确保索引目录存在 */
async function ensureIndexDir(): Promise<void> {
  const dbDir = Path.join(FileManager.documentsDirectory, '.file_store', '.search-index')
  const exists = await FileManager.exists(dbDir)
  if (!exists) {
    await FileManager.createDirectory(dbDir, true)
  }
}

/** 打开或创建数据库（带缓存） */
async function openDatabase(dirPath: string): Promise<SQLite.Database> {
  // 检查内存缓存
  if (dbCache.has(dirPath)) {
    return dbCache.get(dirPath)!
  }
  
  await ensureIndexDir()
  const dbPath = getDbPath(dirPath)
  const db = SQLite.open(dbPath)
  
  // 创建文件表
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
  
  // 创建元数据表
  await db.createTable('metadata', {
    columns: [
      { name: 'key', type: 'TEXT', primaryKey: true },
      { name: 'value', type: 'TEXT' },
    ],
    ifNotExists: true
  })
  
  // 创建索引：仅保留 parent_path（目录查询用）。
  // name/content 用于 LIKE '%…%'（前导通配符），B-tree 索引无法命中，建了反而拖慢写入。
  await db.createIndex('idx_parent', {
    table: 'files',
    columns: ['parent_path'],
    ifNotExists: true
  })
  
  // 迁移：为旧数据库添加 content 列
  try {
    await db.execute('ALTER TABLE files ADD COLUMN content TEXT')
  } catch {
    // 列已存在，忽略
  }
  
  // 缓存数据库连接
  dbCache.set(dirPath, db)
  
  return db
}

/** 关闭指定目录的数据库 */
export function closeDatabase(dirPath?: string): void {
  if (dirPath) {
    dbCache.delete(dirPath)
    indexStatsCache.delete(dirPath)
  } else {
    dbCache.clear()
    indexStatsCache.clear()
  }
}

/** 检查索引是否存在且有效 */
export async function isIndexValid(dirPath: string, maxAge: number = 172800000): Promise<boolean> {
  try {
    const dbPath = getDbPath(dirPath)
    const exists = await FileManager.exists(dbPath)
    if (!exists) return false
    
    const database = await openDatabase(dirPath)
    
    // 检查元数据中的时间戳
    const result = await database.fetchOne<{ value: string }>(
      "SELECT value FROM metadata WHERE key = 'last_updated'"
    )
    
    if (!result?.value) return false
    
    const lastUpdated = parseInt(result.value)
    const now = Date.now()
    
    // 检查是否过期（默认48小时）
    return (now - lastUpdated) < maxAge
  } catch {
    return false
  }
}

/** 获取缓存的索引统计信息 */
export async function getIndexStats(dirPath: string): Promise<IndexStats> {
  // 检查内存缓存
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
    
    // 缓存统计信息
    indexStatsCache.set(dirPath, stats)
    
    return stats
  } catch {
    return { total: 0, lastUpdated: null, dirPath }
  }
}

/** 递归遍历目录并建立索引 */
let _activeIndexTask: { cancelled: boolean } | null = null

/** 取消当前正在进行的索引构建。 */
export function cancelBuildIndex(): void {
  if (_activeIndexTask) _activeIndexTask.cancelled = true
}

export async function buildIndex(
  dirPath: string,
  onProgress?: (count: number, currentPath: string) => void,
  forceRebuild: boolean = false
): Promise<number> {
  // 每次构建持有独立取消令牌；后启动的构建不会重置前一任务的取消状态。
  const task = { cancelled: false }
  _activeIndexTask = task
  // 如果索引有效且不强制重建，直接返回现有数量
  if (!forceRebuild && await isIndexValid(dirPath)) {
    const stats = await getIndexStats(dirPath)
    if (stats.total > 0) {
      console.log(`使用缓存索引: ${stats.total} 个文件`)
      if (_activeIndexTask === task) _activeIndexTask = null
      return stats.total
    }
  }
  
  const database = await openDatabase(dirPath)
  
  // 清除旧索引
  await database.execute('DELETE FROM files')
  
  let count = 0

  // 索引期间最大文件限制固定不变，只读一次 Storage 缓存（避免每个文件读两次设置）
  const maxIndexBytes = getMaxIndexFileSizeKB() * 1024

  // 批量提交：把最多 BATCH_SIZE 行拼成一条多行 INSERT（单条语句 = 一个隐式事务），
  // 比逐行 execute 少 N 倍事务开销。该 SQLite 封装不支持裸 BEGIN/COMMIT，
  // transaction() 也只收单步，因此用 execute 多行 VALUES 实现批量。
  const BATCH_SIZE = 80
  const INSERT_COLS = 'path, name, relative_path, size, modification_date, is_directory, category, icon, icon_color, parent_path, content'
  const INSERT_ROW = '(?,?,?,?,?,?,?,?,?,?,?)'
  let pendingRows: any[][] = []

  /** 把累积的行拼成一条多行 INSERT 提交；失败打标记并向上抛（终止索引，避免半截索引被标记为有效） */
  async function flushBatch(): Promise<void> {
    if (pendingRows.length === 0) return
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
    } catch (e) {
      const wrapped = e instanceof Error ? e : new Error(String(e))
      ;(wrapped as any).__batchFlushError = true
      throw wrapped
    }
  }

  /** 是否是可读取内容的文本文件 */
  function isTextLikeFile(cat: string): boolean {
    return cat === 'text' || cat === 'code' || cat === 'data'
  }

  /** 读取文本文件内容（在完整读取前限制字节大小）。 */
  async function readTextContent(filePath: string, maxBytes: number): Promise<string> {
    try {
      const text = await readTextFile(filePath, maxBytes)
      if (!text) return ''
      // 限制内容长度，避免数据库过大（最多 50KB）。
      return text.length > 51200 ? text.substring(0, 51200) : text
    } catch {
      return ''
    }
  }

  async function traverse(currentDir: string, relativePath: string): Promise<void> {
    try {
      const entries = await FileManager.readDirectory(currentDir)
      
      for (const entry of entries) {
        const fullPath = Path.join(currentDir, entry)
        const relPath = relativePath ? `${relativePath}/${entry}` : entry
        
        try {
          if (task.cancelled) break
          const info = await getFileInfo(fullPath)
          // 跳过超过最大文件限制的文件
          if (!info.isDirectory && info.size > maxIndexBytes) {
            continue
          }
          const ext = Path.extname(entry)
          const category = getFileCategory(ext)
          
          // 对文本类文件读取内容
          let content = ''
          if (!info.isDirectory && isTextLikeFile(category)) {
            content = await readTextContent(fullPath, maxIndexBytes)
          }
          
          // 累积行参数，满批后拼多行 INSERT 一次提交（避免逐行自动提交）
          pendingRows.push([
            fullPath,
            entry,
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
          onProgress?.(count, fullPath)
          if (pendingRows.length >= BATCH_SIZE) {
            await flushBatch()
          }

          if (info.isDirectory && !task.cancelled) {
            await traverse(fullPath, relPath)
          }
        } catch (e) {
          // 跳过无法访问的文件；批次提交失败必须终止整个索引，不能吞
          if (e && (e as any).__batchFlushError) throw e
        }
      }
    } catch (e) {
      if (e && (e as any).__batchFlushError) throw e
      console.log(`无法读取目录 ${currentDir}:`, e)
    }
  }
  
  try {
    await traverse(dirPath, '')

    // 剩余行最后统一提交；last_updated 只在全部文件写入后落库，
    // 中途失败也不会把半截索引误判为有效缓存（isIndexValid 只认 last_updated）。
    await flushBatch()
    await database.execute(
      "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_updated', ?)",
      [String(Date.now())]
    )
  } catch (e) {
    console.log('建立索引失败:', e)
    if (_activeIndexTask === task) _activeIndexTask = null
    throw e
  }
  
  // 更新缓存
  indexStatsCache.set(dirPath, {
    total: count,
    lastUpdated: Date.now(),
    dirPath
  })
  
  if (_activeIndexTask === task) _activeIndexTask = null
  return count
}

/** 从索引中搜索文件（搜索文件名和文件内容） */
export async function searchFromIndex(
  dirPath: string,
  query: string,
  limit: number = 100,
  offset: number = 0
): Promise<DeepSearchResult[]> {
  const database = await openDatabase(dirPath)
  
  if (!query.trim()) return []
  
  // 转义 SQLite LIKE 元字符（% _ \），避免搜索词中的这些字符被当作通配符
  // （例如搜 "_" 会匹配所有非空文件名，搜 "100%" 会误匹配）。
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

    // 从内容中收集所有匹配行
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

    // 如果文件名不匹配则用第一个内容匹配作为主匹配
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

/** 删除索引数据库 */
export async function deleteIndex(dirPath: string): Promise<void> {
  const dbPath = getDbPath(dirPath)
  if (await FileManager.exists(dbPath)) {
    await FileManager.remove(dbPath)
  }
  closeDatabase(dirPath)
}

/** 删除所有索引 */
export async function deleteAllIndexes(): Promise<void> {
  const dbDir = Path.join(FileManager.documentsDirectory, '.file_store', '.search-index')
  if (await FileManager.exists(dbDir)) {
    await FileManager.remove(dbDir)
  }
  closeDatabase()
}

/** 格式化索引时间 */
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
