// 书签管理器 - 使用 Storage API 持久化
import { pathToDisplayName } from './utils'

export interface Bookmark {
  name: string
  path: string
  /** 持久书签 ID（由 pickDirectoryBookmark 创建） */
  bookmarkId: string
}

const BOOKMARKS_KEY = 'FileStore_Bookmarks'
const SHARED_OPTIONS = { shared: true }

function getStorage(): any {
  return (globalThis as any).Storage
}

/** 读取书签列表 */
function readBookmarks(): Bookmark[] {
  try {
    const st = getStorage()
    if (!st) return []

    let raw: string | null = null
    try {
      raw = st.get?.(BOOKMARKS_KEY, SHARED_OPTIONS) ?? st.getString?.(BOOKMARKS_KEY, SHARED_OPTIONS)
    } catch {}
    if (raw == null) {
      try {
        raw = st.get?.(BOOKMARKS_KEY) ?? st.getString?.(BOOKMARKS_KEY)
      } catch {}
    }
    if (raw && typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw)
        if (Array.isArray(parsed)) return parsed
      } catch {}
    }
  } catch (e) {
    console.log('读取书签失败:', e)
  }
  return []
}

/** 保存书签列表 */
function saveBookmarks(bookmarks: Bookmark[]): void {
  
  const json = JSON.stringify(bookmarks,null,2)
  const st = getStorage()
  try {
    if (typeof st?.set === 'function') {
      st.set(BOOKMARKS_KEY, json, SHARED_OPTIONS)
    } else {
      st?.setString?.(BOOKMARKS_KEY, json, SHARED_OPTIONS)
    }
  } catch {}
  try {
    if (typeof st?.set === 'function') {
      st.set(BOOKMARKS_KEY, json)
    } else {
      st?.setString?.(BOOKMARKS_KEY, json)
    }
  } catch {}
}

/** 获取所有书签 */
export function getAllBookmarks(): Bookmark[] {
  return readBookmarks()
}

/** 通过持久书签 ID 重新获取可访问的路径 */
export function resolveBookmarkPath(bookmarkId: string): string | null {
  try {
    return FileManager.bookmarkedPath(bookmarkId)
  } catch (e) {
    console.log('解析书签路径失败:', e)
    return null
  }
}

/** 手动添加书签（路径 + 显示名称，不使用系统持久书签） */
export function addBookmarkManually(path: string, displayName: string): Bookmark | null {
  try {
    const trimmedPath = path.trim()
    const trimmedName = displayName.trim()
    if (!trimmedPath || !trimmedName) return null
    
    const bookmarks = readBookmarks()
    
    // 检查是否已挂载相同路径
    if (bookmarks.some(b => b.path === trimmedPath)) {
      return bookmarks.find(b => b.path === trimmedPath) ?? null
    }
    
    // 检查名称重复
    let finalName = trimmedName
    let counter = 2
    while (bookmarks.some(b => b.name === finalName)) {
      finalName = `${trimmedName} (${counter})`
      counter++
    }
    
    const bookmark: Bookmark = { name: finalName, path: trimmedPath, bookmarkId: '' }
    bookmarks.push(bookmark)
    saveBookmarks(bookmarks)
    return bookmark
  } catch (e) {
    console.log('添加书签失败:', e)
    return null
  }
}

/** 添加目录书签（使用持久安全域书签） */
export async function addDirectoryBookmark(): Promise<Bookmark | null> {
  try {
    // 使用唯一的 preferredName，避免系统弹出"已存在同名书签"提示
    const uniqueName = `FSKEY_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
    const result = await DocumentPicker.pickDirectoryBookmark({ preferredName: uniqueName })
    if (result) {
      const { path: pickedPath, bookmarkName } = result
      const bookmarks = readBookmarks()
      
      // 检查是否已挂载相同路径
      const existingIndex = bookmarks.findIndex(b => b.path === pickedPath)
      if (existingIndex >= 0) {
        return bookmarks[existingIndex]
      }
      
      // 生成显示名称，处理重复名称
      let displayName = pathToDisplayName(pickedPath)
      let counter = 2
      while (bookmarks.some(b => b.name === displayName)) {
        displayName = `${pathToDisplayName(pickedPath)} (${counter})`
        counter++
      }
      
      const bookmark: Bookmark = { name: displayName, path: pickedPath, bookmarkId: bookmarkName }
      bookmarks.push(bookmark)
      saveBookmarks(bookmarks)
      return bookmark
    }
    return null
  } catch (e) {
    console.log('添加目录书签失败:', e)
    return null
  }
}

/** 通过名称删除书签 */
export function removeBookmark(name: string): boolean {
  try {
    const bookmarks = readBookmarks()
    const filtered = bookmarks.filter(b => b.name !== name)
    if (filtered.length < bookmarks.length) {
      saveBookmarks(filtered)
      return true
    }
    return false
  } catch (e) {
    console.log('删除书签失败:', e)
    return false
  }
}

/** 通过 bookmarkId 删除书签（更可靠） */
export function removeBookmarkById(bookmarkId: string): boolean {
  try {
    const bookmarks = readBookmarks()
    const filtered = bookmarks.filter(b => b.bookmarkId !== bookmarkId)
    if (filtered.length < bookmarks.length) {
      saveBookmarks(filtered)
      return true
    }
    return false
  } catch (e) {
    console.log('通过 ID 删除书签失败:', e)
    return false
  }
}

/** 检查书签是否存在 */
export function bookmarkExists(name: string): boolean {
  const bookmarks = readBookmarks()
  return bookmarks.some(b => b.name === name)
}

/** 重命名书签 */
export function renameBookmark(oldName: string, newName: string): boolean {
  try {
    const bookmarks = readBookmarks()
    const idx = bookmarks.findIndex(b => b.name === oldName)
    if (idx >= 0) {
      bookmarks[idx] = { ...bookmarks[idx], name: newName }
      saveBookmarks(bookmarks)
      return true
    }
    return false
  } catch (e) {
    console.log('重命名书签失败:', e)
    return false
  }
}

/** 获取书签路径（优先用持久书签解析） */
export function getBookmarkPath(name: string): string | null {
  const bookmarks = readBookmarks()
  const bookmark = bookmarks.find(b => b.name === name)
  if (!bookmark) return null
  // 如果有持久书签 ID，用它重新解析路径
  if (bookmark.bookmarkId) {
    const resolved = resolveBookmarkPath(bookmark.bookmarkId)
    if (resolved) return resolved
  }
  // 回退到保存的路径
  return bookmark.path
}

/** 获取内置目录列表 */
export interface BuiltinDirectory {
  name: string
  path: string
  icon: string
  description: string
}

export function getBuiltinDirectories(): BuiltinDirectory[] {
  const dirs: BuiltinDirectory[] = []
  
  // 文档目录
  try {
    dirs.push({
      name: '文档',
      path: FileManager.documentsDirectory,
      icon: 'doc.text.fill',
      description: 'Files app 可访问',
    })
  } catch {}
  
  // 脚本目录
  try {
    dirs.push({
      name: '脚本',
      path: FileManager.scriptsDirectory,
      icon: 'chevron.left.forwardslash.chevron.right',
      description: '脚本存储位置',
    })
  } catch {}
  
  // App Group 目录
  try {
    dirs.push({
      name: 'App Group',
      path: FileManager.appGroupDocumentsDirectory,
      icon: 'square.grid.2x2.fill',
      description: '小组件可访问',
    })
  } catch {}
  
  // 临时目录
  try {
    dirs.push({
      name: '临时',
      path: FileManager.temporaryDirectory,
      icon: 'clock.fill',
      description: '可随时清理',
    })
  } catch {}
  
  return dirs
}

/** 重新排序书签（传入新的顺序数组） */
export function reorderBookmarks(reordered: Bookmark[]): boolean {
  try {
    saveBookmarks(reordered)
    return true
  } catch (e) {
    console.log('重新排序书签失败:', e)
    return false
  }
}
