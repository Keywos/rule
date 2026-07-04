// 通用排序筛选 — 类型、配置、工具函数

import { FileInfo } from './utils'
import { isLivePhotoFile } from './LivePhotoPacker'
import { Bookmark } from './BookmarkManager'

/* ─── 类型 ─── */

export type SortOrder = 'modified-asc' | 'modified-desc' | 'added-asc' | 'added-desc' | 'type-asc'

export interface SortOption {
  key: SortOrder
  title: string
}

export interface FilterOption {
  key: string
  title: string
  systemImage: string
}

/* ─── 排序切换组 ─── */

export interface SortToggleDef {
  /** 'modified' | 'added' | 'type' */
  key: string
  title: string
  systemImage: string
  /** true = 可切换 最新/最旧 */
  togglable: boolean
}

export const FILE_SORT_TOGGLES: SortToggleDef[] = [
  { key: 'modified', title: '修改日期', systemImage: 'calendar.badge.clock', togglable: true },
  { key: 'added', title: '添加日期', systemImage: 'calendar.badge.plus', togglable: true },
  { key: 'type', title: '按文件类型排序', systemImage: 'doc.text.magnifyingglass', togglable: false },
]

/** 默认排序：修改日期 ↑ */
export const DEFAULT_SORT_ORDER: SortOrder = 'modified-asc'

/* ─── 文件筛选选项（单选） ─── */

export const FILE_FILTER_OPTIONS: FilterOption[] = [
  { key: 'all', title: '全部', systemImage: 'tray.full' },
  { key: 'image', title: '图片', systemImage: 'photo' },
  { key: 'livePhoto', title: '实况', systemImage: 'livephoto' },
  { key: 'video', title: '视频', systemImage: 'video' },
  { key: 'document', title: '文档', systemImage: 'doc.text' },
  { key: 'folder', title: '文件夹', systemImage: 'folder' },
]

/** 默认筛选：全部 */
export const DEFAULT_FILTER_TYPE = 'all'

/* ─── 目录排序/筛选选项 ─── */

export const BOOKMARK_SORT_OPTIONS = [
  { key: 'name', title: '按名称排序', systemImage: 'textformat' },
]

/* ─── 排序工具函数 ─── */

/** 获取方向箭头 */
export function getSortArrow(order: SortOrder, toggleKey: string): string {
  return ''
}

/** 将 SortOrder 转为 utils.sortFiles 所需的 (mode, order) */
export function sortOrderToMode(order: SortOrder): { mode: string; dir: 'asc' | 'desc' } {
  const [mode, dir] = order.split('-') as [string, 'asc' | 'desc']
  return { mode, dir }
}

/** 根据选择的 toggle key 生成新的 SortOrder */
export function resolveSortOrder(current: SortOrder, toggleKey: string): SortOrder {
  if (toggleKey === 'type') return 'type-asc'
  const prefix = toggleKey
  if (current.startsWith(prefix)) {
    // 同组切换方向
    return current === `${prefix}-asc` ? `${prefix}-desc` as SortOrder : `${prefix}-asc` as SortOrder
  }
  // 不同组切过去，默认 asc
  return `${prefix}-asc` as SortOrder
}

/** 对文件列表排序 */
export function sortFilesByOrder(files: FileInfo[], order: SortOrder): FileInfo[] {
  if (files.length < 2) return files
  // useMemo 确保返回新引用，slice 避免变异输入
  const sorted = files.slice(0)
  sorted.sort((a, b) => {
    switch (order) {
      case 'modified-asc':
        return a.modificationDate - b.modificationDate
      case 'modified-desc':
        return b.modificationDate - a.modificationDate
      case 'added-asc':
        return a.creationDate - b.creationDate
      case 'added-desc':
        return b.creationDate - a.creationDate
      case 'type-asc':
        const catCmp = a.category.localeCompare(b.category)
        return catCmp !== 0 ? catCmp : a.name.localeCompare(b.name, 'zh-CN', { numeric: true })
      default:
        return 0
    }
  })
  return sorted
}

/** 对文件列表筛选 */
export function filterFiles(files: FileInfo[], type: string): FileInfo[] {
  if (type === 'all' || !type) return files
  return files.filter(f => {
    const cat = f.category
    switch (type) {
      case 'folder':
        return f.isDirectory
      case 'livePhoto':
        return isLivePhotoFile(f.name)
      case 'image':
        return cat === 'image' && !isLivePhotoFile(f.name)
      case 'video':
        return cat === 'video'
      case 'document':
        return cat === 'text' || cat === 'code' || cat === 'pdf' || cat === 'data' || cat === 'archive'
      default:
        return true
    }
  })
}

/** 对书签列表排序 */
export function sortBookmarks(bookmarks: Bookmark[], order: string): Bookmark[] {
  const sorted = [...bookmarks]
  sorted.sort((a, b) => {
    if (order === 'name-desc') {
      return b.name.localeCompare(a.name)
    }
    return a.name.localeCompare(b.name)
  })
  return sorted
}
