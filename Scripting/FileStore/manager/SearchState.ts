// 全局搜索状态 - 用于跨组件通信（避免通过NavigationLink传递props导致白屏）

type SearchStateListener = (show: boolean) => void
type FocusRequestListener = () => void
type ScrollToFileListener = (path: string | null) => void

let _showSearch = false
let _listeners: SearchStateListener[] = []
let _focusListeners: FocusRequestListener[] = []

// 从深度搜索跳转到目录时，需要滚动到该文件
let _scrollToFilePath: string | null = null
let _scrollToFileListeners: ScrollToFileListener[] = []

/* ─── 深度搜索偏好：按目录自动开启 ─── */
// 内存缓存（即时生效）+ Storage 持久化
const DEEP_SEARCH_PREFS_KEY = 'FileStore_deepSearch'
const SHARED_OPTIONS = { shared: true }
let _deepSearchPrefsCache: Record<string, boolean> | null = null
function _ensurePrefs(): Record<string, boolean> {
  if (_deepSearchPrefsCache) return _deepSearchPrefsCache
  try {
    const st = (globalThis as any).Storage
    if (!st) { _deepSearchPrefsCache = {}; return {} }
    const raw: string | null = st.get?.(DEEP_SEARCH_PREFS_KEY, SHARED_OPTIONS) ?? st.getString?.(DEEP_SEARCH_PREFS_KEY, SHARED_OPTIONS)
    if (raw && typeof raw === 'string') { _deepSearchPrefsCache = JSON.parse(raw) as Record<string, boolean>; return _deepSearchPrefsCache }
  } catch {}
  try {
    const st = (globalThis as any).Storage
    if (!st) { _deepSearchPrefsCache = {}; return {} }
    const raw: string | null = st.get?.(DEEP_SEARCH_PREFS_KEY) ?? st.getString?.(DEEP_SEARCH_PREFS_KEY)
    if (raw && typeof raw === 'string') { _deepSearchPrefsCache = JSON.parse(raw) as Record<string, boolean>; return _deepSearchPrefsCache }
    _deepSearchPrefsCache = {}
  } catch { _deepSearchPrefsCache = {} }
  return _deepSearchPrefsCache ?? {}
}
function _flushPrefs(): void {
  try {
    const st = (globalThis as any).Storage
    if (!st || !_deepSearchPrefsCache) return
    const json = JSON.stringify(_deepSearchPrefsCache,null,2)
    if (typeof st.set === 'function') st.set(DEEP_SEARCH_PREFS_KEY, json, SHARED_OPTIONS)
    else st.setString?.(DEEP_SEARCH_PREFS_KEY, json, SHARED_OPTIONS)
  } catch {}
  try {
    const st = (globalThis as any).Storage
    if (!st || !_deepSearchPrefsCache) return
    const json = JSON.stringify(_deepSearchPrefsCache,null,2)
    if (typeof st.set === 'function') st.set(DEEP_SEARCH_PREFS_KEY, json)
    else st.setString?.(DEEP_SEARCH_PREFS_KEY, json)
  } catch {}
}
export function setDeepSearchPref(dirPath: string, enabled: boolean): void {
  const prefs = _ensurePrefs()
  prefs[dirPath] = enabled
  _flushPrefs()
}
export function getDeepSearchPref(dirPath: string): boolean {
  const prefs = _ensurePrefs()
  return prefs[dirPath] === true
}

export function getGlobalShowSearch(): boolean {
  return _showSearch
}

export function setGlobalShowSearch(show: boolean): void {
  _showSearch = show
  _listeners.forEach(fn => fn(show))
}

/**
 * 请求搜索输入框聚焦。
 * 当搜索按钮被点击时调用，用于将焦点设置到搜索输入框。
 */
export function requestSearchFocus(): void {
  _focusListeners.forEach(fn => fn())
}

/**
 * 订阅搜索聚焦请求。
 * 返回取消订阅函数。
 */
export function onSearchFocusRequest(listener: FocusRequestListener): () => void {
  _focusListeners.push(listener)
  return () => {
    _focusListeners = _focusListeners.filter(fn => fn !== listener)
  }
}

/**
 * 订阅搜索状态变化。
 * 不会立即调用 listener，请配合 getGlobalShowSearch() 初始化组件状态。
 */
export function onSearchStateChange(listener: SearchStateListener): () => void {
  _listeners.push(listener)
  return () => {
    _listeners = _listeners.filter(fn => fn !== listener)
  }
}

/* ─── 跳转到目录时滚动到文件 ─── */

export function requestScrollToFile(path: string): void {
  _scrollToFilePath = path
  _scrollToFileListeners.forEach(fn => fn(path))
}

export function consumeScrollToFile(): string | null {
  const path = _scrollToFilePath
  _scrollToFilePath = null
  return path
}

export function onScrollToFileRequest(listener: ScrollToFileListener): () => void {
  _scrollToFileListeners.push(listener)
  return () => {
    _scrollToFileListeners = _scrollToFileListeners.filter(fn => fn !== listener)
  }
}

/* ─── 深度搜索索引最大文件限制（KB） ─── */

const MAX_FILE_SIZE_KEY = 'FileStore_maxIndexFileSizeKB'

/** 获取最大文件限制（KB），默认 50 KB */
export function getMaxIndexFileSizeKB(): number {
  try {
    const st = (globalThis as any).Storage
    if (!st) return 50
    const raw: string | null = st.get?.(MAX_FILE_SIZE_KEY, SHARED_OPTIONS) ?? st.getString?.(MAX_FILE_SIZE_KEY, SHARED_OPTIONS)
    if (raw && typeof raw === 'string') {
      const val = parseInt(raw)
      if (!isNaN(val) && val > 0) return val
    }
  } catch {}
  try {
    const st = (globalThis as any).Storage
    if (!st) return 50
    const raw: string | null = st.get?.(MAX_FILE_SIZE_KEY) ?? st.getString?.(MAX_FILE_SIZE_KEY)
    if (raw && typeof raw === 'string') {
      const val = parseInt(raw)
      if (!isNaN(val) && val > 0) return val
    }
  } catch {}
  return 50
}

/** 设置最大文件限制（KB） */
export function setMaxIndexFileSizeKB(kb: number): void {
  try {
    const st = (globalThis as any).Storage
    if (!st) return
    const json = String(kb)
    if (typeof st.set === 'function') st.set(MAX_FILE_SIZE_KEY, json, SHARED_OPTIONS)
    else st.setString?.(MAX_FILE_SIZE_KEY, json, SHARED_OPTIONS)
  } catch {}
  try {
    const st = (globalThis as any).Storage
    if (!st) return
    const json = String(kb)
    if (typeof st.set === 'function') st.set(MAX_FILE_SIZE_KEY, json)
    else st.setString?.(MAX_FILE_SIZE_KEY, json)
  } catch {}
}
