// 扩展名 → 默认打开方式 持久化存储
// 使用 Storage API 存储

export type OpenerPrefix = 'editor:' | 'preview:' | 'image:' | 'video:' | 'livephoto:' | 'pdf:' | 'webpage:' | 'markdown:' | 'extract:' | 'extractfolder:' | 'share:'

// 所有可选的打开方式
export const OPENER_OPTIONS: { label: string; prefix: OpenerPrefix }[] = [
  { label: '代码编辑器', prefix: 'editor:' },
  { label: '文件预览', prefix: 'preview:' },
  { label: '图片查看器', prefix: 'image:' },
  { label: '视频播放器', prefix: 'video:' },
  { label: 'PDF 预览', prefix: 'pdf:' },
  { label: '网页预览', prefix: 'webpage:' },
  { label: 'Markdown 预览', prefix: 'markdown:' },
  { label: '解压文件', prefix: 'extract:' },
  { label: '解压到文件夹内', prefix: 'extractfolder:' },
  { label: '分享', prefix: 'share:' },
]

// 已有专用处理器的分类 → 不弹选择框
const KNOWN_CATEGORIES = new Set(['text', 'code', 'data', 'image', 'video', 'livephoto'])

export function isKnownCategory(category: string): boolean {
  return KNOWN_CATEGORIES.has(category)
}

const DEFAULTS_KEY = 'FileStore_ExtensionDefaults'
const SHARED_OPTIONS = { shared: true }

function getStorage(): any {
  return (globalThis as any).Storage
}

interface ExtensionDefaults {

  [ext: string]: OpenerPrefix
}

let _defaultsCache: ExtensionDefaults | null = null

function loadDefaults(): ExtensionDefaults {
  if (_defaultsCache) return _defaultsCache
  try {
    const st = getStorage()
    if (!st) return {}

    let raw: string | null = null
    try {
      raw = st.get?.(DEFAULTS_KEY, SHARED_OPTIONS) ?? st.getString?.(DEFAULTS_KEY, SHARED_OPTIONS)
    } catch {}
    if (raw == null) {
      try {
        raw = st.get?.(DEFAULTS_KEY) ?? st.getString?.(DEFAULTS_KEY)
      } catch {}
    }
    if (raw && typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw)
        if (parsed && typeof parsed === 'object') {
          _defaultsCache = parsed
          return parsed
        }
      } catch {}
    }
  } catch (e) {
    console.log('读取默认打开方式失败:', e)
  }
  _defaultsCache = {}
  return _defaultsCache
}

function saveDefaults(data: ExtensionDefaults): void {
  _defaultsCache = data
  const json = JSON.stringify(data, null, 2)
  const st = getStorage()
  try {
    if (typeof st?.set === 'function') {
      st.set(DEFAULTS_KEY, json, SHARED_OPTIONS)
    } else {
      st?.setString?.(DEFAULTS_KEY, json, SHARED_OPTIONS)
    }
  } catch {}
  try {
    if (typeof st?.set === 'function') {
      st.set(DEFAULTS_KEY, json)
    } else {
      st?.setString?.(DEFAULTS_KEY, json)
    }
  } catch {}
}

/** 获取某个扩展名的默认打开方式（存储的），null 表示未设置 */
export function getDefaultOpener(ext: string): OpenerPrefix | null {
  const data = loadDefaults()
  return data[ext.toLowerCase()] ?? null
}

/** 保存某个扩展名的默认打开方式 */
export function setDefaultOpener(ext: string, prefix: OpenerPrefix): void {
  const data = loadDefaults()
  data[ext.toLowerCase()] = prefix
  saveDefaults(data)
}
