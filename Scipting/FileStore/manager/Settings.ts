// 设置管理器 - 使用 Storage API 持久化

/** 高频设置 - 与 UI 渲染直接相关，变化频繁 */
export interface AppSettingsCore {
  /** 是否全屏显示 */
  isFullscreen: boolean
  /** 是否显示底部标签栏文字 */
  showTabLabels: boolean
  /** 默认标签页：0=首页, 1=挂载目录, 2=双栏浏览 */
  defaultTab: number
  /** 是否显示文件夹内项目个数 */
  showFolderItemCounts: boolean
  /** 默认排序方式 */
  defaultSortOrder: string
  /** 默认筛选类型 */
  defaultFilterType: string
  /** 是否独立显示退出按钮 */
  showExitButton: boolean
  /** 滑动时隐藏底部标签栏 */
  tabBarMinimizeOnScroll: boolean
}

/** 低频设置 - 导航路径、书签等，极少变更 */
export interface AppSettingsMeta {
  /** 首页显示的目录路径（书签名称） */
  homeDirectoryBookmarkName: string | null
  /** 首页文件列表的当前路径 */
  homeCurrentPath: string | null
  /** 双栏浏览 - 左侧当前目录 */
  dualLeftPath: string | null
  /** 双栏浏览 - 左侧当前书签名称 */
  dualLeftBookmarkName: string | null
  /** 双栏浏览 - 右侧当前目录 */
  dualRightPath: string | null
  /** 双栏浏览 - 右侧当前书签名称 */
  dualRightBookmarkName: string | null
  /** 双栏浏览 - 布局方向（左右分栏/上下分栏） */
  dualLayoutDir: 'horizontal' | 'vertical'
}

/** 完整设置（序列化用 + 向后兼容） */
export type AppSettings = AppSettingsCore & AppSettingsMeta

const SETTINGS_KEY = 'FileStore_Settings'
const SHARED_OPTIONS = { shared: true }

function getStorage(): any {
  return (globalThis as any).Storage
}

/** 默认设置 */
const defaultSettings: AppSettings = {
  isFullscreen: true,
  homeDirectoryBookmarkName: null,
  homeCurrentPath: null,
  showTabLabels: true,
  defaultTab: 0,
  showFolderItemCounts: true,
  defaultSortOrder: 'modified-asc',
  defaultFilterType: 'all',
  showExitButton: false,
  tabBarMinimizeOnScroll: true,
  dualLeftPath: null,
  dualLeftBookmarkName: null,
  dualRightPath: null,
  dualRightBookmarkName: null,
  dualLayoutDir: 'horizontal',
}

/** 读取设置 */
export function readSettings(): AppSettings {
  try {
    const st = getStorage()
    if (!st) return { ...defaultSettings }

    let raw: string | null = null
    try {
      raw = st.get?.(SETTINGS_KEY, SHARED_OPTIONS) ?? st.getString?.(SETTINGS_KEY, SHARED_OPTIONS)
    } catch {}
    if (raw == null) {
      try {
        raw = st.get?.(SETTINGS_KEY) ?? st.getString?.(SETTINGS_KEY)
      } catch {}
    }
    if (raw && typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw)
        if (parsed && typeof parsed === 'object') {
          const settings = { ...defaultSettings, ...parsed }
          // 校验 defaultTab 范围
          if (typeof settings.defaultTab !== 'number' || settings.defaultTab < 0 || settings.defaultTab > 3) {
            settings.defaultTab = 0
          }
          return settings
        }
      } catch {}
    }
  } catch (e) {
    console.log('读取设置失败:', e)
  }
  return { ...defaultSettings }
}

/** 保存设置 */
export function saveSettings(settings: AppSettings): void {
  const json = JSON.stringify(settings,null,2)
  const st = getStorage()
  try {
    if (typeof st?.set === 'function') {
      st.set(SETTINGS_KEY, json, SHARED_OPTIONS)
    } else {
      st?.setString?.(SETTINGS_KEY, json, SHARED_OPTIONS)
    }
  } catch {}
  try {
    if (typeof st?.set === 'function') {
      st.set(SETTINGS_KEY, json)
    } else {
      st?.setString?.(SETTINGS_KEY, json)
    }
  } catch {}
}
