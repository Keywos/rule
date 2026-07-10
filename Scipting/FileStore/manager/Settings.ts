// 设置管理器 - 使用 Storage API 持久化

export interface AppSettingsCore {
  /** 是否显示底部标签栏文字 */
  showTabLabels: boolean;
  /** 默认标签页：0=首页, 1=挂载目录, 2=双栏浏览 */
  defaultTab: number;
  /** 是否显示文件夹内项目个数 */
  showFolderItemCounts: boolean;
  /** 默认排序方式 */
  defaultSortOrder: string;
  /** 默认筛选类型 */
  defaultFilterType: string;
  /** 是否独立显示退出按钮 */
  showExitButton: boolean;
  /** 滑动时隐藏底部标签栏 */
  tabBarMinimizeOnScroll: boolean;
}

export interface AppSettingsMeta {
  /** 首页显示的目录路径（书签名称） */
  homeDirectoryBookmarkName: string | null;
  /** 首页文件列表的当前路径 */
  homeCurrentPath: string | null;
  /** 双栏浏览 - 左侧当前目录 */
  dualLeftPath: string | null;
  /** 双栏浏览 - 左侧当前书签名称 */
  dualLeftBookmarkName: string | null;
  /** 双栏浏览 - 右侧当前目录 */
  dualRightPath: string | null;
  /** 双栏浏览 - 右侧当前书签名称 */
  dualRightBookmarkName: string | null;
  /** 双栏浏览 - 布局方向（左右分栏/上下分栏） */
  dualLayoutDir: "horizontal" | "vertical";
}

/** 完整设置（序列化用 + 向后兼容） */
export type AppSettings = AppSettingsCore & AppSettingsMeta;

const SETTINGS_KEY = "FileStore_Settings";
const SHARED_OPTIONS = { shared: true };

function getStorage(): any {
  return (globalThis as any).Storage;
}

/** 默认设置 */
const defaultSettings: AppSettings = {
  homeDirectoryBookmarkName: null,
  homeCurrentPath: null,
  showTabLabels: true,
  defaultTab: 0,
  showFolderItemCounts: true,
  defaultSortOrder: "modified-asc",
  defaultFilterType: "all",
  showExitButton: false,
  tabBarMinimizeOnScroll: true,
  dualLeftPath: null,
  dualLeftBookmarkName: null,
  dualRightPath: null,
  dualRightBookmarkName: null,
  dualLayoutDir: "horizontal",
};

function normalizeSettings(raw: unknown): AppSettings | null {
  let obj: any = raw;
  if (typeof raw === "string") {
    try {
      obj = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!obj || typeof obj !== "object") return null;

  const settings = { ...defaultSettings, ...obj };
  if (typeof settings.defaultTab !== "number" || settings.defaultTab < 0 || settings.defaultTab > 3) {
    settings.defaultTab = 0;
  }
  return settings;
}

/** 读取设置（兼容对象 / JSON 字符串、shared / private 域） */
export function readSettings(): AppSettings {
  try {
    const st = getStorage();
    if (!st) return { ...defaultSettings };

    let raw: unknown = null;
    try {
      raw = st.get?.(SETTINGS_KEY, SHARED_OPTIONS);
    } catch {}
    if (raw == null) {
      try {
        raw = st.get?.(SETTINGS_KEY);
      } catch {}
    }
    if (raw == null) {
      try {
        raw = st.getString?.(SETTINGS_KEY, SHARED_OPTIONS) ?? st.getString?.(SETTINGS_KEY);
      } catch {}
    }

    const settings = normalizeSettings(raw);
    if (settings) return settings;
  } catch (e) {
    console.log("读取设置失败:", e);
  }
  return { ...defaultSettings };
}

/** 保存设置（直接存对象，符合 Storage 支持的 JSON 类型） */
export function saveSettings(settings: AppSettings): void {
  const st = getStorage();
  try {
    st?.set?.(SETTINGS_KEY, settings, SHARED_OPTIONS);
  } catch {}
  try {
    st?.set?.(SETTINGS_KEY, settings);
  } catch {}
}
