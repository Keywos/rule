// 书签管理器 - 使用 Storage API 持久化
import { Path } from "scripting";
import { pathToDisplayName } from "./utils";

export interface Bookmark {
  name: string;
  path: string;
  /** 持久书签 ID（由 pickDirectoryBookmark 创建） */
  bookmarkId: string;
}

const BOOKMARKS_KEY = "FileStore_Bookmarks";
const SHARED_OPTIONS = { shared: true };

function getStorage(): any {
  return (globalThis as any).Storage;
}

/** 解析 Storage 值（兼容对象 / JSON 字符串） */
function parseStoredBookmarks(raw: unknown): Bookmark[] | null {
  if (raw == null) return null;
  if (Array.isArray(raw)) return raw as Bookmark[];
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed as Bookmark[];
    } catch {}
  }
  return null;
}

/** 读取书签列表（优先 shared 域，兼容旧 JSON 字符串） */
function readBookmarks(): Bookmark[] {
  try {
    const st = getStorage();
    if (!st) return [];

    let raw: unknown = null;
    try {
      raw = st.get?.(BOOKMARKS_KEY, SHARED_OPTIONS);
    } catch {}
    if (raw == null) {
      try {
        raw = st.get?.(BOOKMARKS_KEY);
      } catch {}
    }
    // 兼容旧 setString API
    if (raw == null) {
      try {
        raw = st.getString?.(BOOKMARKS_KEY, SHARED_OPTIONS) ?? st.getString?.(BOOKMARKS_KEY);
      } catch {}
    }

    const parsed = parseStoredBookmarks(raw);
    // console.log("读取书签列表:", parsed);
    if (parsed) return parsed;
  } catch (e) {
    console.log("读取书签失败:", e);
  }
  return [];
}

/** 保存书签列表（直接存 JSON 对象，符合 Storage 支持的类型） */
function saveBookmarks(bookmarks: Bookmark[]): void {
  const st = getStorage();
  try {
    st?.set?.(BOOKMARKS_KEY, bookmarks, SHARED_OPTIONS);
  } catch {}
  try {
    st?.set?.(BOOKMARKS_KEY, bookmarks);
  } catch {}
}

/** 获取所有书签 */
export function getAllBookmarks(): Bookmark[] {
  return readBookmarks();
}

/** 通过持久书签 ID 重新获取可访问的路径 */
export function resolveBookmarkPath(bookmarkId: string): string | null {
  try {
    return FileManager.bookmarkedPath(bookmarkId);
  } catch (e) {
    console.log("解析书签路径失败:", e);
    return null;
  }
}

/** 手动添加书签（路径 + 显示名称，不使用系统持久书签） */
export function addBookmarkManually(path: string, displayName: string): Bookmark | null {
  try {
    const trimmedPath = path.trim();
    const trimmedName = displayName.trim();
    if (!trimmedPath || !trimmedName) return null;

    const bookmarks = readBookmarks();

    // 检查是否已挂载相同路径
    if (bookmarks.some((b) => b.path === trimmedPath)) {
      return bookmarks.find((b) => b.path === trimmedPath) ?? null;
    }

    // 检查名称重复
    let finalName = trimmedName;
    let counter = 2;
    while (bookmarks.some((b) => b.name === finalName)) {
      finalName = `${trimmedName} (${counter})`;
      counter++;
    }

    const bookmark: Bookmark = { name: finalName, path: trimmedPath, bookmarkId: "" };
    bookmarks.push(bookmark);
    saveBookmarks(bookmarks);
    return bookmark;
  } catch (e) {
    console.log("添加书签失败:", e);
    return null;
  }
}

/** 添加目录书签（使用持久安全域书签） */
export async function addDirectoryBookmark(): Promise<Bookmark | null> {
  try {
    // 使用唯一的 preferredName，避免系统弹出"已存在同名书签"提示
    const uniqueName = `FSKEY_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const result = await DocumentPicker.pickDirectoryBookmark({ preferredName: uniqueName });
    if (result) {
      const { path: pickedPath, bookmarkName } = result;
      const bookmarks = readBookmarks();

      // 检查是否已挂载相同路径
      const existingIndex = bookmarks.findIndex((b) => b.path === pickedPath);
      if (existingIndex >= 0) {
        return bookmarks[existingIndex];
      }

      // 生成显示名称，处理重复名称
      let displayName = pathToDisplayName(pickedPath);
      let counter = 2;
      while (bookmarks.some((b) => b.name === displayName)) {
        displayName = `${pathToDisplayName(pickedPath)} (${counter})`;
        counter++;
      }

      const bookmark: Bookmark = { name: displayName, path: pickedPath, bookmarkId: bookmarkName };
      bookmarks.push(bookmark);
      saveBookmarks(bookmarks);
      return bookmark;
    }
    return null;
  } catch (e) {
    console.log("添加目录书签失败:", e);
    return null;
  }
}

/** 通过名称删除书签 */
export function removeBookmark(name: string): boolean {
  try {
    const bookmarks = readBookmarks();
    const filtered = bookmarks.filter((b) => b.name !== name);
    if (filtered.length < bookmarks.length) {
      saveBookmarks(filtered);
      return true;
    }
    return false;
  } catch (e) {
    console.log("删除书签失败:", e);
    return false;
  }
}

/** 通过 bookmarkId 删除书签（更可靠）。
 *  手动书签的 bookmarkId 为空字符串，直接用它过滤会匹配并删除所有手动书签。
 *  因此当 bookmarkId 为空时，改用唯一路径定位要删除的书签。 */
export function removeBookmarkById(bookmarkId: string, path?: string): boolean {
  try {
    const bookmarks = readBookmarks();
    // bookmarkId 非空：按 id 删除（目录书签）；为空：按 path 删除（手动书签）。
    const filtered = bookmarkId
      ? bookmarks.filter((b) => b.bookmarkId !== bookmarkId)
      : path
        ? bookmarks.filter((b) => b.path !== path)
        : bookmarks;
    if (filtered.length < bookmarks.length) {
      saveBookmarks(filtered);
      return true;
    }
    return false;
  } catch (e) {
    console.log("通过 ID 删除书签失败:", e);
    return false;
  }
}

/** 检查书签是否存在 */
export function bookmarkExists(name: string): boolean {
  const bookmarks = readBookmarks();
  return bookmarks.some((b) => b.name === name);
}

/** 重命名书签 */
export function renameBookmark(oldName: string, newName: string): boolean {
  try {
    const bookmarks = readBookmarks();
    const idx = bookmarks.findIndex((b) => b.name === oldName);
    if (idx >= 0) {
      bookmarks[idx] = { ...bookmarks[idx], name: newName };
      saveBookmarks(bookmarks);
      return true;
    }
    return false;
  } catch (e) {
    console.log("重命名书签失败:", e);
    return false;
  }
}

/** 获取书签路径（优先用持久书签解析） */
export function getBookmarkPath(name: string): string | null {
  const bookmarks = readBookmarks();
  const bookmark = bookmarks.find((b) => b.name === name);
  if (!bookmark) return null;
  // 如果有持久书签 ID，用它重新解析路径
  if (bookmark.bookmarkId) {
    const resolved = resolveBookmarkPath(bookmark.bookmarkId);
    if (resolved) return resolved;
  }
  // 回退到保存的路径
  return bookmark.path;
}

/** 获取内置目录列表（对齐 Scripting FileManager 官方路径 API） */
export interface BuiltinDirectory {
  name: string;
  path: string;
  icon: string;
  description: string;
}

function pushBuiltin(dirs: BuiltinDirectory[], name: string, getPath: () => string, icon: string, description: string, available: () => boolean = () => true) {
  try {
    if (!available()) return;
    const path = getPath();
    if (!path) return;
    dirs.push({ name, path, icon, description });
  } catch {}
}

export function getBuiltinDirectories(): BuiltinDirectory[] {
  const dirs: BuiltinDirectory[] = [];
  pushBuiltin(dirs, "File Store", () => Path.join(FileManager.documentsDirectory, "File Store"), "folder.fill", "默认文件仓库");
  pushBuiltin(dirs, "脚本", () => FileManager.scriptsDirectory, "chevron.left.forwardslash.chevron.right", "脚本存储位置");
  pushBuiltin(
    dirs,
    "iCloud 文档",
    () => FileManager.iCloudDocumentsDirectory,
    "icloud.fill",
    "iCloud Drive Documents",
    () => !!FileManager.isiCloudEnabled,
  );
  pushBuiltin(dirs, "App Group", () => FileManager.appGroupDocumentsDirectory, "square.grid.2x2.fill", "小组件可访问");
  pushBuiltin(dirs, "临时", () => FileManager.temporaryDirectory, "clock.fill", "系统临时目录，可被清理");
  pushBuiltin(dirs, "Safari 扩展", () => FileManager.safariBrowserDirectory, "safari", "Safari 用户脚本数据根目录");
  pushBuiltin(dirs, "Safari 下载", () => FileManager.safariBrowserDownloadsDirectory, "arrow.down.circle.fill", "GM.download 下载目录");
  pushBuiltin(dirs, "Safari 脚本", () => FileManager.safariBrowserUserscriptsDirectory, "doc.badge.gearshape", "已安装的 userscripts");
  pushBuiltin(dirs, "Safari 存储", () => FileManager.safariBrowserStorageDirectory, "internaldrive", "GM 值 JSON 存储");

  return dirs;
}

/** 重新排序书签（传入新的顺序数组） */
export function reorderBookmarks(reordered: Bookmark[]): boolean {
  try {
    saveBookmarks(reordered);
    return true;
  } catch (e) {
    console.log("重新排序书签失败:", e);
    return false;
  }
}
