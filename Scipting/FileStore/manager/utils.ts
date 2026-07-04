// 文件管理器工具函数
import { Path } from "scripting";

/** 将路径转换为友好的显示名称 */
export function pathToDisplayName(filePath: string): string {
  let p = filePath.replace(/^file:\/\//, "");

  const rules: Array<[RegExp, string]> = [
    [
      /^\/private\/var\/mobile\/Containers\/Shared\/AppGroup\/[^/]+\/File Provider Storage\/?/,
      "iPhone/",
    ],
    [
      /^(\/private)?\/var\/mobile\/Library\/Mobile Documents\/(?:com~apple~CloudDocs|iCloud~com~[^/]+)?\/?/,
      "iCloud/",
    ],
    [
      /^\/private\/var\/mobile\/Containers\/Data\/Application\/[^/]+\/Documents\/?/,
      "Documents/",
    ],
    [
      /^\/private\/var\/mobile\/Containers\/Shared\/AppGroup\/[^/]+\/?/,
      "AppGroup/",
    ],
  ];

  
  for (const [regex, replacement] of rules) {
    if (regex.test(p)) {
      p = p.replace(regex, replacement);
      break; // 只会匹配一种，匹配后结束
    }
  }

  return p.replace(/\/$/, "");
}
/** 复制文本到剪贴板并弹出简短提示（无需确认） */
export async function copyAndToast(text: string, label?: string): Promise<void> {
  await Pasteboard.setString(text);
  // 返回提示信息，调用方可用 toast 展示
  return;
}

/** 获取复制成功的 toast 消息，截取前几个字符 */
export function copiedMessage(text: string): string {
  const preview = text.length > 20 ? text.slice(0, 20) + ".." : text;
  return `已复制 ${preview}`;
}

/** 格式化文件大小 */
export function fmtSize(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(2)} GB`;
}

/** 格式化日期 */
export function fmtDate(ts: number): string {
  const d = new Date(ts > 1e12 ? ts : ts * 1000);
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");

  if (d.toDateString() === now.toDateString()) {
    return `今天 ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) {
    return `昨天 ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  if (d.getFullYear() === now.getFullYear()) {
    return `${d.getMonth() + 1}月${d.getDate()}日`;
  }

  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())}`;
}

/** 文件类型分类 */
export type FileCategory = "text" | "code" | "image" | "pdf" | "audio" | "video" | "archive" | "data" | "unknown" | "livephoto";

/** 获取文件类型分类 */
export function getFileCategory(ext: string): FileCategory {
  const e = ext.toLowerCase();

  const textExts = [".txt", ".md", ".rtf", ".csv", ".log", ".ini", ".conf", ".cfg"];
  if (textExts.includes(e)) return "text";

  const codeExts = [
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".py",
    ".swift",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".html",
    ".conf",
    ".dconf",
    ".htm",
    ".css",
    ".scss",
    ".less",
    ".sh",
    ".bash",
    ".sql",
    ".java",
    ".kt",
    ".c",
    ".cpp",
    ".h",
    ".m",
    ".mm",
    ".rb",
    ".go",
    ".rs",
    ".php",
    ".lua",
    ".r",
    ".vue",
    ".svelte",
    ".toml",
    ".env",
    ".gitignore",
    ".dockerfile",
    ".makefile",
  ];
  if (codeExts.includes(e)) return "code";

  if (e === ".live") return "livephoto";

  const imageExts = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".svg", ".webp", ".heic", ".heif", ".ico", ".icns", ".dng", ".raw", ".cr2", ".cr3", ".nef", ".arw", ".orf", ".rw2", ".raf", ".pef", ".srw"];
  if (imageExts.includes(e)) return "image";

  if (e === ".pdf") return "pdf";

  const audioExts = [".mp3", ".m4a", ".wav", ".aac", ".flac", ".ogg", ".wma", ".aiff"];
  if (audioExts.includes(e)) return "audio";

  const videoExts = [".mp4", ".mov", ".m4v", ".avi", ".mkv", ".wmv", ".flv", ".webm"];
  if (videoExts.includes(e)) return "video";

  const archiveExts = [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"];
  if (archiveExts.includes(e)) return "archive";

  const dataExts = [".plist", ".db", ".sqlite", ".sqlite3"];
  if (dataExts.includes(e)) return "data";

  return "unknown";
}

/** 获取文件图标 */
export function getFileIcon(ext: string, isDirectory: boolean): string {
  if (isDirectory) return "folder.fill";

  const e = ext.toLowerCase();
  if (e === ".live") return "livephoto";
  const cat = getFileCategory(e);

  switch (cat) {
    case "text":
      if (e === ".md") return "doc.text";
      if (e === ".csv") return "tablecells";
      if (e === ".rtf") return "doc.richtext";
      if (e === ".log") return "doc.text";
      return "doc.plaintext";
    case "code":
      if (e === ".json") return "curlybraces";
      if (e === ".html" || e === ".htm") return "globe";
      if (e === ".css" || e === ".scss" || e === ".less") return "paintbrush.fill";
      if (e === ".sh" || e === ".bash") return "terminal";
      if (e === ".sql") return "cylinder";
      if (e === ".py") return "text.word.spacing";
      if (e === ".swift") return "bird.fill";
      return "chevron.left.forwardslash.chevron.right";
    case "image":
      if (e === ".svg") return "photo.on.rectangle";
      if (".dng.raw.cr2.cr3.nef.arw".includes(e)) return "camera.aperture";
      return "photo";
    case "pdf":
      return "doc.richtext";
    case "audio":
      return "waveform";
    case "video":
      return "film";
    case "archive":
      return "archivebox";
    case "data":
      if (e === ".plist") return "list.clipboard";
      return "externaldrive";
    case "livephoto":
      return "livephoto";
    default:
      return "doc";
  }
}

/** 获取文件图标颜色 */
export function getFileIconColor(ext: string, isDirectory: boolean): FileInfo["iconColor"] {
  if (isDirectory) return "systemBlue";

  if (ext.toLowerCase() === ".live") return "systemPink";
  const cat = getFileCategory(ext);
  switch (cat) {
    case "text":
      return "systemGray";
    case "code":
      return "systemOrange";
    case "image":
      return "systemGreen";
    case "pdf":
      return "systemRed";
    case "audio":
      return "systemPurple";
    case "video":
      return "systemPink";
    case "archive":
      return "systemIndigo";
    case "data":
      return "systemTeal";
    default:
      return "systemGray";
  }
}

/** 语言映射 */
export const langMap: Record<string, string> = {
  ".json": "JSON",
  ".js": "JavaScript",
  ".ts": "TypeScript",
  ".tsx": "TypeScript (React)",
  ".jsx": "JavaScript (React)",
  ".md": "Markdown",
  ".txt": "纯文本",
  ".html": "HTML",
  ".conf": "配置文件",
  ".dcong": "配置文件",
  ".htm": "HTML",
  ".css": "CSS",
  ".scss": "SCSS",
  ".py": "Python",
  ".swift": "Swift",
  ".csv": "CSV",
  ".log": "日志",
  ".xml": "XML",
  ".yaml": "YAML",
  ".yml": "YAML",
  ".sh": "Shell",
  ".bash": "Bash",
  ".sql": "SQL",
  ".rtf": "富文本",
  ".pdf": "PDF",
  ".java": "Java",
  ".kt": "Kotlin",
  ".c": "C",
  ".cpp": "C++",
  ".rb": "Ruby",
  ".go": "Go",
  ".rs": "Rust",
  ".php": "PHP",
  ".lua": "Lua",
  ".r": "R",
  ".toml": "TOML",
};

/** MIME 类型映射（用于导出） */
export function getMimeType(ext: string): string {
  const e = ext.toLowerCase();
  const mimeMap: Record<string, string> = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".ts": "text/typescript",
    ".json": "application/json",
    ".xml": "application/xml",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".wav": "audio/wav",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".zip": "application/zip",
    ".csv": "text/csv",
    ".rtf": "application/rtf",
  };
  return mimeMap[e] || "application/octet-stream";
}

/** 文件信息接口 */
export interface FileInfo {
  name: string;
  path: string;
  isDirectory: boolean;
  isLink: boolean;
  size: number;
  creationDate: number;
  modificationDate: number;
  extension: string;
  category: FileCategory;
  mimeType: string;
  icon: string;
  iconColor:
    | "systemRed"
    | "systemGreen"
    | "systemBlue"
    | "systemOrange"
    | "systemYellow"
    | "systemPink"
    | "systemPurple"
    | "systemTeal"
    | "systemIndigo"
    | "systemBrown"
    | "systemMint"
    | "systemCyan"
    | "systemGray"
    | "systemGray2"
    | "systemGray3"
    | "systemGray4"
    | "systemGray5"
    | "systemGray6"
    | "accentColor";
}

/** 获取文件信息 */
export async function getFileInfo(filePath: string): Promise<FileInfo> {
  const name = Path.basename(filePath);
  // 先判断符号链接，再判断目录
  const isLink = await FileManager.isLink(filePath)
  const isDir = (await FileManager.isDirectory(filePath)) && !isLink

  // 目录不需要 stat，直接返回
  if (isDir) {
    let cDate = 0, mDate = 0
    try {
      const stat = await FileManager.stat(filePath);
      cDate = stat.creationDate || 0
      mDate = stat.modificationDate || 0
    } catch {}
    return {
      name,
      path: filePath,
      isDirectory: true,
      isLink,
      size: 0,
      creationDate: cDate,
      modificationDate: mDate,
      extension: "",
      category: "unknown",
      mimeType: '',
      icon: getFileIcon("", true),
      iconColor: getFileIconColor("", true),
    };
  }

  const stat = await FileManager.stat(filePath);
  const ext = Path.extname(name);
  const category = getFileCategory(ext);

  return {
    name,
    path: filePath,
    isDirectory: false,
    isLink,
    size: stat.size,
    creationDate: stat.creationDate,
    modificationDate: stat.modificationDate,
    extension: ext,
    category,
    mimeType: getMimeType(ext),
    icon: getFileIcon(ext, false),
    iconColor: getFileIconColor(ext, false),
  };
}

/** ── 目录列表缓存（防止返回导航时闪屏） ── */
const _dirCache = new Map<string, { files: FileInfo[]; timestamp: number }>()
const _DIR_CACHE_TTL = 30000 // 30 秒内认为缓存有效

/** ── 请求合并：同一目录的并发请求只走一次磁盘 ── */
const _inflightRequests = new Map<string, Promise<FileInfo[]>>()

/** 缓存目录列表 */
export function cacheDirectoryListing(path: string, files: FileInfo[]) {
  _dirCache.set(path, { files, timestamp: Date.now() })
}

/** 获取缓存的目录列表，过期返回 null */
export function getCachedDirectoryListing(path: string): FileInfo[] | null {
  const entry = _dirCache.get(path)
  if (entry && Date.now() - entry.timestamp < _DIR_CACHE_TTL) {
    return entry.files
  }
  return null
}

/** 清除所有缓存 */
export function clearDirectoryCache() {
  _dirCache.clear()
}

/** 清除指定目录的缓存（用于新建/粘贴/拖拽后立即刷新） */
export function invalidateDirectoryCache(dirPath: string) {
  _dirCache.delete(dirPath)
  _inflightRequests.delete(dirPath)
}

/** 获取目录内容列表 */
export async function listDirectory(dirPath: string): Promise<FileInfo[]> {
  // 优先返回缓存，消除快速切换时的闪屏
  const cached = getCachedDirectoryListing(dirPath)
  if (cached) return cached

  // 同一目录已有请求在进行中，直接等待结果，避免重复 I/O
  const inflight = _inflightRequests.get(dirPath)
  if (inflight) return inflight

  const promise = (async () => {
    const entries = await FileManager.readDirectory(dirPath);

    const results = await Promise.all(
      entries.map(async (entry) => {
        try {
          const fullPath = Path.join(dirPath, entry);
          const info = await getFileInfo(fullPath);
          return info;
        } catch (e) {
          return null; // 跳过无法访问的文件
        }
      })
    );

    const items: FileInfo[] = results.filter((item): item is FileInfo => item != null);

    // 自动缓存列表结果，供 GeneralBrowser 回退时使用
    cacheDirectoryListing(dirPath, items)

    return items;
  })()

  _inflightRequests.set(dirPath, promise)

  try {
    return await promise
  } finally {
    _inflightRequests.delete(dirPath)
  }
}

/** 快速获取目录条目数（只读目录，不做 getFileInfo）
 *  始终从磁盘实时读取，不使用列表缓存——文件夹计数徽标必须反映即时状态，
 *  避免跨栏拖拽后另一栏的计数因缓存过期而不刷新。 */
export async function countDirectoryItems(dirPath: string): Promise<number> {
  const entries = await FileManager.readDirectory(dirPath);
  return entries.length;
}

/** 排序方式 */
export type SortMode = "name" | "date" | "size" | "type" | "createdate";
export type SortOrder = "asc" | "desc";

/** 排序文件列表 */
export function sortFiles(files: FileInfo[], mode: SortMode, order: SortOrder): FileInfo[] {
  const sorted = [...files];
  const dirFirst = true;
  const mult = order === "asc" ? 1 : -1;

  sorted.sort((a, b) => {
    // 目录优先
    if (dirFirst) {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
    }

    switch (mode) {
      case "name":
        return mult * a.name.localeCompare(b.name, "zh-CN", { numeric: true });
      case "date":
        return mult * (a.modificationDate - b.modificationDate);
      case "createdate":
        return mult * (a.creationDate - b.creationDate);
      case "size":
        return mult * (a.size - b.size);
      case "type":
        const catCmp = mult * a.category.localeCompare(b.category);
        return catCmp !== 0 ? catCmp : mult * a.name.localeCompare(b.name, "zh-CN", { numeric: true });
      default:
        return 0;
    }
  });

  return sorted;
}

/** 搜索文件 */
export function searchFiles(files: FileInfo[], query: string): FileInfo[] {
  if (!query.trim()) return files;
  const q = query.toLowerCase();
  return files.filter((f) => f.name.toLowerCase().includes(q));
}

/* ─── 剪贴板路径管理（跨标签/子目录保留） ─── */

const _CLIPBOARD_PATH_FILE = Path.join(FileManager.temporaryDirectory, '.fstore_copied_path')

/** 读取剪贴板中存储的路径 */
export async function readClipboardPath(): Promise<string | null> {
  try {
    if (await FileManager.exists(_CLIPBOARD_PATH_FILE)) {
      return await FileManager.readAsString(_CLIPBOARD_PATH_FILE)
    }
  } catch {}
  return null
}

/** 写入路径到剪贴板存储（传 null 清除） */
export async function writeClipboardPath(path: string | null) {
  try {
    if (path) {
      await FileManager.writeAsString(_CLIPBOARD_PATH_FILE, path)
    } else {
      if (await FileManager.exists(_CLIPBOARD_PATH_FILE)) {
        await FileManager.remove(_CLIPBOARD_PATH_FILE)
      }
    }
  } catch {}
}

/** 生成不重名的路径，自动加 _01 _02 后缀 */
export async function uniquePath(targetPath: string): Promise<string> {
  if (!(await FileManager.exists(targetPath))) return targetPath
  const ext = Path.extname(targetPath)
  const base = targetPath.slice(0, targetPath.length - ext.length)
  for (let i = 1; i <= 999; i++) {
    const suffix = `_${String(i).padStart(2, '0')}`
    const candidate = `${base}${suffix}${ext}`
    if (!(await FileManager.exists(candidate))) return candidate
  }
  // fallback: use timestamp
  return `${base}_${Date.now()}${ext}`
}

/**
 * 从压缩包文件名中提取安全的目录名。
 * 处理 .hidden.zip、无扩展名、特殊字符等边界情况。
 */
export function sanitizeExtractDirName(archiveName: string): string {
  // 手动去除压缩扩展名（Path.extname 对 .hidden.zip 返回空）
  const knownExts = ['.zip', '.rar', '.7z', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar', '.gz', '.bz2', '.xz']
  let base = archiveName
  for (const ext of knownExts) {
    if (base.toLowerCase().endsWith(ext)) {
      base = base.slice(0, base.length - ext.length)
      break
    }
  }
  // 删除路径分隔符和非法字符
  base = base.replace(/[/\\:*?"<>|]/g, '_').trim()
  // 防止空目录名或
  if (!base || base === '.' || base === '..') base = 'extracted'
  return base
}

/** 解压到目标目录，避免覆盖已有文件。先解压到临时目录，再用 uniquePath 逐个移动 */
export async function safeUnzip(zipPath: string, destDir: string): Promise<void> {
  const tmpDir = Path.join(FileManager.temporaryDirectory, `_unzip_${Date.now()}`)
  await FileManager.createDirectory(tmpDir)
  try {
    await FileManager.unzip(zipPath, tmpDir)
    const entries = await FileManager.readDirectory(tmpDir)
    for (const entry of entries) {
      const src = Path.join(tmpDir, entry)
      const dest = await uniquePath(Path.join(destDir, entry))
      await FileManager.copyFile(src, dest)
      try { await FileManager.remove(src) } catch {}
    }
  } finally {
    try { await FileManager.remove(tmpDir) } catch {}
  }
}

/* ─── 重命名弹窗 ─── */

/** 弹出重命名对话框，旧名为空时仅提示输入新名 */
export async function renameWithPrompt(oldName: string): Promise<string | null> {
  const result = await Dialog.prompt({
    title: "重命名",
    message: oldName,
    defaultValue: oldName,
    placeholder: "输入新名称",
    cancelLabel: "取消",
    confirmLabel: "确认",
  })
  if (result != null) {
    const trimmed = result.trim()
    if (trimmed && trimmed !== oldName) {
      return trimmed
    }
  }
  return null
}
