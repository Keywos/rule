// 文件管理器工具函数
import { Path } from "scripting"

/** 确保 iCloud 文件已下载到本地（FileManager iCloud APIs） */
export async function ensureLocalFile(filePath: string): Promise<boolean> {
  try {
    if (typeof FileManager.isFileStoredIniCloud === "function" && FileManager.isFileStoredIniCloud(filePath)) {
      if (typeof FileManager.isiCloudFileDownloaded === "function" && !FileManager.isiCloudFileDownloaded(filePath)) {
        if (typeof FileManager.downloadFileFromiCloud === "function") {
          return await FileManager.downloadFileFromiCloud(filePath)
        }
      }
    }
  } catch { }
  return true
}

export function buildSystemDirDefs(): Array<{ name: string; getPath: () => string; icon: string; tag: string }> {
  const defs: Array<{ name: string; getPath: () => string; icon: string; tag: string }> = [
   // { name: "iPhone/Scripting", getPath: () => FileManager.documentsDirectory, icon: "paperclip", tag: "本机" },
    {
      name: "File Store",
      getPath: () => Path.join(FileManager.documentsDirectory, "File Store"),
      icon: "book.pages.fill",
      tag: "本机",
    },
  ]
  try {
    defs.push({
      name: "Scripts",
      getPath: () => FileManager.scriptsDirectory,
      icon: "chevron.left.forwardslash.chevron.right",
      tag: "脚本",
    })
  } catch { }
  return defs
}
/**
 * 判断字符串是否为“正常解码出的文本”。
 * 用于拦截二进制文件 / 解码失败产生的乱码：
 * - U+FFFD 替换字符：toDecodedString 等 API 对无法解码的字节统一替换为 U+FFFD
 * - NUL 字节（\u0000）：典型二进制标志
 * - 异常控制字符占比过高（排除 \t \n \r）：典型二进制标志
 * 空字符串视为可接受（空文件场景），由调用方结合文件大小判断。
 */
export function isPlausibleText(text: string | null | undefined): boolean {
  if (text == null) return false
  if (text.length === 0) return true
  if (text.includes("\uFFFD")) return false
  if (text.includes("\u0000")) return false
  let controlCount = 0
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || code === 0x7f) {
      controlCount++
    }
  }
  return controlCount / text.length <= 0.02
}

/**
 * 读取文本文件（统一入口）：
 * - 先 ensureLocalFile（iCloud 按需下载）
 * - 多编码回退（每个候选都经过 isPlausibleText 过滤，拒绝二进制/解码失败乱码）
 * - maxBytes：在任何完整读取前按文件元数据拒绝超限文件（适合搜索索引）
 */
export async function readTextFile(filePath: string, maxBytes?: number): Promise<string | null> {
  try {
    await ensureLocalFile(filePath);

    let fileSize = -1;
    try {
      const stat = await FileManager.stat(filePath);
      fileSize = typeof stat.size === "number" ? stat.size : -1;
    } catch {}

    if (maxBytes != null && maxBytes >= 0 && fileSize > maxBytes) return null;

    // 1. 优先尝试直接以 UTF-8 快速解析
    try {
      const text = await FileManager.readAsString(filePath);
      if (text != null && (text.length > 0 || fileSize === 0) && isPlausibleText(text)) {
        return text;
      }
    } catch {}

    // 2. 避免多次磁盘 I/O：只读一次原始 Data，后续全在内存中进行多编码转换
    const data = await FileManager.readAsData(filePath);
    if (!data) return null;
    const dataSize = data.size ?? 0;
    if (dataSize === 0) return "";

    const encodings = [
      "utf-8", "gb18030", "gbk", "utf-16", "utf16LittleEndian",
      "utf16BigEndian", "shiftJIS", "japaneseEUC", "windowsCP1252", "isoLatin1"
    ] as const;

    for (const enc of encodings) {
      try {
        const text = data.toRawString(enc as any);
        if (text && isPlausibleText(text)) return text;
      } catch {}
    }

    try {
      const decoded = data.toDecodedString("utf8");
      if (decoded && isPlausibleText(decoded)) return decoded;
    } catch {}
  } catch {}

  return null;
}
/** 长按 菜单 使用系统分享 / Open in… 菜单分享文件（DocumentInteraction） */
export async function shareFilePath(filePath: string, fileName: string) {
  try {
    const tmpPath = Path.join(FileManager.temporaryDirectory, fileName)
    if (await FileManager.exists(tmpPath)) {
      await FileManager.remove(tmpPath)
    }
    await FileManager.copyFile(filePath, tmpPath)
    await DocumentInteraction.optionsMenu(tmpPath)
    try {
      await FileManager.remove(tmpPath)
    } catch { }
  } catch (e) {
    console.log("分享失败:", e)
  }
}

/** 已解析的已知根目录缓存：路径在运行期间基本不变，避免每个文件重复调用 FileManager getter */
let _resolvedRoots: Array<[string, string]> | null = null

/** 用 FileManager 已知根目录做前缀替换（比纯正则更准确） */
function replaceKnownRoots(filePath: string): string | null {
  if (!_resolvedRoots) {
    const roots: Array<[() => string | null, string]> = [
    [
      () => {
        try {
          return FileManager.isiCloudEnabled ? FileManager.iCloudDocumentsDirectory : null
        } catch {
          return null
        }
      },
      "iCloud/",
    ],
    [
      () => {
        try {
          return FileManager.isWebDAVAvailable ? FileManager.webDAVDocumentsDirectory : null
        } catch {
          return null
        }
      },
      "WebDAV/",
    ],
    [
      () => {
        try {
          return FileManager.safariBrowserDownloadsDirectory
        } catch {
          return null
        }
      },
      "Safari/Downloads/",
    ],
    [
      () => {
        try {
          return FileManager.safariBrowserUserscriptsDirectory
        } catch {
          return null
        }
      },
      "Safari/Userscripts/",
    ],
    [
      () => {
        try {
          return FileManager.safariBrowserStorageDirectory
        } catch {
          return null
        }
      },
      "Safari/Storages/",
    ],
    [
      () => {
        try {
          return FileManager.safariBrowserDirectory
        } catch {
          return null
        }
      },
      "Safari/",
    ],
    [
      () => {
        try {
          return FileManager.scriptsDirectory
        } catch {
          return null
        }
      },
      "Scripts/",
    ],
    [
      () => {
        try {
          return FileManager.documentsDirectory
        } catch {
          return null
        }
      },
      "Documents/",
    ],
    [
      () => {
        try {
          return FileManager.appGroupDocumentsDirectory
        } catch {
          return null
        }
      },
      "AppGroup/",
    ],
    [
      () => {
        try {
          return FileManager.temporaryDirectory
        } catch {
          return null
        }
      },
      "Temp/",
    ],
    ]

    // 首次调用时解析并缓存所有可用根目录
    _resolvedRoots = []
    for (const [getRoot, label] of roots) {
      const root = getRoot()
      if (!root) continue
      _resolvedRoots.push([root.replace(/\/$/, ""), label])
    }
  }

  for (const [root, label] of _resolvedRoots) {
    if (filePath === root || filePath.startsWith(root + "/")) {
      return label + filePath.slice(root.length).replace(/^\//, "")
    }
  }
  return null
}

/** 将路径转换为友好的显示名称 */
export function pathToDisplayName(filePath: string): string {
  let p = filePath.replace(/^file:\/\//, "")

  const known = replaceKnownRoots(p)
  if (known != null) return known.replace(/\/$/, "")

  const rules: Array<[RegExp, string]> = [
    [/^\/private\/var\/mobile\/Containers\/Shared\/AppGroup\/[^/]+\/File Provider Storage\/?/, "iPhone/"],
    [/^(\/private)?\/var\/mobile\/Library\/Mobile Documents\/(?:com~apple~CloudDocs|iCloud~com~[^/]+)?\/?/, "iCloud/"],
    [/^\/private\/var\/mobile\/Containers\/Data\/Application\/[^/]+\/Documents\/?/, "Documents/"],
    [/^\/private\/var\/mobile\/Containers\/Shared\/AppGroup\/[^/]+\/?/, "AppGroup/"],
  ]

  for (const [regex, replacement] of rules) {
    if (regex.test(p)) {
      p = p.replace(regex, replacement)
      break
    }
  }

  return p.replace(/\/$/, "")
}
/** 复制文本到剪贴板并弹出简短提示（无需确认） */
export async function copyAndToast(text: string, label?: string): Promise<void> {
  await Pasteboard.setString(text)
  // 返回提示信息，调用方可用 toast 展示
  return
}

/** 获取复制成功的 toast 消息，截取前几个字符 */
export function copiedMessage(text: string): string {
  const preview = text.length > 20 ? text.slice(0, 20) + ".." : text
  return `已复制 ${preview}`
}

/** 格式化文件大小 */
export function fmtSize(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

/** 格式化日期 */
export function fmtDate(ts: number): string {
  const d = new Date(ts > 1e12 ? ts : ts * 1000)
  const now = new Date()
  const pad = (n: number) => String(n).padStart(2, "0")

  if (d.toDateString() === now.toDateString()) {
    return `今天 ${pad(d.getHours())}:${pad(d.getMinutes())}`
  }

  const yesterday = new Date(now)
  yesterday.setDate(yesterday.getDate() - 1)
  if (d.toDateString() === yesterday.toDateString()) {
    return `昨天 ${pad(d.getHours())}:${pad(d.getMinutes())}`
  }

  if (d.getFullYear() === now.getFullYear()) {
    return `${d.getMonth() + 1}月${d.getDate()}日`
  }

  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())}`
}

/** 文件类型分类 */
export type FileCategory = "text" | "code" | "image" | "pdf" | "audio" | "video" | "archive" | "data" | "unknown" | "livephoto"

const TEXT_EXTS = new Set([".txt", ".md", ".rtf", ".csv", ".log", ".ini", ".conf", ".cfg"])
const CODE_EXTS = new Set([
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
])
const IMAGE_EXTS = new Set([
  ".jpg",
  ".jpeg",
  ".png",
  ".gif",
  ".bmp",
  ".tiff",
  ".tif",
  ".svg",
  ".webp",
  ".heic",
  ".heif",
  ".ico",
  ".icns",
  ".dng",
  ".raw",
  ".cr2",
  ".cr3",
  ".nef",
  ".arw",
  ".orf",
  ".rw2",
  ".raf",
  ".pef",
  ".srw",
])
const RAW_IMAGE_EXTS = new Set([".dng", ".raw", ".cr2", ".cr3", ".nef", ".arw"])
const AUDIO_EXTS = new Set([".mp3", ".m4a", ".wav", ".aac", ".flac", ".ogg", ".wma", ".aiff"])
const VIDEO_EXTS = new Set([".mp4", ".mov", ".m4v", ".avi", ".mkv", ".wmv", ".flv", ".webm"])
const ARCHIVE_EXTS = new Set([".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"])
const DATA_EXTS = new Set([".plist", ".db", ".sqlite", ".sqlite3"])

/** 获取文件类型分类 */
export function getFileCategory(ext: string): FileCategory {
  const e = ext.toLowerCase()

  if (TEXT_EXTS.has(e)) return "text"
  if (CODE_EXTS.has(e)) return "code"
  if (e === ".live") return "livephoto"
  if (IMAGE_EXTS.has(e)) return "image"
  if (e === ".pdf") return "pdf"
  if (AUDIO_EXTS.has(e)) return "audio"
  if (VIDEO_EXTS.has(e)) return "video"
  if (ARCHIVE_EXTS.has(e)) return "archive"
  if (DATA_EXTS.has(e)) return "data"

  return "unknown"
}

/** 获取文件图标 */
export function getFileIcon(ext: string, isDirectory: boolean, category?: FileCategory): string {
  if (isDirectory) return "folder.fill"

  const e = ext.toLowerCase()
  if (e === ".live") return "livephoto"
  const cat = category ?? getFileCategory(e)

  switch (cat) {
    case "text":
      if (e === ".md") return "doc.text"
      if (e === ".csv") return "tablecells"
      if (e === ".rtf") return "doc.richtext"
      if (e === ".log") return "doc.text"
      return "doc.plaintext"
    case "code":
      if (e === ".json") return "curlybraces"
      if (e === ".html" || e === ".htm") return "globe"
      if (e === ".css" || e === ".scss" || e === ".less") return "paintbrush.fill"
      if (e === ".sh" || e === ".bash") return "terminal"
      if (e === ".sql") return "cylinder"
      if (e === ".py") return "text.word.spacing"
      if (e === ".swift") return "bird.fill"
      return "chevron.left.forwardslash.chevron.right"
    case "image":
      if (e === ".svg") return "photo.on.rectangle"
      if (RAW_IMAGE_EXTS.has(e)) return "camera.aperture"
      return "photo"
    case "pdf":
      return "doc.richtext"
    case "audio":
      return "waveform"
    case "video":
      return "film"
    case "archive":
      return "archivebox"
    case "data":
      if (e === ".plist") return "list.clipboard"
      return "externaldrive"
    case "livephoto":
      return "livephoto"
    default:
      return "doc"
  }
}

/** 获取文件图标颜色 */
export function getFileIconColor(ext: string, isDirectory: boolean, category?: FileCategory): FileInfo["iconColor"] {
  if (isDirectory) return "systemBlue"

  if (ext.toLowerCase() === ".live") return "systemPink"
  const cat = category ?? getFileCategory(ext)
  switch (cat) {
    case "text":
      return "systemGray"
    case "code":
      return "systemOrange"
    case "image":
      return "systemGreen"
    case "pdf":
      return "systemRed"
    case "audio":
      return "systemPurple"
    case "video":
      return "systemPink"
    case "archive":
      return "systemIndigo"
    case "data":
      return "systemTeal"
    default:
      return "systemGray"
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
}

/** 本地扩展名 MIME 回退表 */
const MIME_FALLBACK: Record<string, string> = {
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
  ".heic": "image/heic",
  ".heif": "image/heif",
  ".mp3": "audio/mpeg",
  ".m4a": "audio/mp4",
  ".wav": "audio/wav",
  ".mp4": "video/mp4",
  ".mov": "video/quicktime",
  ".zip": "application/zip",
  ".csv": "text/csv",
  ".rtf": "application/rtf",
}

/**
 * 获取 MIME 类型。
 * 优先使用 FileManager.mimeType(path)（系统按扩展名识别），再回退本地映射。
 */
export function getMimeType(ext: string, filePath?: string): string {
  if (filePath) {
    try {
      const m = FileManager.mimeType(filePath)
      if (m && typeof m === "string" && m.length > 0) return m
    } catch { }
  }
  const e = ext.toLowerCase()
  return MIME_FALLBACK[e] || "application/octet-stream"
}

/** 文件信息接口 */
export interface FileInfo {
  name: string
  path: string
  isDirectory: boolean
  isLink: boolean
  size: number
  creationDate: number
  modificationDate: number
  extension: string
  category: FileCategory
  mimeType: string
  icon: string
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
  | "accentColor"
}

/** 获取文件信息（并行 isLink / isDirectory / stat，减少串行 I/O） */
export async function getFileInfo(filePath: string): Promise<FileInfo> {
  const name = Path.basename(filePath)

  // 并行探测：链接判定 + 目录判定 + 元数据
  // 注意：stat 对符号链接会解析目标，因此 isLink 仍需单独查询
  const [isLink, isDirHint, stat] = await Promise.all([
    FileManager.isLink(filePath).catch(() => false),
    FileManager.isDirectory(filePath).catch(() => false),
    FileManager.stat(filePath).catch(
      () =>
        null as {
          creationDate: number
          modificationDate: number
          type: string
          size: number
        } | null,
    ),
  ])

  // 优先用 isDirectory；stat.type 作补充（link 已解析时可能是 directory/file）
  const isDir = (!!isDirHint && !isLink) || (!isLink && !!stat && stat.type === "directory")

  if (isDir) {
    return {
      name,
      path: filePath,
      isDirectory: true,
      isLink: !!isLink,
      size: 0,
      creationDate: stat?.creationDate || 0,
      modificationDate: stat?.modificationDate || 0,
      extension: "",
      category: "unknown",
      mimeType: "",
      icon: getFileIcon("", true),
      iconColor: getFileIconColor("", true),
    }
  }

  const ext = Path.extname(name)
  const category = getFileCategory(ext)

  return {
    name,
    path: filePath,
    isDirectory: false,
    isLink: !!isLink,
    size: stat?.size || 0,
    creationDate: stat?.creationDate || 0,
    modificationDate: stat?.modificationDate || 0,
    extension: ext,
    category,
    mimeType: getMimeType(ext, filePath),
    icon: getFileIcon(ext, false, category),
    iconColor: getFileIconColor(ext, false, category),
  }
}

/** ── 目录列表缓存（防止返回导航时闪屏） ── */
const _dirCache = new Map<string, { files: FileInfo[]; timestamp: number }>()
const _DIR_CACHE_TTL = 30000 // 30 秒内认为缓存有效

/** ── 请求合并：同一目录的并发请求只走一次磁盘 ── */
const _inflightRequests = new Map<string, Promise<FileInfo[]>>()
const DIRECTORY_INFO_CONCURRENCY = 16

/** 以固定并发度执行任务，避免超大目录同时发起过多 stat 请求。 */
async function mapWithConcurrency<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length)
  let nextIndex = 0
  const workerCount = Math.min(limit, items.length)
  await Promise.all(Array.from({ length: workerCount }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex++
      results[index] = await worker(items[index])
    }
  }))
  return results
}

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
    const entries = await FileManager.readDirectory(dirPath)

    // 限制 stat 并发度；目录包含大量文件时避免瞬时耗尽 I/O 与内存。
    const results = await mapWithConcurrency(entries, DIRECTORY_INFO_CONCURRENCY, async (entry) => {
      try {
        const fullPath = Path.join(dirPath, entry)
        return await getFileInfo(fullPath)
      } catch {
        return null // 跳过无法访问的文件
      }
    })

    const items: FileInfo[] = results.filter((item): item is FileInfo => item != null)

    // 自动缓存列表结果，供 GeneralBrowser 回退时使用
    cacheDirectoryListing(dirPath, items)

    return items
  })()

  _inflightRequests.set(dirPath, promise)

  try {
    return await promise
  } finally {
    _inflightRequests.delete(dirPath)
  }
}

/** 快速获取目录条目数（只读目录，不做 getFileInfo）
 *  始终从磁盘实时读取，不使用列表缓存----文件夹计数徽标必须反映即时状态，
 *  避免跨栏拖拽后另一栏的计数因缓存过期而不刷新。 */
export async function countDirectoryItems(dirPath: string): Promise<number> {
  const entries = await FileManager.readDirectory(dirPath)
  return entries.length
}

/** 排序方式 */
export type SortMode = "name" | "date" | "size" | "type" | "createdate"
export type SortOrder = "asc" | "desc"

/** 排序文件列表 */
export function sortFiles(files: FileInfo[], mode: SortMode, order: SortOrder): FileInfo[] {
  const sorted = [...files]
  const dirFirst = true
  const mult = order === "asc" ? 1 : -1

  sorted.sort((a, b) => {
    // 目录优先
    if (dirFirst) {
      if (a.isDirectory && !b.isDirectory) return -1
      if (!a.isDirectory && b.isDirectory) return 1
    }

    switch (mode) {
      case "name":
        return mult * a.name.localeCompare(b.name, "zh-CN", { numeric: true })
      case "date":
        return mult * (a.modificationDate - b.modificationDate)
      case "createdate":
        return mult * (a.creationDate - b.creationDate)
      case "size":
        return mult * (a.size - b.size)
      case "type":
        const catCmp = mult * a.category.localeCompare(b.category)
        return catCmp !== 0 ? catCmp : mult * a.name.localeCompare(b.name, "zh-CN", { numeric: true })
      default:
        return 0
    }
  })

  return sorted
}

/** 搜索文件 */
export function searchFiles(files: FileInfo[], query: string): FileInfo[] {
  if (!query.trim()) return files
  const q = query.toLowerCase()
  return files.filter((f) => f.name.toLowerCase().includes(q))
}

/* ─── 剪贴板路径管理（跨标签/子目录保留） ─── */

const _CLIPBOARD_PATH_FILE = Path.join(FileManager.temporaryDirectory, ".fstore_copied_path")

/** 读取剪贴板中存储的路径 */
export async function readClipboardPath(): Promise<string | null> {
  try {
    if (await FileManager.exists(_CLIPBOARD_PATH_FILE)) {
      return await FileManager.readAsString(_CLIPBOARD_PATH_FILE)
    }
  } catch { }
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
  } catch { }
}

const uniqueWriteQueues = new Map<string, Promise<void>>()

/**
 * Serializes destination allocation and writing for one directory.
 * Provider reads may remain concurrent, while conflicting writes cannot overwrite each other.
 */
export async function writeToUniquePath<T>(
  targetPath: string,
  write: (path: string) => Promise<T>,
): Promise<{ path: string; value: T }> {
  const dirPath = Path.dirname(targetPath)
  const previous = uniqueWriteQueues.get(dirPath) ?? Promise.resolve()
  let release: () => void = () => {}
  const current = new Promise<void>((resolve) => {
    release = resolve
  })
  const tail = previous.then(() => current)
  uniqueWriteQueues.set(dirPath, tail)

  await previous
  try {
    const path = await uniquePath(targetPath)
    const value = await write(path)
    return { path, value }
  } finally {
    release()
    if (uniqueWriteQueues.get(dirPath) === tail) uniqueWriteQueues.delete(dirPath)
  }
}

/** 生成不重名的路径，自动加 _01 _02 后缀 */
export async function uniquePath(targetPath: string): Promise<string> {
  if (!(await FileManager.exists(targetPath))) return targetPath
  const ext = Path.extname(targetPath)
  const base = targetPath.slice(0, targetPath.length - ext.length)
  for (let i = 1; i <= 999; i++) {
    const suffix = `_${String(i).padStart(2, "0")}`
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
  // 持续剥离归档后缀，避免 .zip.gz 等多层压缩包在目录名中遗留后缀。
  const knownExts = [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".rar", ".7z", ".tgz", ".tar", ".gz", ".bz2", ".xz"];
  let base = archiveName;
  let removed = true;
  while (removed) {
    removed = false;
    const lower = base.toLowerCase();
    for (const ext of knownExts) {
      if (lower.endsWith(ext)) {
        base = base.slice(0, base.length - ext.length);
        removed = true;
        break;
      }
    }
  }
  // 未知归档格式同样移除其最后一层扩展名；保留以点开头的隐藏文件名。
  const unknownExt = Path.extname(base);
  if (unknownExt && base.length > unknownExt.length) {
    base = base.slice(0, base.length - unknownExt.length);
  }
  // 删除路径分隔符和非法字符
  base = base.replace(/[/\\:*?"<>|]/g, "_").trim()
  // 防止空目录名或
  if (!base || base === "." || base === "..") base = "extracted"
  return base
}

/** 将任意路径编码为一个 shell 参数，避免空格、引号和命令替换字符被 shell 解释。 */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}

/* ─── 7z 归档（AES-256 加密）─── */

/** 判断是否为 .7z 归档文件 */
export function isSevenZFile(filePath: string): boolean {
  return Path.extname(filePath).toLowerCase() === ".7z"
}

/**
 * 检测归档真实类型（不依赖扩展名）：
 * - "7z"：魔数 37 7A BC AF 27 1C（"7z¼¯'"）
 * - "zip"：PK（50 4B）开头，含 WinZip AES 加密 zip（文件头仍是 PK）
 */
async function detectArchiveKind(filePath: string): Promise<"7z" | "zip" | "other"> {
  try {
    const bytes = await FileManager.readAsBytes(filePath)
    if (bytes.length >= 2) {
      if (bytes[0] === 0x37 && bytes[1] === 0x7a) return "7z"
      if (bytes[0] === 0x50 && bytes[1] === 0x4b) return "zip"
    }
  } catch { }
  return "other"
}

/** 判断 7z 操作错误是否为“密码错误”（Archive API 对错误密码与损坏归档使用同一错误码） */
function isSevenZPasswordError(e: unknown): boolean {
  const err = e as { name?: string; code?: string }
  return !!err && err.name === "ArchiveError" && err.code === "invalidPasswordOrCorruptArchive"
}

/** 弹出居中的密码输入框（obscureText 隐藏明文） */
async function promptSevenZPassword(title: string, message: string, placeholder: string): Promise<string | null> {
  return await Dialog.prompt({
    title,
    message,
    obscureText: true,
    placeholder,
    cancelLabel: "取消",
    confirmLabel: "确定",
  })
}

/**
 * 将 7z 归档解压到新目录 destDir（目录由 Archive API 创建，destDir 必须不存在）。
 * 归档需要密码时自动弹出居中的密码输入框；密码错误会提示重试（最多 3 次尝试）。
 * @returns true 解压成功；false 用户取消了输入密码
 */
export async function extractSevenZ(archivePath: string, destDir: string): Promise<boolean> {
  let password: string | undefined
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const task = Archive.extract7z({
        sourcePath: archivePath,
        destinationPath: destDir,
        ...(password !== undefined ? { password } : {}),
      })
      await task.result
      return true
    } catch (e) {
      if (!isSevenZPasswordError(e)) {
        console.log("[extractSevenZ] 非密码错误:", JSON.stringify({ name: (e as any)?.name, code: (e as any)?.code, message: (e as any)?.message || String(e) }))
        throw e
      }
      // extract7z 在密码错误、密码缺失或损坏归档时都可能已经创建目标目录；
      // 每一次准备重试前都清理，确保带密码重试使用全新目标目录。
      try { await FileManager.remove(destDir) } catch { }
      console.log("[extractSevenZ] 尝试", attempt, "失败:", JSON.stringify({ name: (e as any)?.name, code: (e as any)?.code, message: (e as any)?.message || String(e) }))
      const input = await promptSevenZPassword(
        attempt === 0 ? "输入解压密码" : "密码错误，请重试",
        Path.basename(archivePath),
        "该 7z 归档需要密码",
      )
      if (input == null) return false
      password = input
    }
  }
  // 多次密码错误：清理最后一次可能残留的半成品目录
  try { await FileManager.remove(destDir) } catch { }
  throw new Error("解压失败：密码错误次数过多")
}

/**
 * 为压缩包查看器解压 7z，并返回本次使用的密码。
 * 返回 null 表示原归档无需密码；返回字符串表示保存修改时应继续使用该密码。
 */
export async function extractSevenZForEditing(archivePath: string, destDir: string): Promise<string | null | false> {
  let password: string | undefined
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const task = Archive.extract7z({
        sourcePath: archivePath,
        destinationPath: destDir,
        ...(password !== undefined ? { password } : {}),
      })
      await task.result
      return password ?? null
    } catch (error) {
      if (!isSevenZPasswordError(error)) throw error
      try { await FileManager.remove(destDir) } catch { }
      const input = await promptSevenZPassword(
        attempt === 0 ? "输入 7z 解压密码" : "密码错误，请重试",
        Path.basename(archivePath),
        "查看并保存修改需要使用原密码",
      )
      if (input == null) return false
      password = input
    }
  }
  try { await FileManager.remove(destDir) } catch { }
  throw new Error("解压失败：密码错误次数过多")
}

/**
 * 为 7z 引擎准备源条目。空目录与符号链接不受 create7z 支持，
 * 因此目录会展开为普通文件，并保留与 ZIP（shouldKeepParent=false）一致的相对路径结构。
 */
async function buildSevenZSources(sourcePath: string): Promise<Array<{ path: string; archivePath?: string }>> {
  if (!(await FileManager.isDirectory(sourcePath))) return [{ path: sourcePath }]

  const entries = await FileManager.readDirectory(sourcePath, true)
  const sources: Array<{ path: string; archivePath?: string }> = []
  for (const entry of entries) {
    const fullPath = entry === sourcePath || entry.startsWith(sourcePath + "/")
      ? entry
      : Path.join(sourcePath, entry)
    if (await FileManager.isLink(fullPath)) continue
    if (!(await FileManager.isFile(fullPath))) continue
    const relativePath = fullPath.startsWith(sourcePath + "/")
      ? fullPath.slice(sourcePath.length + 1)
      : entry
    sources.push({ path: fullPath, archivePath: relativePath })
  }
  return sources
}

/** 使用已有密码创建真正的 AES-256 7z 归档，供查看器保存修改后的 7z。 */
export async function createSevenZArchiveWithPassword(
  sourcePath: string,
  destPath: string,
  password: string,
): Promise<void> {
  const sources = await buildSevenZSources(sourcePath)
  if (sources.length === 0) {
    throw new Error("7z 加密引擎不支持保存空文件夹")
  }
  const task = Archive.create7z({
    sources,
    destinationPath: destPath,
    password,
    encryptHeader: true,
  })
  await task.result
}

/**
 * 创建 AES-256 加密的 7z 归档（内容与文件名默认全部加密）。
 * 压缩前弹出居中的密码输入框，并二次确认密码防止误输。
 * @returns true 压缩成功；false 用户取消或密码无效
 */
export async function createSevenZArchive(sourcePath: string, destPath: string): Promise<boolean> {
  const password = await promptSevenZPassword(
    "7z 加密压缩 (AES-256)",
    Path.basename(sourcePath),
    "输入加密密码",
  )
  if (password == null) return false
  if (!password) {
    try { await Dialog.alert({ title: "密码不能为空", message: "加密压缩必须设置密码。" }) } catch { }
    return false
  }
  const confirm = await promptSevenZPassword(
    "确认密码",
    Path.basename(sourcePath),
    "再次输入加密密码",
  )
  if (confirm == null) return false
  if (confirm !== password) {
    try { await Dialog.alert({ title: "两次输入的密码不一致", message: "请重新发起压缩。" }) } catch { }
    return false
  }
  await createSevenZArchiveWithPassword(sourcePath, destPath, password)
  return true
}

/** 判断 Archive ZIP 解压错误是否为密码错误/归档损坏。 */
function isZipPasswordError(err: unknown): boolean {
  return !!err && (err as any).name === "ArchiveError" && (err as any).code === "invalidPasswordOrCorruptArchive"
}

/** 检测 ZIP 内文件名编码：UTF-8 有替换符时按 GB18030 读取。 */
function detectZipPathEncoding(archive: Archive): "utf-8" | "gb18030" {
  try {
    if (archive.getEntryPaths("utf-8").some((path) => path.includes("\uFFFD"))) return "gb18030"
  } catch { }
  return "utf-8"
}

/**
 * 逐条解压普通 ZIP，从一开始就使用正确的路径编码。
 * 返回 false 表示可能是加密 ZIP，交给 Archive.extractZip 的密码流程处理。
 */
async function tryExtractZipPlain(archivePath: string, destDir: string): Promise<boolean> {
  try {
    let archive = Archive.openForMode(archivePath, "read")
    const encoding = detectZipPathEncoding(archive)
    archive = Archive.openForMode(archivePath, "read", { pathEncoding: encoding })
    const entries = archive.entries(encoding)
    if (entries.length === 0 || entries.some((entry) => entry.isEncrypted)) return false

    // 关键：部分加密 ZIP 在无密码打开时只暴露目录条目，
    // 如果不对照中央目录，下面只创建目录后会被误判为解压成功。
    const centralEntries = parseZipCentralNameBytes(await FileManager.readAsBytes(archivePath))
    const expectedFileCount = centralEntries.filter((entry) => !entry.isDir).length
    const visibleFileCount = entries.filter((entry) => entry.type !== "directory").length
    if (expectedFileCount > 0 && visibleFileCount === 0) {
      console.log("[extractZip] 无密码只读到目录条目，转密码流程:", { expectedFileCount, visibleFileCount })
      return false
    }

    for (const entry of entries) {
      const destination = Path.join(destDir, entry.path)
      if (entry.type === "directory") {
        await FileManager.createDirectory(destination, true)
        continue
      }
      await FileManager.createDirectory(Path.dirname(destination), true)
      await archive.extractTo(entry.path, destination)
      // 某些加密 ZIP 会被实例 API 静默跳过；立刻转密码解压，不能把半成品视为成功。
      if (!(await FileManager.exists(destination))) return false
    }
    return true
  } catch (error) {
    console.log("[extractZip] 常规解压失败，转密码流程:", JSON.stringify({ name: (error as any)?.name, code: (error as any)?.code, message: (error as any)?.message || String(error) }))
    return false
  }
}

/** 解压 ZIP 并返回保存时应继续使用的密码：null=无密码，false=用户取消。 */
export async function extractZipForEditing(archivePath: string, destDir: string): Promise<string | null | false> {
  if (await tryExtractZipPlain(archivePath, destDir)) return null
  try { await FileManager.remove(destDir) } catch { }

  for (let attempt = 0; attempt < 3; attempt++) {
    const password = await promptSevenZPassword(
      attempt === 0 ? "输入 ZIP 解压密码" : "密码错误，请重试",
      Path.basename(archivePath),
      "查看并保存修改需要使用原密码",
    )
    if (password == null) return false
    try {
      const result = await Archive.extractZip({
        sourcePath: archivePath,
        destinationPath: destDir,
        password,
      })
      await verifyZipExtractedFiles(archivePath, destDir, result.entryCount)
      await fixMojibakeZipNames(archivePath, destDir)
      return password
    } catch (error) {
      try { await FileManager.remove(destDir) } catch { }
      if (!isZipPasswordError(error)) throw error
    }
  }
  throw new Error("解压失败：密码错误次数过多")
}

/**
 * 解压 ZIP：普通 ZIP 使用可指定编码的逐条解压；加密 ZIP 使用 Archive.extractZip。
 * Archive.extractZip 要求目标目录不存在，且会对整个归档原子写入。
 */
async function extractZipWithPassword(archivePath: string, destDir: string): Promise<boolean> {
  const result = await extractZipForEditing(archivePath, destDir)
  return result !== false
}

/**
 * 防止 Archive.extractZip 只建立目录却漏写加密文件时仍被误报为成功。
 * 仅做一次递归目录读取，避免逐文件 exists 调用。
 */
async function verifyZipExtractedFiles(archivePath: string, destDir: string, reportedEntryCount: number): Promise<void> {
  const expected = parseZipCentralNameBytes(await FileManager.readAsBytes(archivePath))
  const expectedFiles = expected.filter((entry) => !entry.isDir).length
  if (expectedFiles === 0) return

  const diskEntries = await FileManager.readDirectory(destDir, true)
  let fileCount = 0
  for (const entry of diskEntries) {
    const fullPath = entry === destDir || entry.startsWith(destDir + "/") ? entry : Path.join(destDir, entry)
    if (await FileManager.isFile(fullPath)) fileCount++
  }
  if (fileCount < expectedFiles) {
    throw new Error(`ZIP 解压不完整：归档应有 ${expectedFiles} 个文件，实际只解出 ${fileCount} 个（引擎报告 ${reportedEntryCount} 个条目）`)
  }
}

/**
 * 修复 Archive.extractZip 解出的 GBK/GB18030 中文文件名。
 * 中央目录只解析一次；目标目录也只递归读取一次建索引。之后仅在实际需要时重命名，
 * 不再对每个归档条目和每个候选名称反复访问文件系统。
 */
async function fixMojibakeZipNames(archivePath: string, destDir: string): Promise<void> {
  try {
    const parsed = parseZipCentralNameBytes(await FileManager.readAsBytes(archivePath))
    if (parsed.length === 0 || parsed.every((entry) => !decodeUtf8Lossy(entry.raw).includes("\uFFFD"))) return

    const blobLength = parsed.reduce((total, entry) => total + entry.raw.length + 1, 0)
    const blob = new Uint8Array(blobLength)
    let offset = 0
    for (const entry of parsed) {
      blob.set(entry.raw, offset)
      offset += entry.raw.length
      blob[offset++] = 0
    }

    const tempPath = Path.join(FileManager.temporaryDirectory, `_zip_names_${Date.now()}_${Math.floor(Math.random() * 100000)}.bin`)
    const decodedLists: string[][] = []
    try {
      await FileManager.writeAsBytes(tempPath, blob)
      for (const encoding of ["gb18030", "macOSRoman", "isoLatin1"] as const) {
        try {
          decodedLists.push((await FileManager.readAsString(tempPath, encoding)).split("\0").slice(0, parsed.length))
        } catch { }
      }
    } finally {
      try { await FileManager.remove(tempPath) } catch { }
    }
    if (decodedLists.length === 0) return

    const correctNames = decodedLists[0]
    const renameEntries = parsed.map((entry, index) => {
      const correct = (correctNames[index] ?? "").replace(/\/+$/, "")
      const candidates = Array.from(new Set([
        decodeUtf8Lossy(entry.raw),
        decodeWin1252(entry.raw),
        decodeCp437(entry.raw),
        ...decodedLists.slice(1).map((list) => list[index] ?? ""),
      ].map((name) => name.replace(/\/+$/, "")).filter(Boolean)))
      return { correct, candidates, isDir: entry.isDir }
    }).filter((entry) => entry.correct && isSafeArchiveRelativePath(entry.correct))
    if (renameEntries.length === 0) return

    // 单次扫描生成“物理父目录 → 名称 → 路径”的索引；目录重命名后只移动对应索引桶。
    const diskEntries = await FileManager.readDirectory(destDir, true)
    const children = new Map<string, Map<string, string>>()
    for (const entry of diskEntries) {
      const fullPath = entry === destDir || entry.startsWith(destDir + "/") ? entry : Path.join(destDir, entry)
      const parent = Path.dirname(fullPath)
      let bucket = children.get(parent)
      if (!bucket) children.set(parent, bucket = new Map())
      bucket.set(Path.basename(fullPath), fullPath)
    }

    const renamedDirs = new Map<string, string>()
    const sorted = [...renameEntries].sort((a, b) => a.correct.split("/").length - b.correct.split("/").length)
    for (const entry of sorted) {
      const base = entry.correct.split("/").pop() ?? entry.correct
      const parentName = entry.correct.slice(0, entry.correct.length - base.length).replace(/\/+$/, "")
      const physicalParent = parentName ? (renamedDirs.get(parentName) ?? Path.join(destDir, parentName)) : destDir
      const bucket = children.get(physicalParent)
      if (!bucket) continue

      // 文件已是正确名称时不做 I/O；目录还要记录它的物理位置，供子项使用。
      const existing = bucket.get(base)
      if (existing) {
        if (entry.isDir) renamedDirs.set(entry.correct, existing)
        continue
      }

      let source: string | undefined
      for (const candidate of entry.candidates) {
        const candidateBase = candidate.split("/").pop() ?? candidate
        if (candidateBase !== base && bucket.has(candidateBase)) {
          source = bucket.get(candidateBase)
          break
        }
      }
      if (!source) continue

      const target = Path.join(physicalParent, base)
      try {
        await FileManager.rename(source, target)
      } catch {
        continue
      }
      bucket.delete(Path.basename(source))
      bucket.set(base, target)
      if (entry.isDir) {
        const childBucket = children.get(source)
        if (childBucket) {
          children.delete(source)
          children.set(target, childBucket)
        }
        renamedDirs.set(entry.correct, target)
      }
    }
  } catch (error) {
    console.log("[fixMojibakeZipNames] 跳过:", String(error))
  }
}

/** ZIP 内路径必须是相对路径且不含 . / .. 组件。 */
function isSafeArchiveRelativePath(path: string): boolean {
  return !!path && !path.startsWith("/") && path.split("/").every((part) => part && part !== "." && part !== "..")
}

/** 解析 ZIP 中央目录，返回每个条目的原始文件名字节（加密 ZIP 也可读取）。 */
function parseZipCentralNameBytes(fileBytes: Uint8Array): { raw: Uint8Array; isDir: boolean }[] {
  let eocd = -1
  const start = Math.max(0, fileBytes.length - 22 - 65536)
  for (let index = fileBytes.length - 22; index >= start; index--) {
    if (fileBytes[index] === 0x50 && fileBytes[index + 1] === 0x4b && fileBytes[index + 2] === 0x05 && fileBytes[index + 3] === 0x06) {
      eocd = index
      break
    }
  }
  if (eocd < 0) return []
  const count = fileBytes[eocd + 10] | (fileBytes[eocd + 11] << 8)
  const centralOffset = (fileBytes[eocd + 16] | (fileBytes[eocd + 17] << 8) | (fileBytes[eocd + 18] << 16) | (fileBytes[eocd + 19] << 24)) >>> 0
  const entries: { raw: Uint8Array; isDir: boolean }[] = []
  let offset = centralOffset
  for (let index = 0; index < count; index++) {
    if (fileBytes[offset] !== 0x50 || fileBytes[offset + 1] !== 0x4b || fileBytes[offset + 2] !== 0x01 || fileBytes[offset + 3] !== 0x02) break
    const nameLength = fileBytes[offset + 28] | (fileBytes[offset + 29] << 8)
    const extraLength = fileBytes[offset + 30] | (fileBytes[offset + 31] << 8)
    const commentLength = fileBytes[offset + 32] | (fileBytes[offset + 33] << 8)
    const raw = fileBytes.slice(offset + 46, offset + 46 + nameLength)
    entries.push({ raw, isDir: raw.length > 0 && raw[raw.length - 1] === 0x2f })
    offset += 46 + nameLength + extraLength + commentLength
  }
  return entries
}

/** UTF-8 容错解码，用于匹配 extractZip 可能写出的乱码名称。 */
function decodeUtf8Lossy(bytes: Uint8Array): string {
  let output = ""
  let index = 0
  while (index < bytes.length) {
    const byte = bytes[index]
    if (byte < 0x80) {
      output += String.fromCharCode(byte)
      index++
      continue
    }
    let length = 0
    let codePoint = 0
    if ((byte & 0xe0) === 0xc0) { length = 2; codePoint = byte & 0x1f }
    else if ((byte & 0xf0) === 0xe0) { length = 3; codePoint = byte & 0x0f }
    else if ((byte & 0xf8) === 0xf0) { length = 4; codePoint = byte & 0x07 }
    let valid = length > 0
    if (valid) {
      for (let next = 1; next < length; next++) {
        const continuation = bytes[index + next]
        if (continuation === undefined || (continuation & 0xc0) !== 0x80) { valid = false; break }
        codePoint = (codePoint << 6) | (continuation & 0x3f)
      }
      if (valid && (codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff))) valid = false
      if (valid && length === 2 && codePoint < 0x80) valid = false
      if (valid && length === 3 && codePoint < 0x800) valid = false
      if (valid && length === 4 && codePoint < 0x10000) valid = false
    }
    if (valid) {
      output += String.fromCodePoint(codePoint)
      index += length
    } else {
      output += "\uFFFD"
      index++
    }
  }
  return output
}

function decodeWin1252(bytes: Uint8Array): string {
  const special: Record<number, number> = { 0x80: 0x20ac, 0x82: 0x201a, 0x83: 0x0192, 0x84: 0x201e, 0x85: 0x2026, 0x86: 0x2020, 0x87: 0x2021, 0x88: 0x02c6, 0x89: 0x2030, 0x8a: 0x0160, 0x8b: 0x2039, 0x8c: 0x0152, 0x8e: 0x017d, 0x91: 0x2018, 0x92: 0x2019, 0x93: 0x201c, 0x94: 0x201d, 0x95: 0x2022, 0x96: 0x2013, 0x97: 0x2014, 0x98: 0x02dc, 0x99: 0x2122, 0x9a: 0x0161, 0x9b: 0x203a, 0x9c: 0x0153, 0x9e: 0x017e, 0x9f: 0x0178 }
  let output = ""
  for (const byte of bytes) output += String.fromCharCode(byte < 0x80 ? byte : (special[byte] ?? byte))
  return output
}

function decodeCp437(bytes: Uint8Array): string {
  const table = [0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5, 0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9, 0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192, 0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba, 0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb, 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580, 0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4, 0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229, 0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248, 0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0]
  let output = ""
  for (const byte of bytes) output += String.fromCharCode(byte < 0x80 ? byte : (table[byte - 0x80] ?? byte))
  return output
}

/** 创建 WinZip AES-256 加密 ZIP，压缩前二次确认密码。 */
export async function createZipArchive(sourcePath: string, destPath: string): Promise<boolean> {
  const password = await promptSevenZPassword(
    "ZIP 加密压缩 (AES-256)",
    Path.basename(sourcePath),
    "输入加密密码",
  )
  if (password == null) return false
  if (!password) {
    try { await Dialog.alert({ title: "密码不能为空", message: "加密压缩必须设置密码。" }) } catch { }
    return false
  }
  const confirm = await promptSevenZPassword(
    "确认密码",
    Path.basename(sourcePath),
    "再次输入加密密码",
  )
  if (confirm == null) return false
  if (confirm !== password) {
    try { await Dialog.alert({ title: "两次输入的密码不一致", message: "请重新发起压缩。" }) } catch { }
    return false
  }
  await Archive.createZip({
    sourcePath,
    destinationPath: destPath,
    password,
    compressionMethod: "deflate",
  })
  return true
}

/** 按归档格式解压到 destDir（zip/tar 等要求 destDir 已存在；7z 由 Archive API 自行创建）。返回 false 表示用户取消了 7z 密码输入 */
async function extractArchiveInto(archivePath: string, destDir: string): Promise<boolean> {
  const name = Path.basename(archivePath).toLowerCase()
  const ext = Path.extname(archivePath).toLowerCase()

  // 判断压缩格式并选择解压方式
  const isTarGz = name.endsWith(".tar.gz")
  const isTarBz2 = name.endsWith(".tar.bz2")
  const isTarXz = name.endsWith(".tar.xz")
  const isTgz = name.endsWith(".tgz")
  const isTar = ext === ".tar" || isTarGz || isTarBz2 || isTarXz || isTgz

  if (ext === ".zip") {
    return await extractZipWithPassword(archivePath, destDir)
  } else if (isSevenZFile(archivePath)) {
    // 7z：使用 Archive API（支持 AES-256 加密归档，需要密码时自动弹出输入框）
    return await extractSevenZ(archivePath, destDir)
  } else if (isTar) {
    const r = await Shell.run(`tar -xf ${shellQuote(archivePath)}`, { cwd: destDir })
    if (r.exitCode !== 0) {
      throw new Error(`tar 解压失败: ${r.output}`)
    }
  } else if (ext === ".gz" && !isTarGz) {
    // 单独 .gz 文件（非 tar.gz）
    const outName = name.slice(0, -3)
    const r = await Shell.run(`gzip -d -c ${shellQuote(archivePath)} > ${shellQuote(Path.join(destDir, outName))}`)
    if (r.exitCode !== 0) {
      throw new Error(`gzip 解压失败: ${r.output}`)
    }
  } else if (ext === ".bz2" && !isTarBz2) {
    const outName = name.slice(0, -4)
    const r = await Shell.run(`bzip2 -d -c ${shellQuote(archivePath)} > ${shellQuote(Path.join(destDir, outName))}`)
    if (r.exitCode !== 0) {
      throw new Error(`bzip2 解压失败: ${r.output}`)
    }
  } else if (ext === ".xz" && !isTarXz) {
    const outName = name.slice(0, -3)
    const r = await Shell.run(`xz -d -c ${shellQuote(archivePath)} > ${shellQuote(Path.join(destDir, outName))}`)
    if (r.exitCode !== 0) {
      throw new Error(`xz 解压失败: ${r.output}`)
    }
  } else {
    try {
      await FileManager.unzip(archivePath, destDir)
    } catch {
      throw new Error(`不支持的压缩格式: ${ext}`)
    }
  }
  return true
}

/**
 * 解压到新目录（不经过临时目录）：非 7z 先创建 destDir 再直接解压；7z 由 Archive API 自行创建 destDir。
 * 调用方需保证 destDir 唯一（重名时自行加后缀）。
 * @returns true 解压成功；false 用户取消了 7z 密码输入
 */
export async function extractArchiveToNewDir(archivePath: string, destDir: string): Promise<boolean> {
  if (!isSevenZFile(archivePath)) {
    await FileManager.createDirectory(destDir, true)
  }
  return await extractArchiveInto(archivePath, destDir)
}

/**
 * 统一智能解压 ZIP / 7z 到新目录：按真实魔数识别，支持有密码和无密码归档。
 * ZIP 统一走 extractZipWithPassword，7z 统一走 extractSevenZ。
 */
export async function extractArchiveSmartToNewDir(archivePath: string, destDir: string): Promise<boolean> {
  const kind = await detectArchiveKind(archivePath)
  console.log("[智能解压] 真实类型:", kind)
  if (kind === "7z") return await extractSevenZ(archivePath, destDir)
  if (kind === "zip") {
    await FileManager.createDirectory(destDir, true)
    return await extractZipWithPassword(archivePath, destDir)
  }
  throw new Error(`不是有效的 ZIP/7z 文件: ${Path.basename(archivePath)}`)
}

/** 兼容旧调用名：统一入口现在同时支持 ZIP 与 7z。 */
export const extractSevenZToNewDir = extractArchiveSmartToNewDir

/** 递归统计目录下所有文件（不含目录本身）的数量 */
async function countFilesRecursive(dirPath: string): Promise<number> {
  let count = 0
  const entries = await FileManager.readDirectory(dirPath)
  for (const entry of entries) {
    const p = Path.join(dirPath, entry)
    try {
      if (await FileManager.isDirectory(p)) count += await countFilesRecursive(p)
      else count += 1
    } catch { }
  }
  return count
}

/** 解压到目标目录，避免覆盖已有文件。先解压到临时目录，再用 uniquePath 逐个移动（用于“解压到当前目录”等已有目录场景） */
export async function safeUnzip(archivePath: string, destDir: string): Promise<void> {
  const tmpDir = await uniquePath(Path.join(FileManager.temporaryDirectory, `_unzip_${Date.now()}`))
  const is7z = isSevenZFile(archivePath)
  // 7z 由 Archive.extract7z 自行创建目标目录，因此不预创建 tmpDir
  if (!is7z) {
    await FileManager.createDirectory(tmpDir)
  }
  try {
    const ok = await extractArchiveInto(archivePath, tmpDir)
    if (!ok) return // 用户取消输入密码，不移动任何文件

    const copiedPaths: string[] = []
    const entries = await FileManager.readDirectory(tmpDir)
    try {
      for (const entry of entries) {
        const src = Path.join(tmpDir, entry)
        const { path: dest } = await writeToUniquePath(Path.join(destDir, entry), (targetPath) => FileManager.copyFile(src, targetPath))
        copiedPaths.push(dest)
        try {
          await FileManager.remove(src)
        } catch { }
      }
    } catch (error) {
      await Promise.all(copiedPaths.map(async (path) => {
        try {
          await FileManager.remove(path)
        } catch { }
      }))
      throw error
    }
  } finally {
    try {
      await FileManager.remove(tmpDir)
    } catch { }
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

/**
 * 将文件的修改时间刷新为当前时间。
 * copyFile 会保留源文件的修改时间，这里通过读回内容再写回，使 mtime 变为当前时间。
 * 仅对小于 50MB 的文件执行（避免大文件占用大量内存）。
 */
export async function refreshFileModificationTime(path: string): Promise<void> {
  try {
    const stat = await FileManager.stat(path);
    if (!stat || stat.size > 50 * 1024 * 1024) return;
    const data = await FileManager.readAsData(path);
    await FileManager.writeAsData(path, data);
  } catch (e) {
    console.log("refreshFileModificationTime 失败:", e);
  }
}

/**
 * 将外部文件复制到 File Store 目录（持久化保存），返回副本路径。
 * 如果文件已在 File Store 中，则返回原始路径（saved=false）。
 * 如果文件不可直接读取，通过书签解析（分享自动创建的书签）取得可读路径再复制。
 */
export async function copyFileToFileStore(src: string): Promise<{ path: string; saved: boolean }> {
  const fileStoreDir = Path.join(FileManager.documentsDirectory, "File Store");

  // 已在 File Store 中 → 无需复制
  if (src === fileStoreDir || src.startsWith(fileStoreDir + "/")) {
    return { path: src, saved: false };
  }

  // 清理路径前缀（file://）
  const normalizePath = (p: string) => p.replace(/^file:\/\//i, "").replace(/\\/g, "/");
  const srcClean = normalizePath(src);

  // 尝试获取可读的源文件路径
  async function resolveReadablePath(): Promise<string | null> {
    // 0. 获取源文件大小（用于验证候选是否是对应文件）
    let srcSize = -1;
    try {
      srcSize = (await FileManager.stat(srcClean)).size;
    } catch {}

    // 1. 直接探测可读性
    try {
      const probe = await FileManager.readAsData(srcClean);
      if (probe && probe.size > 0) {
        console.log("copyFileToFileStore: 直接可读, src=", srcClean);
        return srcClean;
      }
    } catch (e) {
      console.log("copyFileToFileStore: 直接不可读, 尝试书签解析:", String(e).slice(0, 120));
    }

    // 2. 遍历所有书签，只接受“文件名与源文件相同”的可读候选
    try {
      const bookmarks = FileManager.getAllFileBookmarks();
      console.log(`copyFileToFileStore: 共有 ${bookmarks.length} 个书签`);

      const srcName = Path.basename(srcClean);
      const srcSegments = srcClean.split("/");
      const srcTail = srcSegments.slice(-2).join("/");

      const candidates: Array<{ name: string; path: string; score: number; size: number }> = [];

      for (const b of bookmarks) {
        try {
          // 书签原始路径的文件名必须与源文件一致（分享自动创建的书签 b.path 即分享文件路径）
          const bPathNorm = normalizePath(b.path || "");
          const bPathName = Path.basename(bPathNorm);
          if (bPathName !== srcName) continue;

          // 尝试 bookmarkedPath（解析安全作用域路径）
          let resolved = FileManager.bookmarkedPath(b.name);
          if (!resolved || !resolved.trim()) {
            // 回退到 b.path（原始路径）
            resolved = b.path;
          }
          if (!resolved || !resolved.trim()) continue;

          const resolvedClean = normalizePath(resolved);
          const resolvedName = Path.basename(resolvedClean);
          // 解析出的可读路径文件名也必须与源文件一致
          if (resolvedName !== srcName) continue;

          const resolvedSegments = resolvedClean.split("/");
          const resolvedTail = resolvedSegments.slice(-2).join("/");

          // 计算匹配分数（越高越可能是正确的分享文件）
          let score = 0;
          if (resolvedClean === srcClean) score += 20;
          if (bPathNorm === srcClean) score += 15;
          if (resolvedTail === srcTail && srcTail.length > 0) score += 5;
          if ((b.name || "").includes(srcName)) score += 3;

          // 探测候选大小
          let candSize = -1;
          try {
            candSize = (await FileManager.stat(resolvedClean)).size;
          } catch {}
          // 大小一致是强信号（src 可 stat 时才使用）
          if (srcSize >= 0 && candSize === srcSize) score += 8;

          candidates.push({ name: b.name, path: resolvedClean, score, size: candSize });
        } catch {}
      }

      // 3. 按分数降序，取第一个可读的候选（已保证文件名一致）
      candidates.sort((a, b) => b.score - a.score);
      for (const c of candidates) {
        try {
          const probe = await FileManager.readAsData(c.path);
          if (probe && probe.size > 0) {
            console.log(`copyFileToFileStore: 书签匹配成功, name=${c.name}, score=${c.score}, path=${c.path}`);
            return c.path;
          }
        } catch {}
      }
    } catch (e) {
      console.log("copyFileToFileStore: 书签遍历失败:", e);
    }

    return null;
  }

  const resolvedSrc = await resolveReadablePath();

  // 复制到 File Store 目录
  if (resolvedSrc) {
    try {
      await FileManager.createDirectory(fileStoreDir, true);
      const srcName = Path.basename(srcClean);
      let dest = Path.join(fileStoreDir, srcName);
      dest = await uniquePath(dest);
      await FileManager.copyFile(resolvedSrc, dest);
      console.log(`copyFileToFileStore: 复制成功 ${dest}`);
      // copyFile 会保留源文件的修改时间，这里读回重写一次让修改时间更新为当前时间
      await refreshFileModificationTime(dest);
      return { path: dest, saved: true };
    } catch (e) {
      console.log("copyFileToFileStore: 复制失败:", e);
    }
  }

  // 全部失败，返回原始路径
  console.log("copyFileToFileStore: 全部失败, src=", srcClean);
  return { path: src, saved: false };
}
