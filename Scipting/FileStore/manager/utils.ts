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
    { name: "iPhone/Scripting", getPath: () => FileManager.documentsDirectory, icon: "paperclip", tag: "本机" },
    {
      name: "iPhone/Scripting/File Store",
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
 * 读取文本文件（统一入口）：
 * - 先 ensureLocalFile（iCloud 按需下载）
 * - 用 isBinaryFile 跳过二进制
 * - 多编码回退
 */
export async function readTextFile(filePath: string): Promise<string | null> {
  try {
    await ensureLocalFile(filePath)

    let fileSize = -1
    try {
      const stat = await FileManager.stat(filePath)
      fileSize = typeof stat.size === "number" ? stat.size : -1
    } catch { }

    const isUsableText = (text: string | null | undefined) => {
      // 只有明确知道文件大小为 0 时才接受空字符串；stat 失败/未知大小不能把空字符串当成功。
      return text != null && (text.length > 0 || fileSize === 0)
    }

    // 1. 默认编码（通常会自动识别 UTF-8/BOM）
    try {
      const text = await FileManager.readAsString(filePath)
      if (isUsableText(text)) return text
    } catch { }

    // 2. 多编码回退，避免 GBK/UTF-16/Shift-JIS 等文件打开为空白
    const encodings = [
      "utf-8",
      "utf-16",
      "utf16LittleEndian",
      "utf16BigEndian",
      "gb18030",
      "gbk",
      "shiftJIS",
      "japaneseEUC",
      "windowsCP1252",
      "isoLatin1",
      "ascii",
    ] as const

    for (const enc of encodings) {
      try {
        const text = await FileManager.readAsString(filePath, enc)
        console.log(enc)

        if (isUsableText(text)) return text
      } catch { }
    }

    // 3. readAsString 可能对部分安全域/iCloud/特殊编码文件返回空字符串。
    //    直接读 Data 再解码，至少保证非空文件不会空白打开。
    try {
      const data = await FileManager.readAsData(filePath)
      const dataSize = data?.size ?? 0
      for (const enc of encodings) {
        try {
          const text = data.toRawString(enc as any)
          if (text != null && (text.length > 0 || dataSize === 0)) return text
        } catch { }
      }
      if (dataSize > 0) {
        try {
          const decoded = data.toDecodedString("utf8")
          if (decoded != null) return decoded
        } catch { }
      }
    } catch { }
  } catch { }

  return null
}
/** 使用系统分享 / Open in… 菜单分享文件（DocumentInteraction） */
export async function shareFilePath(filePath: string, fileName: string) {
  try {
    // 优先直接对原路径弹出菜单，避免多余拷贝
    try {
      await DocumentInteraction.optionsMenu(filePath)
      return
    } catch { }
    // 安全域 / 无法直接分享时，复制到临时目录再分享
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

/** 用 FileManager 已知根目录做前缀替换（比纯正则更准确） */
function replaceKnownRoots(filePath: string): string | null {
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

  for (const [getRoot, label] of roots) {
    const root = getRoot()
    if (!root) continue
    const normalized = root.replace(/\/$/, "")
    if (filePath === normalized || filePath.startsWith(normalized + "/")) {
      return label + filePath.slice(normalized.length).replace(/^\//, "")
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

    const results = await Promise.all(
      entries.map(async (entry) => {
        try {
          const fullPath = Path.join(dirPath, entry)
          const info = await getFileInfo(fullPath)
          return info
        } catch (e) {
          return null // 跳过无法访问的文件
        }
      }),
    )

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
  // 手动去除压缩扩展名（Path.extname 对 .hidden.zip 返回空）
  const knownExts = [".zip", ".rar", ".7z", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".gz", ".bz2", ".xz"]
  let base = archiveName
  for (const ext of knownExts) {
    if (base.toLowerCase().endsWith(ext)) {
      base = base.slice(0, base.length - ext.length)
      break
    }
  }
  // 删除路径分隔符和非法字符
  base = base.replace(/[/\\:*?"<>|]/g, "_").trim()
  // 防止空目录名或
  if (!base || base === "." || base === "..") base = "extracted"
  return base
}

/** 解压到目标目录，避免覆盖已有文件。先解压到临时目录，再用 uniquePath 逐个移动 */
export async function safeUnzip(archivePath: string, destDir: string): Promise<void> {
  const tmpDir = Path.join(FileManager.temporaryDirectory, `_unzip_${Date.now()}`)
  await FileManager.createDirectory(tmpDir)
  try {
    const name = Path.basename(archivePath).toLowerCase()
    const ext = Path.extname(archivePath).toLowerCase()

    // 判断压缩格式并选择解压方式
    const isTarGz = name.endsWith(".tar.gz")
    const isTarBz2 = name.endsWith(".tar.bz2")
    const isTarXz = name.endsWith(".tar.xz")
    const isTgz = name.endsWith(".tgz")
    const isTar = ext === ".tar" || isTarGz || isTarBz2 || isTarXz || isTgz

    if (ext === ".zip") {
      await FileManager.unzip(archivePath, tmpDir)
    } else if (isTar) {
      const r = await Shell.run(`tar -xf "${archivePath}"`, { cwd: tmpDir })
      if (r.exitCode !== 0) {
        throw new Error(`tar 解压失败: ${r.output}`)
      }
    } else if (ext === ".gz" && !isTarGz) {
      // 单独 .gz 文件（非 tar.gz）
      const outName = name.slice(0, -3)
      const r = await Shell.run(`gzip -d -c "${archivePath}" > "${tmpDir}/${outName}"`)
      if (r.exitCode !== 0) {
        throw new Error(`gzip 解压失败: ${r.output}`)
      }
    } else if (ext === ".bz2" && !isTarBz2) {
      const outName = name.slice(0, -4)
      const r = await Shell.run(`bzip2 -d -c "${archivePath}" > "${tmpDir}/${outName}"`)
      if (r.exitCode !== 0) {
        throw new Error(`bzip2 解压失败: ${r.output}`)
      }
    } else if (ext === ".xz" && !isTarXz) {
      const outName = name.slice(0, -3)
      const r = await Shell.run(`xz -d -c "${archivePath}" > "${tmpDir}/${outName}"`)
      if (r.exitCode !== 0) {
        throw new Error(`xz 解压失败: ${r.output}`)
      }
    } else {
      try {
        await FileManager.unzip(archivePath, tmpDir)
      } catch {
        throw new Error(`不支持的压缩格式: ${ext}`)
      }
    }

    const entries = await FileManager.readDirectory(tmpDir)
    for (const entry of entries) {
      const src = Path.join(tmpDir, entry)
      const dest = await uniquePath(Path.join(destDir, entry))
      await FileManager.copyFile(src, dest)
      try {
        await FileManager.remove(src)
      } catch { }
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
