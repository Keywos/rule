/** 编辑器语言名称映射。 */
export const langMap: Record<string, string> = {
  ".json": "JSON", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript (React)",
  ".jsx": "JavaScript (React)", ".md": "Markdown", ".txt": "纯文本", ".html": "HTML",
  ".conf": "配置文件", ".dcong": "配置文件", ".htm": "HTML", ".css": "CSS", ".scss": "SCSS",
  ".py": "Python", ".swift": "Swift", ".csv": "CSV", ".log": "日志", ".xml": "XML",
  ".yaml": "YAML", ".yml": "YAML", ".sh": "Shell", ".bash": "Bash", ".sql": "SQL",
  ".rtf": "富文本", ".pdf": "PDF", ".java": "Java", ".kt": "Kotlin", ".c": "C",
  ".cpp": "C++", ".rb": "Ruby", ".go": "Go", ".rs": "Rust", ".php": "PHP",
  ".lua": "Lua", ".r": "R", ".toml": "TOML",
}

/** 常见扩展名的本地 MIME 回退表。 */
export const MIME_FALLBACK: Record<string, string> = {
  ".txt": "text/plain", ".md": "text/markdown", ".html": "text/html", ".htm": "text/html",
  ".css": "text/css", ".js": "text/javascript", ".ts": "text/typescript", ".json": "application/json",
  ".xml": "application/xml", ".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg", ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
  ".heic": "image/heic", ".heif": "image/heif", ".mp3": "audio/mpeg", ".m4a": "audio/mp4",
  ".wav": "audio/wav", ".mp4": "video/mp4", ".mov": "video/quicktime", ".zip": "application/zip",
  ".csv": "text/csv", ".rtf": "application/rtf",
}
