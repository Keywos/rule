/** 格式化文件大小 */
export function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

/** 格式化 Unix 时间戳或毫秒时间戳 */
export function fmtDate(timestamp: number): string {
  const date = new Date(timestamp > 1e12 ? timestamp : timestamp * 1000)
  const now = new Date()
  const pad = (value: number) => String(value).padStart(2, "0")
  if (date.toDateString() === now.toDateString()) return `今天 ${pad(date.getHours())}:${pad(date.getMinutes())}`
  const yesterday = new Date(now)
  yesterday.setDate(yesterday.getDate() - 1)
  if (date.toDateString() === yesterday.toDateString()) return `昨天 ${pad(date.getHours())}:${pad(date.getMinutes())}`
  if (date.getFullYear() === now.getFullYear()) return `${date.getMonth() + 1}月${date.getDate()}日`
  return `${date.getFullYear()}/${pad(date.getMonth() + 1)}/${pad(date.getDate())}`
}
