// history.ts — 历史记录保存与加载

import { type JetsamData } from "./parser"

const HISTORY_FILE = FileManager.iCloudDocumentsDirectory + "/.jetsamhistory.json"

export interface HistoryEntry {
  timestamp: string
  fileName: string
  deviceType: string
  data: JetsamData
}

export function loadHistory(): HistoryEntry[] {
  try {
    if (!FileManager.existsSync(HISTORY_FILE)) return []
    const content = FileManager.readAsStringSync(HISTORY_FILE)
    const parsed = JSON.parse(content)
    if (!Array.isArray(parsed)) return []
    return parsed
  } catch {
    return []
  }
}

export function saveHistory(entries: HistoryEntry[]): void {
  try {
    FileManager.writeAsStringSync(HISTORY_FILE, JSON.stringify(entries, null, 2))
  } catch (e) {
    console.error("保存历史记录失败:", e)
  }
}

export function addHistoryEntry(
  entries: HistoryEntry[],
  fileName: string,
  deviceType: string,
  data: JetsamData,
  timestamp?: string,
): HistoryEntry[] {
  // 文件名相同则不重复添加，直接返回
  if (entries.some(e => e.fileName === fileName)) {
    return entries
  }
  const entry: HistoryEntry = {
    timestamp: timestamp ?? new Date().toISOString(),
    fileName,
    deviceType,
    data,
  }
  // 最新的在前，最多保留50条
  const updated = [entry, ...entries].slice(0, 50)
  saveHistory(updated)
  return updated
}

export function deleteHistoryEntry(entries: HistoryEntry[], index: number): HistoryEntry[] {
  const updated = entries.filter((_, i) => i !== index)
  saveHistory(updated)
  return updated
}
