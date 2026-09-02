// parser.ts — 解析 JetsamEvent .ips 文件（进程 / 内存信息）

export interface JetsamProcess {
  name: string
  pid: number
  rpages: number          // 常驻内存（页）
  lifetimeMax: number     // 历史最大常驻内存（页）
  purgeable: number
  cpuTime: number         // CPU 时间（秒）
  priority: number
  mem_regions: number
  fds: number
  age: number             // 存活时长（纳秒）
  states: string[]
  reason?: string         // 被杀原因（仅被杀进程有）
  killDelta?: number      // 距被杀时间（纳秒）
  physicalPages?: { internal?: number[] }
}

export interface JetsamMemoryPages {
  active: number
  throttled: number
  fileBacked: number
  wired: number
  anonymous: number
  purgeable: number
  inactive: number
  free: number
  speculative: number
}

export interface JetsamMemory {
  pageSize: number
  compressorSize: number
  compressions: number
  decompressions: number
  uncompressed: number
  largestZone: string
  largestZoneSize: number
  zoneMapCap: number
  zoneMapSize: number
  memoryPages: JetsamMemoryPages
}

// .ips 头部 JSON 的已知字段（其余字段保留任意类型）
export interface JetsamHeader {
  timestamp?: string
  [key: string]: any
}

export interface JetsamData {
  header: JetsamHeader
  build: string
  product: string
  kernel: string
  date: string
  timeDelta: number
  memory: JetsamMemory
  largestProcess: string
  genCounter: number
  processes: JetsamProcess[]
  killed: JetsamProcess[]
}

export function emptyData(): JetsamData {
  return {
    header: {},
    build: "",
    product: "",
    kernel: "",
    date: "",
    timeDelta: 0,
    memory: {
      pageSize: 16384,
      compressorSize: 0,
      compressions: 0,
      decompressions: 0,
      uncompressed: 0,
      largestZone: "",
      largestZoneSize: 0,
      zoneMapCap: 0,
      zoneMapSize: 0,
      memoryPages: {
        active: 0, throttled: 0, fileBacked: 0, wired: 0,
        anonymous: 0, purgeable: 0, inactive: 0, free: 0, speculative: 0,
      },
    },
    largestProcess: "",
    genCounter: 0,
    processes: [],
    killed: [],
  }
}

// .ips 文件：第 1 行为头部 JSON，其余为正文 JSON（美化输出）
export function parseContent(content: string): JetsamData {
  const result = emptyData()
  let header: Record<string, any> = {}
  let body: Record<string, any> = {}
  const nl = content.indexOf("\n")
  try {
    if (nl >= 0) {
      header = JSON.parse(content.slice(0, nl))
      try { body = JSON.parse(content.slice(nl + 1)) } catch {}
    }
    if (Object.keys(body).length === 0) {
      body = JSON.parse(content)
    }
  } catch {
    return result
  }

  const ms = (body.memoryStatus || {}) as Record<string, any>
  const mp = (ms.memoryPages || {}) as Record<string, any>
  const rawProcesses: Record<string, any>[] = Array.isArray(body.processes) ? body.processes : []

  const processes: JetsamProcess[] = rawProcesses.map((p: Record<string, any>) => ({
    name: String(p.name ?? "未知"),
    pid: p.pid ?? 0,
    rpages: p.rpages ?? 0,
    lifetimeMax: p.lifetimeMax ?? 0,
    purgeable: p.purgeable ?? 0,
    cpuTime: p.cpuTime ?? 0,
    priority: p.priority ?? 0,
    mem_regions: p.mem_regions ?? 0,
    fds: p.fds ?? 0,
    age: p.age ?? 0,
    states: Array.isArray(p.states) ? p.states.map(String) : [],
    reason: p.reason != null ? String(p.reason) : undefined,
    killDelta: p.killDelta ?? undefined,
    physicalPages: p.physicalPages,
  }))

  result.header = header
  result.build = body.build ?? ""
  result.product = body.product ?? ""
  result.kernel = body.kernel ?? ""
  result.date = body.date ?? ""
  result.timeDelta = body.timeDelta ?? 0
  result.largestProcess = body.largestProcess ?? ""
  result.genCounter = body.genCounter ?? 0
  result.memory = {
    pageSize: ms.pageSize ?? 16384,
    compressorSize: ms.compressorSize ?? 0,
    compressions: ms.compressions ?? 0,
    decompressions: ms.decompressions ?? 0,
    uncompressed: ms.uncompressed ?? 0,
    largestZone: ms.largestZone ?? "",
    largestZoneSize: ms.largestZoneSize ?? 0,
    zoneMapCap: ms.zoneMapCap ?? 0,
    zoneMapSize: ms.zoneMapSize ?? 0,
    memoryPages: {
      active: mp.active ?? 0,
      throttled: mp.throttled ?? 0,
      fileBacked: mp.fileBacked ?? 0,
      wired: mp.wired ?? 0,
      anonymous: mp.anonymous ?? 0,
      purgeable: mp.purgeable ?? 0,
      inactive: mp.inactive ?? 0,
      free: mp.free ?? 0,
      speculative: mp.speculative ?? 0,
    },
  }
  result.processes = processes
  result.killed = processes.filter((p: JetsamProcess) => p.reason != null)
  return result
}

// ─── 事件时间 ───

// JetsamEvent 头部 timestamp 形如 "2026-08-30 21:28:37.00 +0800"，
// 解析为 ISO 字符串供历史记录使用。
export function resolveEventTimestamp(data: JetsamData): string {
  const raw = data.header?.timestamp ?? data.date ?? ""
  if (!raw) return new Date().toISOString()
  // 把 "2026-08-30 21:28:37.00 +0800" 规范成可解析的 ISO 格式
  // （时区 +0800 → +08:00；仅 +08 → +08:00；末尾 Z 原样保留）
  const iso = raw
    .replace(
      /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*([+-]\d{2})(\d{2})?$/i,
      (_all, date: string, time: string, tzHour: string, tzMin?: string) =>
        date + "T" + time + tzHour + ":" + (tzMin || "00"),
    )
    .replace(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*Z$/i, "$1T$2Z")
  const t = new Date(iso).getTime()
  if (isNaN(t)) return new Date().toISOString()
  return new Date(t).toISOString()
}

// ─── 格式化工具 ───

export function fmtBytes(v: number | null | undefined): string | null {
  if (v == null || isNaN(v)) return null
  if (v >= 1e12) return (v / 1e12).toFixed(2) + " TB"
  if (v >= 1e9) return (v / 1e9).toFixed(2) + " GB"
  if (v >= 1e6) return (v / 1e6).toFixed(1) + " MB"
  if (v >= 1e3) return (v / 1e3).toFixed(0) + " KB"
  return v + " B"
}

// 页数 → 字节 → 可读容量
export function pagesBytes(pages: number, pageSize: number): number {
  return pages * pageSize
}

export function fmtPages(pages: number | null | undefined, pageSize: number): string | null {
  if (pages == null) return null
  return fmtBytes(pagesBytes(pages, pageSize))
}

// 纳秒 → 可读时长
export function fmtDuration(ns: number | null | undefined): string | null {
  if (ns == null || isNaN(ns)) return null
  let s = ns / 1e9
  if (s < 1) return (ns / 1e6).toFixed(0) + " 毫秒"
  if (s < 60) return s.toFixed(0) + " 秒"
  const m = Math.floor(s / 60)
  s = Math.floor(s % 60)
  if (m < 60) return m + " 分 " + s + " 秒"
  const h = Math.floor(m / 60)
  const rm = m % 60
  if (h < 24) return h + " 小时 " + rm + " 分"
  const d = Math.floor(h / 24)
  const rh = h % 24
  return d + " 天 " + rh + " 小时"
}

// ─── 日期格式化 ───

const pad2 = (n: number): string => String(n).padStart(2, "0")

// 短格式："M月D日 HH:MM"（用于历史记录列表）
export function fmtDateTimeShort(ts: string | number | Date): string {
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ""
  return (d.getMonth() + 1) + "月" + d.getDate() + "日 " + d.getHours() + ":" + pad2(d.getMinutes())
}

// 完整格式："YYYY/M/D HH:MM"（用于历史详情页）
export function fmtDateTimeFull(ts: string | number | Date): string {
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ""
  return d.getFullYear() + "/" + (d.getMonth() + 1) + "/" + d.getDate() + " " + d.getHours() + ":" + pad2(d.getMinutes())
}
