// parser.ts — 公用 .synced 文件解析逻辑

const BATTERY_TARGETS = [
  "BatteryConfigValueHistogram_WithAllSafetyKeys_V2",
  "BatteryConfigValueHistogramFinal_V2",
  "BatteryAlgorithms_OnDeviceACAM",
  "OBC_Battery_Health_v3",
  "OBCNoRotationBatteryHealthMetricsv2",
  "Battery_Health_Delta_Prediction_Errors_Aggregate",
  "VacVoltageLimit",
]
const NAND_TARGETS = ["massStorage_NANDInfo_FTLCounters_1"]
const DISK_TARGETS = ["diskfullness1"]

export interface ParsedData {
  metadata: Record<string, any>
  metaExtra: Record<string, any>
  battery: Record<string, any>[]
  nand: Record<string, any> | null
  disk: Record<string, any> | null
}

export function parseContent(content: string): ParsedData {
  const lines = content.split("\n").filter((l: string) => l.trim())
  let metadata: Record<string, any> = {}
  let metaExtra: Record<string, any> = {}
  const battery: Record<string, any>[] = []
  let nand: Record<string, any> | null = null
  let disk: Record<string, any> | null = null

  for (let i = 0; i < lines.length; i++) {
    try {
      const obj = JSON.parse(lines[i])
      if (i === 0 && obj.os_version) metadata = obj
      if (i === 1 && obj._marker === "<metadata>") metaExtra = obj
      if (BATTERY_TARGETS.includes(obj.name)) battery.push(obj)
      if (NAND_TARGETS.includes(obj.name) && !nand) nand = obj
      if (DISK_TARGETS.includes(obj.name) && !disk) disk = obj
    } catch {}
  }
  return { metadata, metaExtra, battery, nand, disk }
}

export function parseFile(fileName: string): ParsedData {
  const filePath = FileManager.iCloudDocumentsDirectory + "/scripts/分析电池/" + fileName
  try {
    const content = FileManager.readAsStringSync(filePath)
    return parseContent(content)
  } catch {
    return { metadata: {}, metaExtra: {}, battery: [], nand: null, disk: null }
  }
}

export function fmtBytes(v: number | null | undefined): string | null {
  if (v == null) return null
  if (v >= 1e12) return (v / 1e12).toFixed(2) + " TB"
  if (v >= 1e9) return (v / 1e9).toFixed(2) + " GB"
  if (v >= 1e6) return (v / 1e6).toFixed(1) + " MB"
  return v + " B"
}

// Apple 日志中 NAND/host 读写量单位是 KB
export function fmtKB(v: number | null | undefined): string | null {
  if (v == null) return null
  const bytes = v * 1024
  if (bytes >= 1e12) return (bytes / 1e12).toFixed(2) + " TB"
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + " GB"
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + " MB"
  return v + " KB"
}
