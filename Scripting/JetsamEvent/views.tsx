// views.tsx -- 公用 JetsamEvent 进程 & 内存 UI 视图组件

import { Navigation, NavigationStack, List, Section, Text, VStack, HStack, ProgressView, Button, Picker, NavigationLink, TextField, useState, useMemo } from "scripting"
import { type JetsamData, type JetsamProcess, type JetsamMemory, fmtPages, fmtDuration, fmtDateTimeFull } from "./parser"
import { type HistoryEntry } from "./history"

// ─── 基础组件 ───

type CardValue = string | number | null | undefined

function Card(props: { cn: string; value: CardValue }) {
  if (props.value === null || props.value === undefined) return null
  let v = String(props.value)
  if (v === "<unknown>" || v === "unknown" || v === "undefined" || v === "null" || v === "NaN") v = "未知"
  if (v.trim() === "") return null
  return (
    <Text font="subheadline" multilineTextAlignment="leading">{props.cn + ":   " + v}</Text>
  )
}

const A = "leading"

// ─── 设备检测 ───

export function detectDevice(product: string, fileName: string): string {
  const p = (product || "").toLowerCase()
  const fnLower = (fileName || "").toLowerCase()
  if (p.startsWith("watch") || fnLower.includes("watch")) return "Watch"
  if (p.startsWith("ipad") || fnLower.includes("ipad")) return "iPad"
  if (p.startsWith("iphone") || fnLower.includes("iphone")) return "iPhone"
  if (p.startsWith("appletv") || p.startsWith("tvos")) return "Apple TV"
  return "未知"
}

export function deviceLabel(type: string): string {
  return type === "iPhone" ? "📱 iPhone" : type === "iPad" ? "📱 iPad" : type === "Watch" ? "⌚ Watch" : type === "Apple TV" ? "📺 Apple TV" : "未知"
}

// 根据 rpages 估算进程内存，页大小 16KB（优先取文件中的 pageSize）
function procMB(p: JetsamProcess, pageSize: number): number {
  return (p.rpages * pageSize) / 1024 / 1024
}

// ─── 内存状态 ───

function MemorySection(props: { memory: JetsamMemory }) {
  const m = props.memory
  const ps = m.pageSize
  const mp = m.memoryPages
  // 注意：memoryPages 各分类是“队列状态”(active/inactive/free/...) 与
  // “页面类型”(fileBacked/anonymous) 的交叉统计，不能相加当“总内存”。
  // 报告里也没有“物理内存总量”字段。
  const freeMB = (mp.free * ps) / 1024 / 1024
  const color = freeMB <= 150 ? "#FF3B30" : freeMB <= 400 ? "#FF9500" : "#34C759"

  return (
    <Section header={<Text>💾 内存状态（被杀瞬间快照）</Text>}>
      <VStack spacing={4} alignment={A}>
        <Text font="caption2" foregroundStyle="#8E8E93">
          ⚠️ 这是 JetsamEvent 生成时刻（杀进程瞬间）的内存快照，非实时数据。报告不含物理内存总量字段。
        </Text>
        <HStack spacing={12} alignment="center">
          <VStack spacing={0} alignment={A} frame={{ maxWidth: "infinity", alignment: "leading" }}>
            <Text font="largeTitle" foregroundStyle={color}>
              {fmtPages(mp.free, ps)}
            </Text>
            <Text font="caption2" foregroundStyle="#8E8E93">空闲内存</Text>
          </VStack>
        </HStack>
        <Card cn="空闲" value={fmtPages(mp.free, ps)} />
        <Card cn="活跃 (active)" value={fmtPages(mp.active, ps)} />
        <Card cn="非活跃 (inactive)" value={fmtPages(mp.inactive, ps)} />
        <Card cn="已固定 (wired)" value={fmtPages(mp.wired, ps)} />
        <Card cn="投机 (speculative)" value={fmtPages(mp.speculative, ps)} />
        <Card cn="受限 (throttled)" value={fmtPages(mp.throttled, ps)} />
        <Card cn="匿名 (anonymous)" value={fmtPages(mp.anonymous, ps)} />
        <Card cn="文件后备 (fileBacked)" value={fmtPages(mp.fileBacked, ps)} />
        <Card cn="可清除 (purgeable)" value={fmtPages(mp.purgeable, ps)} />
        <Card cn="压缩器" value={fmtPages(m.compressorSize, ps)} />
        <Card cn="压缩器中未压缩数据" value={fmtPages(m.uncompressed, ps)} />
        <Card cn="压缩次数" value={m.compressions > 0 ? m.compressions.toLocaleString() : null} />
        <Card cn="解压次数" value={m.decompressions > 0 ? m.decompressions.toLocaleString() : null} />
        <Card cn="最大 Zone" value={m.largestZone ? m.largestZone + " (" + fmtPages(m.largestZoneSize, ps) + ")" : null} />
      </VStack>
    </Section>
  )
}

// ─── 进程详情页（NavigationLink 的 push 目标，不需要 NavigationStack）───

export function ProcessDetailPage(props: { proc: JetsamProcess; pageSize: number }) {
  const { proc, pageSize } = props
  const ps = pageSize || 16384
  const dirty = proc.physicalPages?.internal ? proc.physicalPages.internal[1] : null
  const clean = proc.physicalPages?.internal ? proc.physicalPages.internal[0] : null

  return (
    <List
      navigationTitle={proc.name}
      navigationBarTitleDisplayMode="large"
    >
      <Section header={<Text>📌 基本信息</Text>}>
        <VStack spacing={4} alignment={A}>
          <Card cn="进程名" value={proc.name} />
          <Card cn="PID" value={proc.pid} />
          <Card cn="状态" value={proc.states.length > 0 ? proc.states.join(", ") : null} />
          <Card cn="优先级" value={proc.priority} />
          <Card cn="CPU 时间" value={proc.cpuTime != null ? proc.cpuTime.toFixed(1) + " 秒" : null} />
          <Card cn="文件描述符" value={proc.fds} />
          <Card cn="内存区域" value={proc.mem_regions} />
          <Card cn="存活时长" value={fmtDuration(proc.age)} />
        </VStack>
      </Section>

      <Section header={<Text>💾 内存</Text>}>
        <VStack spacing={4} alignment={A}>
          <Card cn="常驻内存" value={fmtPages(proc.rpages, ps)} />
          <Card cn="历史峰值" value={fmtPages(proc.lifetimeMax, ps)} />
          <Card cn="可清除" value={fmtPages(proc.purgeable, ps)} />
          {clean != null && <Card cn="内部页 (clean)" value={fmtPages(clean, ps)} />}
          {dirty != null && <Card cn="内部页 (dirty)" value={fmtPages(dirty, ps)} />}
          {proc.rpages > 0 && <ProgressView value={Math.min(procMB(proc, ps) / 1024, 1.0)} total={1.0} />}
        </VStack>
      </Section>

      {proc.reason ? (
        <Section header={<Text>⚠️ Jetsam 终止</Text>}>
          <VStack spacing={4} alignment={A}>
            <Text font="subheadline" foregroundStyle="#FF3B30">原因: {proc.reason}</Text>
            <Card cn="距被杀" value={fmtDuration(proc.killDelta)} />
          </VStack>
        </Section>
      ) : null}
    </List>
  )
}

// ─── 被杀进程 ───

export function KilledSection(props: { killed: JetsamProcess[]; pageSize: number }) {
  const { killed, pageSize } = props
  if (killed.length === 0) return null
  return (
    <Section header={<Text>⚠️ 被 Jetsam 终止的进程 ({killed.length})</Text>}>
      {killed.map((p: JetsamProcess, i: number) => (
        <NavigationLink
          key={p.pid ? `${p.name}-${p.pid}` : `${p.name}-${i}`}
          destination={<ProcessDetailPage proc={p} pageSize={pageSize} />}
        >
          <HStack>
            <VStack alignment={A} spacing={2}>
              <Text font="body" foregroundStyle={p.reason ? "#FF3B30" : undefined}>
                {p.name + " (PID " + p.pid + ") · " + fmtPages(p.rpages, pageSize)}
              </Text>
              <Text font="caption2" foregroundStyle="#8E8E93">
                {"被杀原因 " + p.reason + " · 距被杀 " + (fmtDuration(p.killDelta) ?? "-")}
              </Text>
            </VStack>
          </HStack>
        </NavigationLink>
      ))}
    </Section>
  )
}

// ─── 进程列表（支持排序切换） ───

type SortMode = "mem" | "name"

export function ProcessListSection(props: { processes: JetsamProcess[]; pageSize: number }) {
  const { processes, pageSize } = props
  const [sortMode, setSortMode] = useState<SortMode>("mem")
  const [searchText, setSearchText] = useState("")
  if (processes.length === 0) return null

  const query = searchText.trim().toLowerCase()
  const filtered = useMemo(
    () => query
      ? processes.filter((p: JetsamProcess) =>
          p.name.toLowerCase().includes(query) || String(p.pid).includes(query)
        )
      : processes,
    [processes, query]
  )
  const sorted = useMemo(
    () => [...filtered].sort((a, b) => {
      if (sortMode === "name") {
        return a.name.localeCompare(b.name)
      }
      return b.rpages - a.rpages
    }),
    [filtered, sortMode]
  )
  const isMem = sortMode === "mem"
  const showCount = query ? filtered.length : processes.length

  return (
    <Section header={<Text>📋 进程列表 ({showCount} / {processes.length})</Text>}>
      <TextField
        title="搜索"
        prompt="搜索进程名或 PID"
        value={searchText}
        onChanged={setSearchText}
      />
      <Picker
        title="排序方式"
        pickerStyle="menu"
        value={sortMode}
        onChanged={(v: string | number) => setSortMode(v as SortMode)}
      >
        <Text tag="mem">⬇️ 内存占用</Text>
        <Text tag="name">🔤 名称</Text>
      </Picker>
      {query && filtered.length === 0 ? (
        <Text font="subheadline" foregroundStyle="#8E8E93">没有匹配「{searchText}」的进程</Text>
      ) : null}
      {sorted.map((p: JetsamProcess, i: number) => (
        <NavigationLink
          key={p.pid ? `${p.name}-${p.pid}` : `${p.name}-${i}`}
          destination={<ProcessDetailPage proc={p} pageSize={pageSize} />}
        >
          <HStack>
            <VStack alignment={A} spacing={2}>
              <Text font="body" foregroundStyle={p.reason ? "#FF3B30" : undefined}>
                {(isMem ? "#" + (i + 1) + "  " : "") + p.name + " (PID " + p.pid + ") · " + fmtPages(p.rpages, pageSize)}
              </Text>
              <Text font="caption2" foregroundStyle="#8E8E93">
                {"峰值 " + (fmtPages(p.lifetimeMax, pageSize) ?? "N/A") + " · 状态 " + (p.states.length > 0 ? p.states.join(", ") : "-") + (p.reason ? " · ⚠️ " + p.reason : "")}
              </Text>
            </VStack>
          </HStack>
        </NavigationLink>
      ))}
    </Section>
  )
}

// ─── 数据概览 ───

function OverviewSection(props: { data: JetsamData; fileName: string }) {
  const { data, fileName } = props
  const dtype = detectDevice(data.product, fileName)
  return (
    <Section header={<Text>📊 数据概览</Text>}>
      <VStack spacing={4} alignment={A}>
        <Card cn="设备类型" value={deviceLabel(dtype)} />
        <Card cn="产品型号" value={data.product || null} />
        <Card cn="系统版本" value={data.build || null} />
        <Card cn="内核" value={data.kernel || null} />
        <Card cn="事件时间 (被杀时刻)" value={data.date || null} />
        <Card cn="文件" value={fileName} />
        <Card cn="进程总数" value={data.processes.length > 0 ? data.processes.length + " 个" : null} />
        <Card cn="被杀进程" value={data.killed.length > 0 ? data.killed.length + " 个" : "0 个 ✅"} />
        <Card cn="最大进程" value={data.largestProcess || null} />
      </VStack>
    </Section>
  )
}

// ─── 公用：分析内容（不含导航壳，供 index.tsx 嵌套使用）───

export function AnalysisSections(props: { data: JetsamData; fileName: string; recordTime?: string }) {
  const { data, fileName } = props
  return (
    <>
      {props.recordTime ? (
        <Section header={<Text>🕐 记录时间</Text>}>
          <Text font="subheadline">{props.recordTime}</Text>
        </Section>
      ) : null}
      <OverviewSection data={data} fileName={fileName} />
      <MemorySection memory={data.memory} />
      <KilledSection killed={data.killed} pageSize={data.memory.pageSize} />
      <ProcessListSection processes={data.processes} pageSize={data.memory.pageSize} />
    </>
  )
}

// ─── 完整页面（含导航壳，供 intent.tsx 使用）───

export function AnalysisPage(props: { data: JetsamData; fileName: string }) {
  const dismiss = Navigation.useDismiss()
  const { data, fileName } = props
  const dtype = detectDevice(data.product, fileName)
  const label = deviceLabel(dtype)

  return (
    <NavigationStack>
      <List
        navigationTitle={label + " Jetsam 分析"}
        navigationBarTitleDisplayMode="large"
        toolbar={{ cancellationAction: <Button title="关闭" systemImage="pencil.slash" action={dismiss} /> }}
      >
        {data.processes.length > 0 ? (
          <AnalysisSections data={data} fileName={fileName} />
        ) : (
          <Section header={<Text>⚠️ 无进程数据</Text>}>
            <Text font="subheadline" foregroundStyle="#FF3B30">未在文件中找到进程信息</Text>
          </Section>
        )}
      </List>
    </NavigationStack>
  )
}

// ─── 历史记录详情页 ───

export function HistoryDetailPage(props: { entry: HistoryEntry }) {
  const dismiss = Navigation.useDismiss()
  const { entry } = props
  const dtype = detectDevice(entry.data.product, entry.fileName)
  const label = deviceLabel(dtype)
  const dateStr = fmtDateTimeFull(entry.timestamp)

  return (
    <NavigationStack>
      <List
        navigationTitle={label + " Jetsam 历史"}
        navigationBarTitleDisplayMode="large"
        toolbar={{ cancellationAction: <Button title="关闭" systemImage="pencil.slash" action={dismiss} /> }}
      >
        {entry.data.processes.length > 0 ? (
          <AnalysisSections data={entry.data} fileName={entry.fileName} recordTime={dateStr} />
        ) : (
          <Section header={<Text>⚠️ 无进程数据</Text>}>
            <Text font="subheadline" foregroundStyle="#FF3B30">未在文件中找到进程信息</Text>
          </Section>
        )}
      </List>
    </NavigationStack>
  )
}
