// views.tsx -- 公用电池 & 硬件健康 UI 视图组件

import { Navigation, NavigationStack, List, Section, Text, VStack, HStack, ProgressView, Button, DisclosureGroup, TextField, useState, modifiers } from "scripting"
import { type ParsedData, fmtBytes, fmtKB } from "./parser"
import { type HistoryEntry, loadHistory, deleteHistoryEntry } from "./history"

// ─── 基础组件 ───

function Card(props: { cn: string; value: any }) {
  if (props.value === null || props.value === undefined) return null
  let v = String(props.value)
  if (v === "<unknown>" || v === "unknown" || v === "undefined" || v === "null" || v === "NaN") v = "未知"
  if (v.trim() === "") return null
  return (
    <Text font="subheadline" multilineTextAlignment="leading">{props.cn + ":   " + v}</Text>
  )
}

const A = "leading"

// ─── 设备检测（统一逻辑） ───

export function detectDevice(meta: Record<string, any>, fileName: string): string {
  const osVer = (meta.os_version || "").toLowerCase()
  const fnLower = fileName.toLowerCase()
  if (osVer.includes("watch os") || fnLower.includes("watch")) return "Watch"
  if (osVer.includes("iphone os") || fnLower.includes("iphone")) return "iPhone"
  return "未知"
}

function deviceLabel(type: string): string {
  return type === "iPhone" ? "📱 iPhone" : type === "Watch" ? "⌚ Watch" : "未知"
}

// ─── 设备信息 ───

function DeviceInfoSection(props: { meta: Record<string, any>; extra: Record<string, any>; fileName: string }) {
  const { meta, extra, fileName } = props
  const osVer = meta.os_version || "未知"
  const deviceType = detectDevice(meta, fileName)

  return (
    <Section header={<Text>📱 设备信息</Text>}>
      <VStack spacing={4} alignment={A}>
        <Card cn="设备类型" value={deviceType} />
        <Card cn="系统版本" value={osVer} />
        {extra.productSku && <Card cn="地区型号" value={extra.productSku} />}
        {extra.deviceCapacity && <Card cn="存储容量" value={extra.deviceCapacity + " GB"} />}
        {extra.dramSize && <Card cn="内存" value={extra.dramSize + " GB"} />}
        {extra.currentCountry && <Card cn="当前国家" value={extra.currentCountry} />}
        {extra.market && <Card cn="市场" value={extra.market} />}
        {extra.homeCarrierName && <Card cn="运营商" value={extra.homeCarrierName} />}
        {meta.timestamp && <Card cn="采集时间" value={meta.timestamp} />}
      </VStack>
    </Section>
  )
}

// ─── 电池配置 ───

function BatteryConfigSection(props: { m: Record<string, any>; vac: Record<string, any> | null }) {
  const m = props.m
  const vac = props.vac
  const rawMaxCap = m.last_value_AppleRawMaxCapacity
  const nomCap = m.last_value_NominalChargeCapacity
  const hm = m.last_value_BatteryHealthMetric
  const qmaxCell0 = m.last_value_QmaxCell0
  const maxCapPct = m.last_value_MaximumCapacityPercent

  const calcHealth = (rawMaxCap != null && nomCap != null && nomCap > 0)
    ? ((nomCap / rawMaxCap) * 100).toFixed(1) : null
  const calcNum = calcHealth != null ? parseFloat(calcHealth) / 100 : 0

  const [customDesignCap, setCustomDesignCap] = useState("")
  const customDesignNum = parseFloat(customDesignCap)
  const customHealth = (!isNaN(customDesignNum) && customDesignNum > 0 && qmaxCell0 != null && qmaxCell0 > 0)
    ? ((qmaxCell0 / customDesignNum) * 100).toFixed(1) : null

  const nccMax = m.last_value_NCCMax

  // 用 Apple 内部最大容量百分比反推原始设计容量，没有时用 NCCMax 当出厂值
  const deducedDesignCap = (maxCapPct != null && maxCapPct > 0 && rawMaxCap != null)
    ? (rawMaxCap / (maxCapPct / 100))
    : (nccMax != null && nccMax > 0 ? nccMax : null)
  const qmaxHealth = (qmaxCell0 != null && deducedDesignCap != null && deducedDesignCap > 0)
    ? ((qmaxCell0 / deducedDesignCap) * 100).toFixed(1) : null
  const usedNccMax = deducedDesignCap != null && (maxCapPct == null || maxCapPct <= 0 || rawMaxCap == null)

  // 有自定义设计容量时替换估算健康度
  const displayHealth = customHealth ?? qmaxHealth
  const displayNum = displayHealth != null ? parseFloat(displayHealth) / 100 : 0
  const captionText = "估算健康度"

  return (
    <>
      <Section header={<Text>🔋 电池核心指标</Text>}>
        <VStack spacing={4} alignment={A}>
          <HStack alignment="center" spacing={16}>
            <VStack spacing={0} alignment={A}
              frame={{ maxWidth: "infinity", alignment: "leading" }}
            >
              <Text font="largeTitle" foregroundStyle={displayNum >= 0.8 ? "#34C759" : displayNum >= 0.6 ? "#FF9500" : "#FF3B30"}>
                {displayHealth != null ? "≈ " + displayHealth + "%" : "N/A"}
              </Text>
              <Text font="caption2" foregroundStyle="#8E8E93">{captionText}</Text>
            </VStack>
            <VStack
              modifiers={modifiers().padding(4)}
            >
              <TextField
                title="设计容量"
                prompt="修正原始容量"
                value={customDesignCap}
                onChanged={setCustomDesignCap}
              />
            </VStack>
          </HStack>
          {displayNum > 0 && <ProgressView value={Math.min(displayNum, 1.0)} total={1.0} />}
          <Card cn="苹果内部电池健康评分" value={hm != null ? (hm > 100 ? (hm / 10).toFixed(1) : hm) : null} />
          <Card cn="苹果内部最大容量百分比" value={m.last_value_MaximumCapacityPercent != null ? m.last_value_MaximumCapacityPercent + "%" : null} />
          {deducedDesignCap != null && <Card cn={usedNccMax ? "NCCMax 出厂值" : "推算原始设计容量"} value={deducedDesignCap.toFixed(0) + " mAh"} />}
          {qmaxHealth != null && <Card cn="Qmax 推算健康度" value={qmaxHealth + "%"} />}
          <Card cn="循环次数" value={m.last_value_CycleCount != null ? m.last_value_CycleCount + " 次" : null} />
          <Card cn="序列变更" value={m.last_value_BatterySerialChanged != null ? (m.last_value_BatterySerialChanged ? "是 ⚠️" : "否 ✅") : null} />
          {m.last_value_DOFU != null && <Card cn="首次使用日期" value={(() => { const d = new Date(m.last_value_DOFU * 1000); return d.getFullYear() + "年" + (d.getMonth() + 1) + "月" + d.getDate() + "日" })()} />}
          {m.last_value_WeekMfd != null && <Card cn="制造周期" value={(() => { const w = String(m.last_value_WeekMfd); const year = 2020 + parseInt(w[0]); const week = parseInt(w.slice(1)); return year + "年 第" + week + "周" })()} />}
          {m.last_value_TotalOperatingTime != null && <Card cn="总运行时间" value={m.last_value_TotalOperatingTime + " 小时"} />}
        </VStack>
      </Section>

      <Section header={<Text>⚡ 容量</Text>}>
        <VStack spacing={4} alignment={A}>
          <Card cn="当前最大可用容量" value={nomCap != null ? nomCap + " mAh" : null} />
          <Card cn="当前标称容量" value={rawMaxCap != null ? rawMaxCap + " mAh" : null} />
          <Card cn="最大满充容量" value={m.last_value_MaximumFCC != null ? m.last_value_MaximumFCC + " mAh" : null} />
          <Card cn="最小满充容量" value={m.last_value_MinimumFCC != null ? m.last_value_MinimumFCC + " mAh" : null} />
          <Card cn="电芯最大容量估计" value={m.last_value_QmaxCell0 != null ? m.last_value_QmaxCell0 + " mAh" : null} />
          <Card cn="最大 Qmax" value={m.last_value_MaximumQmax != null ? m.last_value_MaximumQmax + " mAh" : null} />
          <Card cn="最小 Qmax" value={m.last_value_MinimumQmax != null ? m.last_value_MinimumQmax + " mAh" : null} />
          <Card cn="净库仑计数范围" value={m.last_value_NCCMax != null && m.last_value_NCCMin != null ? m.last_value_NCCMin + " ~ " + m.last_value_NCCMax + " mAh" : null} />
          <Card cn="日常 SoC 范围" value={m.last_value_DailyMaxSoc != null && m.last_value_DailyMinSoc != null ? m.last_value_DailyMinSoc + "% ~ " + m.last_value_DailyMaxSoc + "%" : null} />
        </VStack>
      </Section>

      <Section header={<Text>⚡ 电压 / 电流 / 温度</Text>}>
        <VStack spacing={4} alignment={A}>
          <Card cn="电池电压范围" value={m.last_value_MaximumPackVoltage != null && m.last_value_MinimumPackVoltage != null ? (m.last_value_MinimumPackVoltage / 1000).toFixed(3) + " ~ " + (m.last_value_MaximumPackVoltage / 1000).toFixed(3) + " V" : null} />
          <Card cn="最大充电电流" value={m.last_value_MaximumChargeCurrent != null ? m.last_value_MaximumChargeCurrent + " mA" : null} />
          <Card cn="最大放电电流" value={m.last_value_MaximumDischargeCurrent != null ? Math.abs(m.last_value_MaximumDischargeCurrent) + " mA" : null} />
          <Card cn="温度范围" value={m.last_value_MinimumTemperature != null && m.last_value_MaximumTemperature != null ? (m.last_value_MinimumTemperature / 10).toFixed(1) + " ~ " + (m.last_value_MaximumTemperature / 10).toFixed(1) + "°C" : null} />
          <Card cn="平均温度" value={m.last_value_AverageTemperature != null ? m.last_value_AverageTemperature + "°C" : null} />
          {vac && vac.last_value_VacVoltageLimit != null && <Card cn="充电限制电压" value={(vac.last_value_VacVoltageLimit / 1000).toFixed(3) + " V"} />}
        </VStack>
      </Section>

    </>
  )
}

// ─── 电化学核心 ───

function AlgoSection(props: { algo: Record<string, any>; config: Record<string, any> | null; obc: Record<string, any> | null; obcNoRot: Record<string, any> | null; pred: Record<string, any>[] }) {
  const m = props.algo
  const c = props.config
  const o = props.obc
  const onr = props.obcNoRot
  const pred = props.pred
  return (
    <Section header={<Text>🧬 电化学核心</Text>}>
      <VStack spacing={4} alignment={A}>
        {/* 电化学容量 */}
        <Card cn="化学最大容量" value={m.sum_of_Qmax != null ? (m.sum_of_Qmax * 1000).toFixed(0) + " mAh" : null} />
        <Card cn="活性锂离子存量" value={m.sum_of_QLi != null ? (m.sum_of_QLi * 100).toFixed(2) + "%" : null} />
        <Card cn="负极活性材料保有率" value={m.sum_of_Qn != null ? (m.sum_of_Qn * 100).toFixed(2) + "%" : null} />
        <Card cn="正极活性材料保有率" value={m.sum_of_Qp != null ? (m.sum_of_Qp * 100).toFixed(2) + "%" : null} />
        <Card cn="净库仑计数" value={m.sum_of_NCCp != null ? (m.sum_of_NCCp * 1000).toFixed(0) + " mAh" : null} />
        <Card cn="硬膨胀" value={m.sum_of_hardSwell} />
        <Card cn="保护缓冲区" value={m.sum_of_protectiveBuffer != null ? (m.sum_of_protectiveBuffer * 100).toFixed(2) + "%" : null} />
        <Card cn="SOC 范围" value={m.sum_of_x0 != null && m.sum_of_x100 != null ? (m.sum_of_x0 * 100).toFixed(2) + "% → " + (m.sum_of_x100 * 100).toFixed(2) + "%" : null} />
        <Card cn="SOH 范围" value={m.sum_of_y0 != null && m.sum_of_y100 != null ? (m.sum_of_y0 * 100).toFixed(2) + "% → " + (m.sum_of_y100 * 100).toFixed(2) + "%" : null} />
        {/* 阻抗（来自 BatteryConfig）*/}
        {c && <Card cn="化学加权内阻" value={c.last_value_ChemicalWeightedRa != null ? c.last_value_ChemicalWeightedRa + " mΩ" : null} />}
        {c && <Card cn="加权平均内阻" value={c.last_value_WeightedRa != null ? c.last_value_WeightedRa + " mΩ" : null} />}
        {c && <Card cn="电池内阻" value={c.last_value_RSS != null ? c.last_value_RSS + " mΩ" : null} />}
        <Card cn="内阻变化比" value={m.sum_of_wRaChangeRatio != null ? (m.sum_of_wRaChangeRatio * 100).toFixed(2) + "%" : null} />
        {/* OBC 充电优化 */}
        {o && <Card cn="循环计数" value={o.sum_of_CycleCount != null ? o.sum_of_CycleCount + " 次" : null} />}
        {o && <Card cn="完整充电次数" value={o.sum_of_LifetimeEngagements} />}
        {o && <Card cn="完整空闲时长" value={o.sum_of_LifetimeIdleDurationMins != null ? o.sum_of_LifetimeIdleDurationMins + " 分钟" : null} />}
        {/* OBC 无轮换 */}
        {onr && <Card cn="无轮换循环计数" value={onr.message?.last_value_CycleCount != null ? onr.message.last_value_CycleCount + " 次" : null} />}
        {onr && <Card cn="无轮换完整充电" value={onr.message?.last_value_LifetimeEngagements} />}
        {/* 模型预测误差 */}
        {pred.map((r: Record<string, any>, i: number) => {
          const pm = r.message || {}
          const predErr = pm.sum_of_prediction_error
          const absErr = pm.sum_of_prediction_error_absolute
          const outputName = pm.prediction_output_name
          const nameLC = (outputName || "").toLowerCase()
          const isAbsolute = nameLC.includes("wra")
          const label = nameLC.includes("nccp") ? "净库仑计数"
            : nameLC.includes("qmaxp") ? "最大化学容量"
            : isAbsolute ? "加权阻抗"
            : outputName
          const errStr = predErr != null
            ? (isAbsolute
              ? (predErr > 0 ? "+" : "") + predErr.toFixed(2) + " mΩ"
              : (predErr > 0 ? "+" : "") + (predErr * 100).toFixed(2) + "%")
            : "N/A"
          const absStr = absErr != null
            ? (isAbsolute ? absErr.toFixed(2) + " mΩ" : (absErr * 100).toFixed(2) + "%")
            : "N/A"
          return <Card key={i} cn={label + " 预测误差"} value={errStr + " (" + absStr + ")"} />
        })}
      </VStack>
    </Section>
  )
}

// ─── NAND 存储 ───

function NANDSection(props: { m: Record<string, any> }) {
  const m = props.m
  // NAND 底层计算
  const vblocks = m.sum_of_numVirtualBlocks || 0
  const pagesPerVBlock = m.sum_of_pagesPerVirtualBlock || 0
  const bytesPerPage = m.sum_of_bytesPerPage || 16384
  const blocksPerVBlock = m.sum_of_blocksPerVirtualBlock || 0
  const factoryBad = m.sum_of_numFactoryBad || 0
  const grownBad = m.sum_of_numGrownBad || 0
  const totalManageable = vblocks * pagesPerVBlock * bytesPerPage
  const pagesPerPBlock = blocksPerVBlock > 0 ? pagesPerVBlock / blocksPerVBlock : 0
  const pBlockSize = pagesPerPBlock * bytesPerPage
  const factoryBadGB = factoryBad * pBlockSize / 1e9
  const grownBadGB = grownBad * pBlockSize / 1e9

  return (
    <Section header={<Text>💾 NAND 存储健康</Text>}>
      <VStack spacing={4} alignment={A}>
        {/* 容量与结构 */}
        <Card cn="FTL 可管理容量" value={totalManageable > 0 ? (totalManageable / 1e9).toFixed(2) + " GB" : null} />
        <Card cn="虚拟块数量" value={vblocks > 0 ? vblocks + " 个" : null} />
        <Card cn="每虚拟块页数" value={pagesPerVBlock > 0 ? pagesPerVBlock.toLocaleString() + " 页" : null} />
        <Card cn="每页大小" value={bytesPerPage > 0 ? (bytesPerPage / 1024) + " KB" : null} />
        <Card cn="每物理块容量" value={pBlockSize > 0 ? (pBlockSize / 1e6).toFixed(2) + " MB" : null} />
        <Card cn="出厂坏块容量" value={factoryBad > 0 ? factoryBad + " 个 ≈ " + factoryBadGB.toFixed(2) + " GB" : null} />
        <Card cn="新增坏块容量" value={grownBad > 0 ? grownBad + " 个 ≈ " + grownBadGB.toFixed(2) + " GB" : ("0 个 ✅")} />
        {/* 健康状态 */}
        <Card cn="NAND 寿命消耗" value={m.sum_of_percentUsed != null ? m.sum_of_percentUsed + "%" : null} />
        <Card cn="SLC 寿命消耗" value={m.sum_of_slcPercentUsed != null ? m.sum_of_slcPercentUsed + "%" : null} />
        <Card cn="可用备用块" value={m.sum_of_spareAvailablePercent != null ? m.sum_of_spareAvailablePercent + "%" : null} />
        {/* 读写量 */}
        <Card cn="主机读取量" value={fmtKB(m.sum_of_hostReads)} />
        <Card cn="主机写入量" value={fmtKB(m.sum_of_hostWrites)} />
        <Card cn="NAND 读取量" value={fmtKB(m.sum_of_nandReads)} />
        <Card cn="NAND 写入量" value={fmtKB(m.sum_of_nandWrites)} />
        {/* 运行统计 */}
        <Card cn="通电时长" value={m.sum_of_powerOnHours != null ? m.sum_of_powerOnHours + " 小时" : null} />
        <Card cn="启动次数" value={m.sum_of_boots} />
        <Card cn="异常关机次数" value={m.sum_of_uncleanBoots} />
        <Card cn="SLC 平均擦写" value={m.sum_of_averageSLCPECycles} />
        <Card cn="TLC 平均擦写" value={m.sum_of_averageTLCPECycles} />
        <Card cn="总擦除次数" value={m.sum_of_bandErases} />
        <Card cn="主机限流次数" value={m.sum_of_numHostChoke} />
        <Card cn="GC 写入量" value={fmtKB(m.sum_of_gcWrites)} />
      </VStack>
    </Section>
  )
}

// ─── 磁盘空间 ───

function DiskSection(props: { m: Record<string, any> }) {
  const m = props.m
  const count = m.Count || 1
  return (
    <Section header={<Text>💿 磁盘空间</Text>}>
      <VStack spacing={4} alignment={A}>
        <Card cn="总容量" value={fmtBytes(m.sum_of_dailyTotalBytesRoot != null ? m.sum_of_dailyTotalBytesRoot / count : null)} />
        <Card cn="可用空间" value={fmtBytes(m.sum_of_dailyFreeBytesRoot != null ? m.sum_of_dailyFreeBytesRoot / count : null)} />
        <Card cn="可清除空间" value={fmtBytes(m.sum_of_dailyPurgeableBytesTot != null ? m.sum_of_dailyPurgeableBytesTot / count : null)} />
      </VStack>
    </Section>
  )
}

// ─── 电池 Section 汇总 ───

function BatterySections(props: { battery: Record<string, any>[] }) {
  const { battery } = props
  const config = battery.find((r: Record<string, any>) => r.name === "BatteryConfigValueHistogram_WithAllSafetyKeys_V2")
    || battery.find((r: Record<string, any>) => r.name === "BatteryConfigValueHistogramFinal_V2")
  const algo = battery.find((r: Record<string, any>) => r.name === "BatteryAlgorithms_OnDeviceACAM")
  const obc = battery.find((r: Record<string, any>) => r.name === "OBC_Battery_Health_v3")
  const obcNoRot = battery.find((r: Record<string, any>) => r.name === "OBCNoRotationBatteryHealthMetricsv2")
  const pred = battery.filter((r: Record<string, any>) => r.name === "Battery_Health_Delta_Prediction_Errors_Aggregate")

  const vac = battery.find((r: Record<string, any>) => r.name === "VacVoltageLimit")

  return (
    <>
      {config && <BatteryConfigSection m={config.message} vac={vac ? vac.message : null} />}
      {algo && <AlgoSection algo={algo.message} config={config ? config.message : null} obc={obc ? obc.message : null} obcNoRot={obcNoRot ? obcNoRot : null} pred={pred} />}
    </>
  )
}

// ─── 公用：分析内容（不含导航壳，供 index.tsx 嵌套使用）───

export function AnalysisSections(props: { data: ParsedData; fileName: string; recordTime?: string }) {
  const { data, fileName } = props
  const dtype = detectDevice(data.metadata, fileName)
  const label = deviceLabel(dtype)

  return (
    <>
      <Section header={<Text>📊 数据概览</Text>}>
        <Text font="subheadline">文件: {fileName}</Text>
        {props.recordTime ? <Text font="subheadline">记录时间: {props.recordTime}</Text> : undefined}
      </Section>
      <DeviceInfoSection meta={data.metadata} extra={data.metaExtra} fileName={fileName} />
      <BatterySections battery={data.battery} />
      {data.nand && <NANDSection m={data.nand.message} />}
    </>
  )
}

// ─── 完整页面（含导航壳，供 intent.tsx 使用）───

export function AnalysisPage(props: { data: ParsedData; fileName: string }) {
  const dismiss = Navigation.useDismiss()
  const { data, fileName } = props
  const dtype = detectDevice(data.metadata, fileName)
  const label = deviceLabel(dtype)

  return (
    <NavigationStack>
      <List
        navigationTitle={label + " 电池 & 硬件分析"}
        navigationBarTitleDisplayMode="large"
        toolbar={{ cancellationAction: <Button title="关闭" systemImage="pencil.slash" action={dismiss} /> }}
      >
        {data.battery.length > 0 ? (
          <AnalysisSections data={data} fileName={fileName} />
        ) : (
          <Section header={<Text>⚠️ 无电池数据</Text>}>
            <Text font="subheadline" foregroundStyle="#FF3B30">未在文件中找到电池硬件记录</Text>
          </Section>
        )}
      </List>
    </NavigationStack>
  )
}

// ─── 历史记录列表 ───

export function HistorySection(props: { onSelect: (entry: HistoryEntry) => void }) {
  const [history, setHistory] = useState(loadHistory())
  const [expanded, setExpanded] = useState(false)

  if (history.length === 0) return null

  const handleDelete = (index: number) => {
    setHistory(deleteHistoryEntry(history, index))
  }

  return (
    <DisclosureGroup
      label={<Text font="headline">📋 历史记录 ({history.length})</Text>}
      isExpanded={expanded}
      onChanged={setExpanded}
    >
      <VStack spacing={4} alignment={A}>
        {history.map((entry: HistoryEntry, i: number) => {
          const dt = detectDevice(entry.data.metadata, entry.fileName)
          const dlabel = deviceLabel(dt)
          const date = new Date(entry.timestamp)
          const dateStr = (date.getMonth() + 1) + "月" + date.getDate() + "日 " + date.getHours() + ":" + String(date.getMinutes()).padStart(2, "0")
          const batCount = entry.data.battery.length
          const hasNand = !!entry.data.nand
          const hasDisk = !!entry.data.disk
          return (
            <VStack key={i} spacing={2} alignment={A}>
              <Button title={dlabel + " | " + dateStr + " | " + batCount + "条" + (hasNand ? " ·NAND" : "") + (hasDisk ? " ·磁盘" : "")} action={() => props.onSelect(entry)} />
              <Button title="删除" foregroundStyle="#FF3B30" action={() => handleDelete(i)} />
            </VStack>
          )
        })}
      </VStack>
    </DisclosureGroup>
  )
}

// ─── 历史记录详情页 ───

export function HistoryDetailPage(props: { entry: HistoryEntry }) {
  const dismiss = Navigation.useDismiss()
  const { entry } = props
  const dtype = detectDevice(entry.data.metadata, entry.fileName)
  const label = deviceLabel(dtype)
  const date = new Date(entry.timestamp)
  const dateStr = date.getFullYear() + "/" + (date.getMonth() + 1) + "/" + date.getDate() + " " + date.getHours() + ":" + String(date.getMinutes()).padStart(2, "0")

  return (
    <NavigationStack>
      <List
        navigationTitle={label + " 历史记录"}
        navigationBarTitleDisplayMode="large"
        toolbar={{ cancellationAction: <Button title="关闭" systemImage="pencil.slash" action={dismiss} /> }}
      >
        {entry.data.battery.length > 0 ? (
          <AnalysisSections data={entry.data} fileName={entry.fileName} recordTime={dateStr} />
        ) : (
          <Section header={<Text>⚠️ 无电池数据</Text>}>
            <Text font="subheadline" foregroundStyle="#FF3B30">未在文件中找到电池硬件记录</Text>
          </Section>
        )}
      </List>
    </NavigationStack>
  )
}
