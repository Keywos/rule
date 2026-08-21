//日照时间
export async function fetchTodayDaylight(): Promise<string | undefined> {
  const unit = HealthUnit.minute()
  const start = new Date()
  start.setHours(0, 0, 0, 0)
  const end = new Date()
  const list = await Health.queryQuantitySamples("timeInDaylight", {
    startDate: start,
    endDate: end,
  })
  const total = list.reduce((sum, item) => sum + item.quantityValue(unit), 0)
  return total ? `日照${Math.round(total)}m` : undefined
}

// 手腕温度
export async function fetchLatestWristTemperature(): Promise<string | undefined> {
  try {
    const list = await Health.queryQuantitySamples("appleSleepingWristTemperature", {
      limit: 1,
      sortDescriptors: [
        {
          key: "startDate",
          order: "reverse",
        },
      ],
    })
    if (!list || list.length === 0) return undefined
    const value = list[0].quantityValue(HealthUnit.degreeCelsius())
    if (!Number.isFinite(value)) return undefined
    return `  ${Math.round(value * 10) / 10}℃`
  } catch (err) {
    console.warn("读取手腕温度失败:", err)
    return undefined
  }
}

export async function fetchTodayHRVHourly(): Promise<{
  avg: number | null
  first: number | null
  list: number[]
}> {
  const unitMs = HealthUnit.secondUnit(HealthMetricPrefix.milli)
  async function queryDay(start: Date, end: Date) {
    const samples = await Health.queryQuantitySamples("heartRateVariabilitySDNN", {
      startDate: start,
      endDate: end,
      sortDescriptors: [
        {
          key: "startDate",
          order: "forward",
        },
      ],
    })

    const sum = Array(12).fill(0)
    const count = Array(12).fill(0)
    let total = 0
    let sampleCount = 0
    let latest: number | null = null

    for (const item of samples) {
      const value = Math.round(item.quantityValue(unitMs))
      if (!Number.isFinite(value)) continue

      latest = value
      total += value
      sampleCount++
      const index = item.startDate.getHours ? Math.floor(item.startDate.getHours() / 2) : Math.floor(new Date(item.startDate).getHours() / 2)

      sum[index] += value
      count[index]++
    }

    const avgList = Array.from({ length: 12 }, (_, i) => (count[i] ? Math.round(sum[i] / count[i]) : 0))

    // console.log(avgList)
    return {
      hasData: sampleCount > 0,
      avg: sampleCount ? Math.round(total / sampleCount) : null,
      first: latest,
      list: avgList,
    }
  }

  const todayStart = new Date()
  todayStart.setHours(0, 0, 0, 0)
  const tomorrow = new Date(todayStart)
  tomorrow.setDate(tomorrow.getDate() + 1)

  const start = new Date()
  start.setHours(0, 0, 0, 0)
  for (let day = 0; day < 3; day++) {
    const end = new Date(start)
    end.setDate(end.getDate() + 1)
    const result = await queryDay(start, end)
    if (result.hasData) {
      return {
        avg: result.avg,
        first: result.first,
        list: result.list,
      }
    }
    start.setDate(start.getDate() - 1)
  }

  return {
    avg: null,
    first: null,
    list: new Array(12).fill(0),
  }
}

export type LatestAndBaseline = {
  latest: number | null
  baseline7d: number | null
  hrvlist?: number[] | null
  base24h?: number[] | null
}

//获取最新心率
export async function fetchLatestHeartRate(): Promise<number | null> {
  // 等价 bpm：count/minute
  const bpm = HealthUnit.count().divided(HealthUnit.minute())
  const list = await Health.queryQuantitySamples("heartRate", {
    limit: 1,
    sortDescriptors: [{ key: "startDate", order: "reverse" }],
  })
  if (list.length === 0) return null
  try {
    return list[0].quantityValue(bpm)
  } catch {
    return null
  }
}
// 24h 心率
export async function fetchHeartRateBaseline24h(): Promise<{
  avg: number | null
  list: number[]
}> {
  const bpm = HealthUnit.count().divided(HealthUnit.minute())

  const todayStart = new Date()
  todayStart.setHours(0, 0, 0, 0)

  async function fetchDayBuckets(start: Date): Promise<number[]> {
    const end = new Date(start)
    end.setDate(end.getDate() + 1)

    const coll = await Health.queryStatisticsCollection("heartRate", {
      startDate: start,
      endDate: end,
      anchorDate: start,
      intervalComponents: new DateComponents({
        hour: 2,
      }),
      statisticsOptions: ["discreteAverage"],
    })

    // 12 个 2 小时桶，默认 0
    const result = Array.from({ length: 12 }, () => 0)

    const stats = coll.statistics() ?? []

    for (const stat of stats) {
      const avg = stat.averageQuantity(bpm)

      if (typeof avg !== "number" || isNaN(avg)) {
        continue
      }

      // 根据真实时间计算属于第几个 2 小时段
      const hour = stat.startDate.getHours()
      const index = Math.floor(hour / 2)

      if (index >= 0 && index < 12) {
        result[index] = Math.round(avg)
      }
    }

    // 输出日志
    // result.forEach((value, i) => {
    //   const startHour = i * 2
    //   const endHour = startHour + 2

    //   const timeLabel =
    //     `${String(startHour).padStart(2, "0")}:00-` +
    //     `${String(endHour).padStart(2, "0")}:00`

    // console.log(`[HeartRate ${timeLabel}]`, value)
    // })

    // console.log("[心率]", result)

    return result
  }

  let todayData = await fetchDayBuckets(todayStart)

  // 今天完全没数据 → 使用昨天
  if (!todayData.some(v => v > 0)) {
    // console.log("[HeartRate] today no data, use yesterday")

    const yesterdayStart = new Date(todayStart)
    yesterdayStart.setDate(yesterdayStart.getDate() - 1)

    todayData = await fetchDayBuckets(yesterdayStart)
  }

  // console.log("[HeartRate baseline24h]", todayData)

  const validValues = todayData.filter(v => v > 0)

  const avg = validValues.length
    ? Math.round(
      validValues.reduce((sum, value) => sum + value, 0) /
      validValues.length
    )
    : null

  return {
    avg,
    list: todayData,
  }
}

/** 同时获取：最新 + 基线 */
export async function fetchLatestAndBaselines(): Promise<{
  hrv: LatestAndBaseline
  hr: LatestAndBaseline
  day_light: string | undefined
  wrist_temp: string | undefined
}> {
  const [latestHR, recentHRV, baseline24hs, wrist_temp, day_light] = await Promise.all([
    fetchLatestHeartRate(),
    fetchTodayHRVHourly(),
    fetchHeartRateBaseline24h(),
    fetchLatestWristTemperature(),
    fetchTodayDaylight(),
  ])

  return {
    hrv: { latest: recentHRV.first, baseline7d: recentHRV.avg, hrvlist: recentHRV.list },
    hr: { latest: latestHR, baseline7d: baseline24hs.avg, base24h: baseline24hs.list },
    wrist_temp,
    day_light,
  }
}
