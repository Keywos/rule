/**
 * 今日活动数据类型
 */
export type TodayActivityData = {
  steps: number | null
  activeEnergy: number | null
  standHours: number | null
}

/**
 * 获取今日步数
 */
async function fetchTodaySteps(): Promise<number | null> {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const tomorrow = new Date(today)
  tomorrow.setDate(tomorrow.getDate() + 1)

  const stats = await Health.queryStatistics("stepCount", {
    startDate: today,
    endDate: tomorrow,
    statisticsOptions: ["cumulativeSum"],
  })

  if (!stats) return 0
  try {
    const value = stats.sumQuantity(HealthUnit.count())
    return value != null ? Math.round(value) : 0
  } catch {
    return 0
  }
}

/**
 * 获取今日活动能量（卡路里）
 */
/* async function fetchTodayActiveEnergy(): Promise<number | null> {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const tomorrow = new Date(today)
  tomorrow.setDate(tomorrow.getDate() + 1)

  const stats = await Health.queryStatistics("activeEnergyBurned", {
    startDate: today,
    endDate: tomorrow,
    statisticsOptions: ["cumulativeSum"],
  })

  if (!stats) return null
  try {
    return stats.sumQuantity(HealthUnit.kilocalorie())
  } catch {
    return null
  }
}
 */
/**
 * 获取今日站立小时数
 */
/* async function fetchTodayStandHours(): Promise<number | null> {
  try {
    const today = new Date()
    today.setHours(0, 0, 0, 0)

    const tomorrow = new Date(today)
    tomorrow.setDate(tomorrow.getDate() + 1)

    const start = DateComponents.fromDate(today)
    const end = DateComponents.fromDate(tomorrow)

    const summaries = await Health.queryActivitySummaries({
      start,
      end,
    })

    if (!summaries || summaries.length === 0) return null

    // 获取今日活动摘要中的站立小时数
    const todaySummary = summaries[0]
    return todaySummary.appleStandHours(HealthUnit.count())
  } catch {
    return null
  }
} */

/**
 * 获取今日所有活动数据
 */
export async function fetchTodayActivity(): Promise<TodayActivityData> {
  const [steps, activeEnergy, standHours] = await Promise.all([
    fetchTodaySteps(),
    null, null
    //fetchTodayActiveEnergy(),
    //fetchTodayStandHours(),
  ])

  return {
    steps,
    activeEnergy,
    standHours,
  }
}