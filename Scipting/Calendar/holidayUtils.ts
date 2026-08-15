const CACHE_KEY_PREFIX = 'holiday_data_v2_'

// 缓存有效期：超过 1 天则清除并重新缓存
const CACHE_TTL_MS = 24 * 60 * 60 * 1000

interface HolidayItem {
  holiday: boolean
  name: string
  wage: number
  date: string
  rest: number
}

interface HolidayData {
  [date: string]: HolidayItem
}

// 节日名称（不含“休/班”标记的事件，如“国庆节”）
interface FestivalData {
  [date: string]: string
}

interface YearData {
  holidays: HolidayData
  festivals: FestivalData
  // 节假日历颜色（仅在为字符串时保存，否则读取时回退默认）
  color?: string
}

function dateKeyOf(date: Date): string {
  return `${(date.getMonth() + 1).toString().padStart(2, '0')}-${date.getDate().toString().padStart(2, '0')}`
}

function loadYearData(year: number): YearData | null {
  const raw = Storage.get<string>(`${CACHE_KEY_PREFIX}${year}`)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object') return null
    if ('holidays' in parsed || 'festivals' in parsed) {
      const p = parsed as Partial<YearData>
      return {
        holidays: p.holidays ?? {},
        festivals: p.festivals ?? {},
        color: typeof p.color === 'string' ? p.color : undefined
      }
    }
    // v1 旧格式：平铺 map，整体就是 holidays
    return { holidays: parsed as HolidayData, festivals: {} }
  } catch {
    return null
  }
}

export async function fetchHolidays(year: number) {
  const key = `${CACHE_KEY_PREFIX}${year}`

  // 缓存控制：命中且未超过 1 天则直接复用，避免每次都查 CalendarEvent.getAll
  const raw = Storage.get<string>(key)
  if (raw) {
    try {
      const parsed = JSON.parse(raw)
      const ts = parsed && typeof parsed === 'object' ? parsed.ts : undefined
      if (typeof ts === 'number' && Date.now() - ts < CACHE_TTL_MS) {
        return
      }
      // 缓存过期（超过一天）或为旧格式：清除后重新缓存
      Storage.remove(key)
    } catch {
      // 解析失败，当作无缓存处理
      Storage.remove(key)
    }
  }

  try {
    const calendars = await Calendar.forEvents()
    // Find calendar by name. Try "中国大陆节假日" or standard "Chinese Holidays"
    const holidayCal = calendars.find(c => c.title === "中国大陆节假日" || c.title === "Chinese Holidays")
    
    if (!holidayCal) {
      console.warn("Holiday calendar '中国大陆节假日' not found.")
      return
    }

    const startDate = new Date(year, 0, 1)
    const endDate = new Date(year, 11, 31, 23, 59, 59)
    const events = await CalendarEvent.getAll(startDate, endDate, [holidayCal])

    const holidayMap: HolidayData = {}
    const festivalMap: FestivalData = {}
    // 顺手缓存节假日历颜色，让组件不必再查 Calendar.forEvents
    const calColor = typeof holidayCal.color === 'string' ? holidayCal.color : undefined

    for (const e of events) {
      // Logic:
      // If title includes "班"/"补" -> Work
      // Else if includes "休" -> Holiday (Rest)
      // Else -> 纯节日事件（如“国庆节”），只记录名称，不参与休/班标记
      const isWork = e.title.includes('班') || e.title.includes('补')
      const isRest = e.title.includes('休')

      // Iterate days (handle all-day events correctly)
      let d = new Date(e.startDate)
      // Reset time to ensure correct loop for all-day events
      d.setHours(0, 0, 0, 0)

      const end = new Date(e.endDate)
      // If all-day event ends at midnight of next day, simple comparison works

      while (d < end) {
        // Ensure we only cache within the requested year (though fetching logic limits scope)
        if (d.getFullYear() === year) {
          const dateKey = dateKeyOf(d)

          if (isWork || isRest) {
            // If multiple events on same day (rare for holiday cal), overwrite?
            holidayMap[dateKey] = {
              holiday: isRest,
              name: e.title,
              wage: 0,
              date: dateKey,
              rest: isRest ? 1 : 0
            }
          } else {
            festivalMap[dateKey] = e.title
          }
        }
        d.setDate(d.getDate() + 1)
      }
    }

    Storage.set(key, JSON.stringify({ ts: Date.now(), holidays: holidayMap, festivals: festivalMap, color: calColor }))
    
  } catch (e) {
    console.error(`Fetch holidays via Calendar error: ${e}`)
  }
}

export function getHolidayType(date: Date): 'work' | 'holiday' | null {
  const data = loadYearData(date.getFullYear())
  if (!data) return null

  const info = data.holidays[dateKeyOf(date)]
  if (!info) return null
  // holiday: true -> Rest (Festival/Holiday)
  // holiday: false -> Work (Adjusted/Ban)
  return info.holiday ? 'holiday' : 'work'
}

// 从缓存读取某天的节日名称（如“国庆节”），无则返回 null
export function getFestivalName(date: Date): string | null {
  const data = loadYearData(date.getFullYear())
  if (!data) return null
  return data.festivals[dateKeyOf(date)] ?? null
}

// 从缓存读取某年的节假日历颜色（若未保存则返回 null，调用方回退默认色）
export function getHolidayCalColor(year: number): string | null {
  const data = loadYearData(year)
  return data?.color ?? null
}

// 从缓存读取某月（month 为 0 起下标）需要标记的天数：
// dotDays - 有节假日历事件的天（画圆点）
// festivals - 节日名称事件的天（画红色横线，如“国庆节”“中秋节”）
export function getMonthHolidayData(
  year: number,
  month: number
): { dotDays: Set<number>; festivals: Set<number> } {
  const data = loadYearData(year)
  const dotDays = new Set<number>()
  const festivalDays = new Set<number>()
  if (!data) return { dotDays, festivals: festivalDays }

  const prefix = `${(month + 1).toString().padStart(2, '0')}-`
  for (const key of Object.keys(data.holidays)) {
    if (key.startsWith(prefix)) dotDays.add(parseInt(key.slice(3), 10))
  }
  for (const key of Object.keys(data.festivals)) {
    if (key.startsWith(prefix)) {
      const day = parseInt(key.slice(3), 10)
      dotDays.add(day)
      festivalDays.add(day)
    }
  }
  return { dotDays, festivals: festivalDays }
}