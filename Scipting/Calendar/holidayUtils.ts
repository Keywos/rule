
const CACHE_KEY_PREFIX = 'holiday_data_'

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

export async function fetchHolidays(year: number) {
  const key = `${CACHE_KEY_PREFIX}${year}`
  // If cached data exists, verify it's not empty/stale? 
  // For now, keep simple cache strategy to avoid excessive calendar queries.
  if (Storage.get(key)) {
    return
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

    for (const e of events) {
      // Logic:
      // If title includes "班" -> Work
      // Else -> Holiday (Rest)
      // This assumes the calendar is specific for holidays/adjustments.
      
      const isWork = e.title.includes('班') || e.title.includes('补')
      const isRest = e.title.includes('休')

      // Solar terms and other events shouldn't be treated as holidays/workdays
      // unless explicitly marked
      if (!isWork && !isRest) {
        continue
      }

      // Iterate days (handle all-day events correctly)
      let d = new Date(e.startDate)
      // Reset time to ensure correct loop for all-day events
      d.setHours(0, 0, 0, 0)
      
      const end = new Date(e.endDate)
      // If all-day event ends at midnight of next day, simple comparison works
      
      while (d < end) {
        // Ensure we only cache within the requested year (though fetching logic limits scope)
        if (d.getFullYear() === year) {
           const dateKey = `${(d.getMonth() + 1).toString().padStart(2, '0')}-${d.getDate().toString().padStart(2, '0')}`
           
           // If multiple events on same day (rare for holiday cal), overwrite?
           holidayMap[dateKey] = {
             holiday: isRest,
             name: e.title,
             wage: 0,
             date: dateKey,
             rest: isRest ? 1 : 0
           }
        }
        d.setDate(d.getDate() + 1)
      }
    }
    
    Storage.set(key, JSON.stringify(holidayMap))
    
  } catch (e) {
    console.error(`Fetch holidays via Calendar error: ${e}`)
  }
}

export function getHolidayType(date: Date): 'work' | 'holiday' | null {
  const year = date.getFullYear()
  const dateKey = `${(date.getMonth() + 1).toString().padStart(2, '0')}-${date.getDate().toString().padStart(2, '0')}`
  
  const cache = Storage.get<string>(`${CACHE_KEY_PREFIX}${year}`)
  if (!cache) return null

  let holidayMap: HolidayData = {}
  try {
    holidayMap = JSON.parse(cache)
  } catch {
    return null
  }

  const info = holidayMap[dateKey]
  if (info) {
    // holiday: true -> Rest (Festival/Holiday)
    // holiday: false -> Work (Adjusted/Ban)
    return info.holiday ? 'holiday' : 'work'
  }
  return null
}
