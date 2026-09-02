interface LunarDate extends Record<Intl.DateTimeFormatPartTypes, string> {
    yearName: string
    /** 年份生肖 */
    yearZodiac: string
    monthName: string
    dayName: string
}

export function lunar(date: Date = new Date()): LunarDate {
    const formatter = new Intl.DateTimeFormat("zh-CN", {
        calendar: "chinese",
        year: "numeric",
        month: "long",
        day: "numeric"
    })
    const parts = formatter.formatToParts(date)
        .reduce((acc, part) => {
            acc[part.type] = part.value
            return acc
        }, {} as Record<Intl.DateTimeFormatPartTypes | 'yearName', string>)

    // Zodiac Mapping
    // Stems: 甲乙丙丁戊己庚辛壬癸
    // Branches: 子丑寅卯辰巳午未申酉戌亥
    // Zodiac: 鼠牛虎兔龙蛇马羊猴鸡狗猪
    // The second char of yearName is the branch.
    const branches = "子丑寅卯辰巳午未申酉戌亥"
    const zodiacs = "鼠牛虎兔龙蛇马羊猴鸡狗猪"
    let yearZodiac = parts.yearName || ''
    if (yearZodiac.length > 1) {
        const branch = yearZodiac[1]
        const idx = branches.indexOf(branch)
        if (idx !== -1) {
            yearZodiac = zodiacs[idx]
        }
    }

    const monthMap: Record<string, string> = {
        "一月": "正月",
        "十一月": "冬月",
        "十二月": "腊月"
    }
    const monthName = (monthMap[parts.month] || parts.month).replace(/月$/, '')

    const dayChars = ["", "一", "二", "三", "四", "五", "六", "七", "八", "九", "十"]
    let dayName = parts.day
    if (/\d+/.test(parts.day)) {
      const day = Number.parseInt(parts.day)
      if (day <= 10) {
          dayName = `初${dayChars[day]}`
      } else if (day < 20) {
          dayName = `十${dayChars[day - 10]}`
      } else if (day === 20) {
          dayName = "二十"
      } else if (day < 30) {
          dayName = `廿${dayChars[day - 20]}`
      } else {
          dayName = `三十${dayChars[day - 30]}`
      }
    }
    return { ...parts, yearZodiac, monthName, dayName }
}
