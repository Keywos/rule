import {
  Button,
  Circle,
  HStack,
  Image,
  Spacer,
  Text,
  VStack,
  ZStack,
  Widget,
  Capsule,
  Grid,
  GridRow,
  Color,
  EnvironmentValuesReader
} from 'scripting'
import {
  getWeekNumber,
  formatYear,
  formatMonthDay,
  getWeekDayName,
  startOfWeek as getStartOfWeek,
  addDays,
  isSameDay
} from './dateUtils'
import {
  ChangeWeekIntent,
  SelectDateIntent,
  ChangeMonthIntent
} from './app_intents'
import { lunar } from './lunar'
import {
  fetchHolidays,
  getHolidayType,
  getFestivalName,
  getMonthHolidayData,
  getHolidayCalColor
} from './holidayUtils'
import SmallWidget from './widgets/SmallWidget'
import { color, colors } from './degisn'

async function WeeklyWidget() {
  const val = Storage.get<string>('weekOffset') || '0'
  let offset = 0
  try {
    offset = JSON.parse(val)
  } catch (e) {
    console.error(e)
  }
  const sd = Storage.get<string>('selectedDate')
  const selectedDate = sd ? new Date(sd) : null

  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const displayDate = addDays(today, offset * 7)

  const weekNum = getWeekNumber(displayDate)

  const descDate = selectedDate || today
  const lunarDate = lunar(descDate)

  const dayDesc =
    `${formatMonthDay(descDate)}` +
    ` 第${getWeekNumber(descDate)}周` +
    ` ${lunarDate.yearName}(${lunarDate.yearZodiac})年` +
    ` ${lunarDate.monthName}月${lunarDate.dayName}`

  // Week Days (Sunday start) - Based on offset
  const firstDayOfWeek = parseInt(Storage.get<string>('firstDayOfWeek') || '0')
  const startOfWeekDate = getStartOfWeek(displayDate, firstDayOfWeek)

  // 从 holidayUtils 缓存读取，避免每次直接 CalendarEvent.getAll
  // 跨年时（如周一所在周跨 12/31）补拉上一年的缓存
  await fetchHolidays(startOfWeekDate.getFullYear())

  const weekDays = Array.from({ length: 7 }).map((_, i) => {
    const d = addDays(startOfWeekDate, i)
    const lunarDate = lunar(d)
    return {
      date: d,
      weekDayName: getWeekDayName(d),
      dayNum: d.getDate(),
      lunarDay: lunarDate.dayName,
      isToday: isSameDay(d, today),
      holidayType: getHolidayType(d),
      eventTitle: getFestivalName(d)
    }
  })

  return (
    <EnvironmentValuesReader keys={['widgetRenderingMode']}>
      {({ widgetRenderingMode }) => (
        <VStack padding={20} frame={Widget.displaySize}>
          {/* Header: Year/Month and Week Number */}
          <HStack>
            <Button
              intent={ChangeWeekIntent('prev')}
              buttonStyle="bordered"
              tint="systemGray2"
            >
              <Image
                systemName="chevron.left"
                font={12}
                foregroundStyle="secondaryLabel"
                widgetAccentedRenderingMode="accented"
              />
            </Button>
            <Button intent={ChangeWeekIntent('reset')} buttonStyle="plain">
              <Text font={24} foregroundStyle="label">
                {formatYear(offset ? startOfWeekDate : today)}
                {offset ? startOfWeekDate.getMonth() + 1 : today.getMonth() + 1}
                月
              </Text>
            </Button>
            <Spacer />
            <VStack alignment="trailing" spacing={2}>
              <Text font={14} foregroundStyle="secondaryLabel" widgetAccentable>
                第{weekNum}周
              </Text>
            </VStack>
            <Button
              intent={ChangeWeekIntent('next')}
              buttonStyle="bordered"
              tint="systemGray2"
            >
              <Image
                systemName="chevron.right"
                font={12}
                foregroundStyle="secondaryLabel"
                widgetAccentable
              />
            </Button>
          </HStack>

          <Spacer />

          {/* Calendar Week Row */}
          <HStack spacing={4}>
            {weekDays.map((item, index) => (
              <VStack key={index} spacing={4} frame={{ maxWidth: 400 }}>
                <Text
                  font={11}
                  foregroundStyle={
                    item.isToday ? colors.systemRed : 'secondaryLabel'
                  }
                  fontWeight="medium"
                  multilineTextAlignment="center"
                >
                  {item.weekDayName}
                </Text>
                <ZStack
                  frame={{ width: 40, height: 40 }}
                  alignment="topTrailing"
                >
                  <Button
                    intent={SelectDateIntent(item.date.toISOString())}
                    buttonStyle="plain"
                  >
                    <VStack
                      frame={{ width: 40, height: 40 }}
                      background={
                        item.isToday ? (
                          <Circle
                            fill={colors.systemRed}
                            opacity={
                              widgetRenderingMode === 'accented' ? 0.2 : 1
                            }
                          />
                        ) : selectedDate &&
                          isSameDay(item.date, selectedDate) ? (
                          <Circle
                            fill="secondarySystemBackground"
                            opacity={
                              widgetRenderingMode === 'accented' ? 0.1 : 1
                            }
                          />
                        ) : undefined
                      }
                      alignment="center"
                      spacing={0}
                    >
                      <Spacer />
                      <Text
                        font={16}
                        foregroundStyle={
                          item.isToday
                            ? 'rgba(255,255,255,0.95)'
                            : 'label'
                        }
                        widgetAccentable
                        multilineTextAlignment="center"
                      >
                        {item.dayNum.toString()}
                      </Text>
                      <Text
                        font={9}
                        lineLimit={1}
                        foregroundStyle={
                          item.isToday
                            ? 'rgba(255,255,255,0.95)'
                            : item.eventTitle
                              ? colors.systemRed
                              : 'secondaryLabel'
                        }
                        widgetAccentable
                        multilineTextAlignment="center"
                        fontWeight="medium"
                      >
                        {item.eventTitle || item.lunarDay}
                      </Text>
                      <Spacer />
                    </VStack>
                  </Button>
                  {item.holidayType && (
                    <Text
                      frame={{ width: 14, height: 14 }}
                      background={{
                        style: color(
                          item.holidayType === 'work'
                            ? colors.systemRed
                            : colors.systemGreen,
                          widgetRenderingMode === 'accented' ? 0.3 : 1
                        ),
                        shape: 'circle'
                      }}
                      font={10}
                      foregroundStyle="rgba(255,255,255,0.95)"
                      widgetAccentable
                    >
                      {item.holidayType === 'work' ? '班' : '休'}
                    </Text>
                  )}
                </ZStack>
              </VStack>
            ))}
          </HStack>
          <HStack frame={{ maxWidth: 'infinity', alignment: 'leading' }}>
            <Capsule
              frame={{ width: 4, height: 16 }}
              fill={color(colors.systemRed, 0.9)}
              widgetAccentable
            />
            <Text
              font={14}
              foregroundStyle="label"
              multilineTextAlignment="leading"
            >
              {dayDesc}
            </Text>
          </HStack>
        </VStack>
      )}
    </EnvironmentValuesReader>
  )
}

async function MonthlyWidget() {
  const today = new Date()
  const year = today.getFullYear()
  const month = today.getMonth()

  // 优先用 holidayUtils 缓存，避免每次直接 CalendarEvent.getAll
  await fetchHolidays(year)

  const { dotDays, festivals } = getMonthHolidayData(year, month)
  const dots: Record<number, Color> = {}

  if (dotDays.size > 0) {
    // 颜色也来自缓存（fetchHolidays 时已把节假日历颜色写入缓存）
    const dotColor = getHolidayCalColor(year) ?? colors.systemGreen.light
    for (const d of dotDays) {
      dots[d] = dotColor as Color
    }
  }

  return (
    <EnvironmentValuesReader keys={['widgetRenderingMode']}>
      {({ widgetRenderingMode }) => (
        <SmallWidget {...{ widgetRenderingMode, dots, festivals }} />
      )}
    </EnvironmentValuesReader>
  )
}

async function LargeMonthlyWidget() {
  const val = Storage.get<string>('monthOffset') || '0'
  let offset = 0
  try {
    offset = JSON.parse(val)
  } catch (e) {
    console.error(e)
  }

  const today = new Date()

  const sd = Storage.get<string>('selectedDate')
  const selectedDate = sd ? new Date(sd) : null

  const descDate = selectedDate || today
  const lunarDate = lunar(descDate)
  const dayDesc =
    `${formatMonthDay(descDate)}` +
    ` 第${getWeekNumber(descDate)}周` +
    ` ${lunarDate.yearName}(${lunarDate.yearZodiac})年` +
    ` ${lunarDate.monthName}月${lunarDate.dayName}`

  const displayDate = new Date(
    today.getFullYear(),
    today.getMonth() + offset,
    1
  )
  const year = displayDate.getFullYear()
  const month = displayDate.getMonth()

  await fetchHolidays(year)

  const firstDay = new Date(year, month, 1)
  const lastDay = new Date(year, month + 1, 0)
  const daysInMonth = lastDay.getDate()
  const firstDayOfWeek = parseInt(Storage.get<string>('firstDayOfWeek') || '0')
  const startDayOfWeek = (firstDay.getDay() - firstDayOfWeek + 7) % 7

  // Generate grid cells
  const gridDays: (Date | null)[] = []

  // Start padding
  for (let i = 0; i < startDayOfWeek; i++) {
    gridDays.push(null)
  }
  // Dates
  for (let i = 1; i <= daysInMonth; i++) {
    gridDays.push(new Date(year, month, i))
  }

  // Chunk into weeks
  const weeks: (Date | null)[][] = []
  for (let i = 0; i < gridDays.length; i += 7) {
    weeks.push(gridDays.slice(i, i + 7))
  }

  const weekDayNames =
    firstDayOfWeek === 1
      ? ['一', '二', '三', '四', '五', '六', '日']
      : ['日', '一', '二', '三', '四', '五', '六']

  return (
    <EnvironmentValuesReader keys={['widgetRenderingMode']}>
      {({ widgetRenderingMode }) => (
        <VStack padding={20} frame={Widget.displaySize}>
          {/* Header */}
          <HStack alignment="center">
            <Button
              intent={ChangeMonthIntent('prev')}
              buttonStyle="bordered"
              tint="systemGray2"
            >
              <Image
                systemName="chevron.left"
                font={12}
                foregroundStyle="secondaryLabel"
              />
            </Button>
            <Button intent={ChangeMonthIntent('reset')} buttonStyle="plain">
              <Text
                font={16}
                fontWeight="bold"
                foregroundStyle="label"
                widgetAccentable
              >
                {year}年{month + 1}月
              </Text>
            </Button>
            <Spacer />
            <Button
              intent={ChangeMonthIntent('next')}
              buttonStyle="bordered"
              tint="systemGray2"
            >
              <Image
                systemName="chevron.right"
                font={12}
                foregroundStyle="secondaryLabel"
                widgetAccentable
              />
            </Button>
          </HStack>

          <Spacer />

          <Grid verticalSpacing={4} horizontalSpacing={0}>
            <GridRow>
              {weekDayNames.map((name, i) => (
                <Text
                  key={i}
                  font={12}
                  fontWeight="medium"
                  foregroundStyle={
                    (firstDayOfWeek === 1
                      ? i === 5 || i === 6
                      : i === 0 || i === 6)
                      ? 'secondaryLabel'
                      : 'label'
                  }
                  frame={{ maxWidth: 'infinity' }}
                  multilineTextAlignment="center"
                >
                  {name}
                </Text>
              ))}
            </GridRow>
            {weeks.map((week, i) => (
              <GridRow key={i}>
                {week.map((date, j) => {
                  if (!date) {
                    // Empty cell
                    return (
                      <ZStack
                        key={j}
                        frame={{ maxWidth: 'infinity', height: 40 }}
                      />
                    )
                  }
                  const isToday = isSameDay(date, today)
                  const eventTitle = getFestivalName(date)
                  const lunarDate = lunar(date)
                  const lunarDay = lunarDate.dayName
                  const holidayType = getHolidayType(date)

                  return (
                    <ZStack
                      key={j}
                      frame={{ maxWidth: 'infinity', height: 40 }}
                      alignment="topTrailing"
                    >
                      <Button
                        intent={SelectDateIntent(date.toISOString())}
                        buttonStyle="plain"
                      >
                        <VStack
                          frame={{ width: 40, height: 40 }}
                          background={
                            isToday
                              ? {
                                  style:
                                    widgetRenderingMode === 'accented'
                                      ? 'rgba(255,0,0,0.3)'
                                      : colors.systemRed,
                                  shape: 'circle'
                                }
                              : selectedDate && isSameDay(date, selectedDate)
                                ? {
                                    style:
                                      widgetRenderingMode === 'accented'
                                        ? 'rgba(28,28,30,0.5)'
                                        : 'secondarySystemBackground',
                                    shape: 'circle'
                                  }
                                : undefined
                          }
                          alignment="center"
                          spacing={0}
                        >
                          <Text
                            font={14}
                            fontWeight="medium"
                            foregroundStyle={
                              isToday
                                ? 'rgba(255,255,255,0.95)'
                                  : date.getDay() === 0 || date.getDay() === 6
                                    ? 'secondaryLabel'
                                    : 'label'
                            }
                            widgetAccentable
                            multilineTextAlignment="center"
                          >
                            {date.getDate().toString()}
                          </Text>
                          <Text
                            font={9}
                            foregroundStyle={
                              isToday
                                ? 'rgba(255,255,255,0.95)'
                                : eventTitle
                                  ? colors.systemRed
                                  : 'secondaryLabel'
                            }
                            widgetAccentable={isToday}
                            lineLimit={1}
                            multilineTextAlignment="center"
                          >
                            {eventTitle || lunarDay}
                          </Text>
                        </VStack>
                      </Button>

                      {holidayType && (
                        <Text
                          frame={{ width: 14, height: 14 }}
                          font={10}
                          background={{
                            style:
                              holidayType === 'work'
                                ? widgetRenderingMode === 'accented'
                                  ? 'rgba(255,0,0,0.3)'
                                  : colors.systemRed
                                : widgetRenderingMode === 'accented'
                                  ? 'rgba(0,255,0,0.3)'
                                  : colors.systemGreen,
                            shape: 'circle'
                          }}
                          foregroundStyle="rgba(255,255,255,0.95)"
                          widgetAccentable
                        >
                          {holidayType === 'work' ? '班' : '休'}
                        </Text>
                      )}
                    </ZStack>
                  )
                })}
              </GridRow>
            ))}
          </Grid>
          <Spacer />
          <HStack frame={{ maxWidth: 'infinity', alignment: 'leading' }}>
            <Capsule
              frame={{ width: 4, height: 16 }}
              fill={color(colors.systemRed, 0.9)}
              widgetAccentable
            />
            <Text
              font={14}
              foregroundStyle="label"
              multilineTextAlignment="leading"
            >
              {dayDesc}
            </Text>
          </HStack>
        </VStack>
      )}
    </EnvironmentValuesReader>
  )
}

async function WidgetView() {
  if (Widget.family === 'systemSmall') {
    return await MonthlyWidget()
  }
  if (Widget.family === 'systemLarge') {
    return await LargeMonthlyWidget()
  }
  return await WeeklyWidget()
}

// Main execution
;(async () => {
  const val = Storage.get<string>('weekOffset') || '0'
  let offset = 0
  try {
    offset = JSON.parse(val)
  } catch (e) {
    console.error(e)
  }
  const today = new Date()
  const displayDate = addDays(today, offset * 7)

  await fetchHolidays(displayDate.getFullYear())

  Widget.present(await WidgetView())
})()
