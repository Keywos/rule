import {
  VStack,
  HStack,
  Text,
  Spacer,
  Grid,
  GridRow,
  ZStack,
  Circle,
  Capsule,
  Button,
  type WidgetRenderingMode,
  type Color
} from 'scripting'
import { isSameDay } from '../dateUtils'
import { lunar } from '../lunar'
import { colors, todayText,labText } from '../degisn'
import { OpenAppIntent } from '../app_intents'

export default function SmallWidget({
  widgetRenderingMode,
  dots,
  festivals
}: {
  widgetRenderingMode: WidgetRenderingMode
  dots: Record<number, Color>
  festivals: Set<number>
}) {
  const today = new Date()
  const year = today.getFullYear()
  const month = today.getMonth()

  const lunarDate = lunar(today)
  // 正/冬/腊 换成大写数字（正月=壹月、冬月=拾壹月、腊月=拾贰月）
  const bigMonth: Record<string, string> = { 正: '一', 冬: '十一', 腊: '十二' }
  const monthName = bigMonth[lunarDate.monthName] ?? lunarDate.monthName
  const lunarText = `${monthName}月${lunarDate.dayName}`

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

  // 网格高度稳定：6 行时保持默认行距；5 行（或更少）时放大行距，让总高度接近一致，避免布局跳动
  const rowHeight = 15
  const refSpacing = 2
  const refRows = 6
  const gridHeightBudget = refRows * rowHeight + refRows * refSpacing
  const verticalSpacing =
    weeks.length >= refRows
      ? refSpacing
      : Math.max(
          refSpacing,
          Math.round(
            (gridHeightBudget - weeks.length * rowHeight) / weeks.length
          )
        )

  const weekDayNames =
    firstDayOfWeek === 1
      ? ['一', '二', '三', '四', '五', '六', '日']
      : ['日', '一', '二', '三', '四', '五', '六']

  return (
    <Button
      intent={OpenAppIntent('com.apple.mobilecal')}
      buttonStyle="plain"
    >
    <VStack
      padding={{ leading: 20, trailing: 20, top: 8, bottom: 8 }}
      frame={{ maxWidth: 'infinity', maxHeight: 'infinity' }}
    >
      {/* Header */}
      <HStack
        alignment="center"
        padding={{ leading: 6, trailing: 0, top: 1, bottom: 0 }}
        //background={"red"}
        frame={{ maxWidth: 'infinity', alignment: 'leading' }}
      >
        <Text font={11} fontWeight="medium" foregroundStyle={colors.systemRed}>
          {month + 1}月
        </Text>

        <Capsule offset={{ x: -3, y: 0 }} fill="separator" frame={{ width: 0.5, height: 10 }} />
        <Text offset={{ x: -6, y: 0 }} font={11} fontWeight="medium" foregroundStyle={labText}>
          {lunarText}
        </Text>
      </HStack>
      {/* <Spacer frame={{ minHeight: 4 }} /> */}
      {/* Calendar Grid */}
      <Grid verticalSpacing={verticalSpacing} horizontalSpacing={0}>
        <GridRow
        //padding={{ leading: 6, trailing: 0, top: 0, bottom: 0 }}
        //background={"red"}
        >
          {weekDayNames.map((name, i) => (
            <Text
              key={i}
              font={10}
              fontWeight="medium"
              foregroundStyle={
                (firstDayOfWeek === 1
                  ? i === 5 || i === 6
                  : i === 0 || i === 6)
                  ? labText
                  : todayText
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
                    frame={{ maxWidth: 'infinity', height: 10 }}
                  />
                )
              }
              const isToday = isSameDay(date, today)
              const dotColor = dots[date.getDate()]
              return (
                <ZStack
                  frame={{ width: 20, height: 15 }}
                  alignment="center"
                >
                  {isToday && (
                    <Circle
                      fill={colors.systemRed}
                      frame={{ width: 18, height: 18 }}
                    />
                  )}
                  <VStack spacing={0} alignment="center">
                  <Text
                    font={11}
                    fontWeight="medium"
                    foregroundStyle={
                      isToday
                        ? todayText
                        : date.getDay() === 0 || date.getDay() === 6
                          ? labText
                          : todayText
                    }
                    multilineTextAlignment="center"
                  >
                    {date.getDate().toString()}
                  </Text>
                  {festivals.has(date.getDate()) ? (
                    <Capsule
                      fill={colors.systemRed}
                      frame={{ width: 12, height: 1 }}
                      widgetAccentable
                    />
                  ) : dotColor ? (
                    <Capsule
                      fill={dotColor}
                      frame={{ width: 12, height: 1 }}
                      widgetAccentable
                    />
                  ) : undefined}
                  </VStack>
                </ZStack>
              )
            })}
          </GridRow>
        ))}
      </Grid>
    </VStack>
    </Button>
  )
}
