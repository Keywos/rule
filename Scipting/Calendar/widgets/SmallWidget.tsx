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
import { colors } from '../degisn'
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
  const lunarText = `${lunarDate.monthName}月${lunarDate.dayName}`

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
        <Text offset={{ x: -6, y: 0 }} font={11} fontWeight="medium" foregroundStyle="gray">
          {lunarText}
        </Text>
      </HStack>
      {/* <Spacer frame={{ minHeight: 4 }} /> */}
      {/* Calendar Grid */}
      <Grid verticalSpacing={2} horizontalSpacing={0}>
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
                      fill={
                        widgetRenderingMode === 'accented'
                          ? 'rgba(255,0,0,0.3)'
                          : colors.systemRed
                      }
                      frame={{ width: 18, height: 18 }}
                    />
                  )}
                  <VStack spacing={0} alignment="center">
                  <Text
                    font={11}
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
                  {festivals.has(date.getDate()) ? (
                    <Capsule
                      fill={colors.systemRed}
                      frame={{ width: 12, height: 1 }}
                      widgetAccentable
                    />
                  ) : dotColor ? (
                    <Circle
                      fill={dotColor}
                      frame={{ width: 3, height: 3 }}
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
