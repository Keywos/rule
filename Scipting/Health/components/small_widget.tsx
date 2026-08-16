import { VStack, HStack, Text, Spacer, Image, Color, Button } from "scripting"
import { StressLevel } from "../utils/stress"
import { RefreshWidgetIntent, openAppHealth } from "../app_intents"

type SmallWidgetProps = {
  hrvValue: number | null
  level: StressLevel | null
  updateTime: Date
  gradient: { top: Color; bottom: Color }
  status: string
  statusIcon: string
  hrvHistory: number[] | null
  steps: number | null
  wristTemp: string | undefined
}

function SparkLine({ data }: { data: number[] }) {
  if (!data || data.length < 2) return null
  const min = Math.min(...data)
  const max = Math.max(...data)
  const range = max - min || 1
  return (
    <HStack spacing={1.5} alignment="bottom">
      {data.map((value, index) => (
        <VStack
          key={index}
          frame={{ width: 3, height: value === 0 ? 3 : 6 + ((value - min) / range) * 16 }}
          background={{ color: "white", opacity: 0.45 }}
          clipShape={{ type: "rect", cornerRadius: 1.5 }}
        />
      ))}
    </HStack>
  )
}

export function SmallWidget({ hrvValue, status, statusIcon, hrvHistory, steps, updateTime, wristTemp }: SmallWidgetProps) {
  const timeStr = `${updateTime.getHours().toString().padStart(2, "0")}:${updateTime.getMinutes().toString().padStart(2, "0")}`

  return (
    <VStack
      padding={14}
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
      widgetBackground="clear"
    >
      <HStack spacing={6} alignment="center">
        <HStack
          spacing={5}
          padding={{ leading: 6, trailing: 0, top: 15, bottom: 0 }}
          clipShape={{ type: "capsule", style: "continuous" }}
          alignment="center"
          opacity={.6}
        >
          <Image systemName={statusIcon} font={{ name: "system", size: 16 }} foregroundStyle="white" /> 
        </HStack>
        <Spacer />
        <Text padding={{ leading: 6, trailing: 0, top: 11.3, bottom: 0 }} font={{ name: "system", size: 11 }} foregroundStyle="white" opacity={0.55} lineLimit={1}>{timeStr}</Text>
        <Button intent={RefreshWidgetIntent(undefined)} buttonStyle="plain">
          <HStack
            padding={{ leading: 3, trailing: 6, top: 15, bottom: 4 }}
            clipShape={{ type: "capsule", style: "continuous" }}
            opacity={.6}
          >
            <Image systemName="arrow.clockwise" font={{ name: "system", size: 12 }} foregroundStyle="white" />
          </HStack>
        </Button>
      </HStack>
      <Spacer />
      <Button intent={openAppHealth("com.apple.Health")} buttonStyle="plain">
        <VStack spacing={3} alignment="leading" frame={{ maxWidth: Infinity }}>
          <HStack frame={{ maxWidth: Infinity }} alignment="firstTextBaseline">
            <Spacer />
          </HStack>
          <HStack spacing={2} alignment="firstTextBaseline"
            padding={{ leading: 6, trailing: 0, top: 0, bottom: 1 }}
            >
            <Text opacity={.9} font={{ name: "system", size: 36 }} fontWeight="bold" fontDesign="rounded" foregroundStyle="white">
              {hrvValue != null ? Math.round(hrvValue) : "-- "}
            </Text>
            <Text font={{ name: "system", size: 12 }} fontWeight="medium" foregroundStyle="white" opacity={0.6}>
              HRV
            </Text>
          </HStack>
          <VStack padding={{ leading: 6, trailing: 0, top: 1, bottom: 0 }}>
          {hrvHistory && hrvHistory.length > 1 ? <SparkLine data={hrvHistory} /> : null}
        </VStack></VStack>
      </Button>

      <Spacer />
      <HStack
        spacing={1}
        alignment="center"
        padding={{ leading: 6, trailing: 0, top: 3, bottom: 15 }}
        clipShape={{ type: "rect", cornerRadius: 12 }}
        frame={{ maxWidth: Infinity }}
      >
        <Image systemName="figure.walk" font={{ name: "system", size: 11 }} foregroundStyle="white" opacity={0.7} />
        <Text opacity={0.66} font={{ name: "system", size: 14 }} fontWeight="semibold" fontDesign="rounded" foregroundStyle="white">
         {steps != null ? steps.toLocaleString() : "--"}
        </Text>
        <Spacer />
          <Text font={{ name: "system", size: 10 }} foregroundStyle="white" opacity={0.6}>
          {(wristTemp?wristTemp:"")} ㅤ
        </Text>
        <Image   padding={{ leading:4, trailing: 6 }} systemName="chevron.right" font={{ name: "system", size: 8 }} foregroundStyle="white" opacity={0.5} />
      </HStack>
    </VStack>
  )
}
