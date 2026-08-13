import { VStack, HStack, Text, Spacer, Color, Widget, Image, Button } from "scripting"
import { AccessoryWidgetBackground, ZStack } from "scripting"

function AccessoryView() {
  return (
    <ZStack>
      <AccessoryWidgetBackground />
      <Text font="caption">Weather</Text>
    </ZStack>
  )
}
import { StressLevel } from "../utils/stress"

import { RefreshWidgetIntent, openAppHealth } from "../app_intents"

interface MediumWidgetProps {
  hrvValue: number | null
  heartRate: number | null
  hrvBaseline: number | null
  hrBaseline: number | null
  steps: number | null
  hrvHistory: number[] | null
  level: StressLevel | null
  updateTime: Date
  gradient: { top: Color; bottom: Color }
  status: string
  statusIcon: string
  hrh: number[] | null
  day_light: string | undefined
  wrist_temp: string | undefined
}

function formatTime(date: Date): string {
  const h = date.getHours()
  const m = date.getMinutes()
  const s = date.getSeconds()
  return (h < 10 ? "0" : "") + h + ":" + (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s
}

// HRV 曲线
function SparkLine({ data }: { data: number[] }) {
  if (!data || data.length < 2) return null

  const values = data
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min || 1

  return (
    <HStack spacing={1} alignment="bottom">
      {values.map((v, i) => {
        const h = v === 0 ? 2 : 4 + ((v - min) / range) * 10
        const isLast = i === values.length - 1

        return (
          <VStack
            key={i}
            frame={{ width: 2.4, height: h }}
            background={{
              color: "white",
              opacity: v === 0 ? 0.4 : isLast ? 1 : 0.6,
            }}
            clipShape={{ type: "rect", cornerRadius: 1 }}
          />
        )
      })}
    </HStack>
  )
}

export function MediumWidget({ hrvValue, heartRate, steps, hrvHistory, hrh, updateTime, gradient, status, statusIcon, wrist_temp, day_light }: MediumWidgetProps) {
  const timeString = formatTime(updateTime)
  return (
    <VStack
      padding
      frame={{
        maxWidth: Infinity,
        maxHeight: Infinity
      }}
    ><HStack spacing={8} padding={{ leading: 4, trailing: 4, top: 5, bottom: 2 }} >
        <Image systemName={statusIcon} foregroundStyle="white" />
        <Text font={14} fontWeight="bold" foregroundStyle="white">
          {status}
        </Text>
        <Text font={11} foregroundStyle="white" opacity={0.8}>
          {(day_light ? day_light : " ") + wrist_temp}
        </Text>
        <Spacer />
        <Text font={11} foregroundStyle="white" opacity={0.8}>
          {timeString}
        </Text>

        <Button intent={RefreshWidgetIntent(undefined)} buttonStyle="plain">
          <HStack padding={{ leading: 7, trailing: 7, top: 5.6, bottom: 6.6 }} background={{ color: "white", opacity: 0.1 }} clipShape={{ type: "capsule", style: "continuous" }}>
            <Image systemName="arrow.clockwise" foregroundStyle="white" font={12} />
          </HStack>
        </Button>
      </HStack>

      <Spacer />

      <Button intent={openAppHealth("com.apple.Health")} buttonStyle="plain">
        <HStack
          spacing={8}
          frame={{
            maxWidth: Infinity,
          }}
        >
          {/* HRV */}
          <VStack
            frame={{ maxWidth: Infinity }}
            padding={{ leading: 10, trailing: 10, top: 18, bottom: 12 }}
            background={{ color: "white", opacity: 0.28 }}
            clipShape={{ type: "rect", cornerRadius: 16 }}
            spacing={4}
          >
            <Image systemName="bolt.heart.fill" font={{ name: "system", size: 18 }} foregroundStyle="white" />

            {/* <Text font={12} foregroundStyle="white" opacity={0.9}>
            HRV
          </Text> */}

            <HStack spacing={2} alignment="firstTextBaseline">
              {/*  */}
              <Text font={{ name: "system", size: 22 }} fontWeight="bold" fontDesign="rounded" foregroundStyle="white">
                {hrvValue != null ? hrvValue : "—"}
              </Text>

              <Text font={{ name: "system", size: 11 }} foregroundStyle="white" opacity={0.9}>
                HRV
              </Text>
            </HStack>
            {/* HRV 曲线 */}
            {hrvHistory && hrvHistory.length > 1 ? <SparkLine data={hrvHistory} /> : null}
          </VStack>
          {/* 心率 */}

          <VStack
            frame={{ maxWidth: Infinity }}
            layoutPriority={1}
            padding={{
              leading: 10,
              trailing: 10,
              top: 18,
              bottom: 12,
            }}
            background={{ color: "white", opacity: 0.28 }}
            clipShape={{ type: "rect", cornerRadius: 16 }}
            spacing={4}
          >
            {/*  */}
            <Image systemName="waveform.path.ecg" font={{ name: "system", size: 18 }} foregroundStyle="white" />

            <HStack spacing={2} alignment="firstTextBaseline">
              <Text font={{ name: "system", size: 22 }} fontWeight="bold" fontDesign="rounded" foregroundStyle="white">
                {heartRate != null ? heartRate.toFixed(0) : "—"}
              </Text>

              <Text font={{ name: "system", size: 11 }} foregroundStyle="white" opacity={0.9}>
                {/* {i18n.units.bpm} */}
                BPM
              </Text>
            </HStack>

            {/*   {
              <Text
                font="caption2"
                foregroundStyle="white"
                opacity={0.85}
              >
                {hrBaselineHint.text ? hrBaselineHint.text : "当前心率"}
              </Text>
            } */}

            {/* 心率 曲线 */}
            {hrh && hrh.length > 1 ? <SparkLine data={hrh} /> : null}
          </VStack>

          {/* 步数 */}
          <VStack
            frame={{ maxWidth: Infinity }}
            layoutPriority={1}
            padding={{
              leading: 10,
              trailing: 10,
              top: 18,
              bottom: 12,
            }}
            background={{ color: "white", opacity: 0.28 }}
            clipShape={{ type: "rect", cornerRadius: 16 }}
            spacing={4}
          >
            <Image systemName="figure.walk" font={{ name: "system", size: 18 }} foregroundStyle="white" />

            <Text font={{ name: "system", size: 22 }} fontWeight="bold" fontDesign="rounded" foregroundStyle="white">
              {steps != null ? steps.toLocaleString() : "—"}
            </Text>

            <Text font="caption2" foregroundStyle="white" opacity={0.85}>
              今日步数
            </Text>
          </VStack>
          {/* </HStack> 改为打开健康 app */}
        </HStack>
      </Button>

      <Spacer />
    </VStack>


  )
}
