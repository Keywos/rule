import { Script, Intent, Navigation, NavigationStack, List, Section, Text, Button, Path } from "scripting"
import { parseContent } from "./parser"
import { AnalysisPage } from "./views"
import { addHistoryEntry, loadHistory } from "./history"
import { detectDevice } from "./views"

function ErrorPage(props: { title: string; detail: string }) {
  const dismiss = Navigation.useDismiss()
  return (
    <NavigationStack>
      <List
        navigationTitle="⚠️ 提示"
        navigationBarTitleDisplayMode="large"
        toolbar={{
          cancellationAction: <Button systemImage="pencil.slash" title="关闭" action={dismiss} />,
        }}
      >
        <Section header={<Text>{props.title}</Text>}>
          <Text font="subheadline" foregroundStyle="#8E8E93">{props.detail}</Text>
        </Section>
      </List>
    </NavigationStack>
  )
}

async function run() {
  try {
    let path: string | null = null

    const files = Intent.fileURLsParameter
    if (files && files.length > 0) {
      path = files[0]
    }
    if (!path) {
      const param = Intent.shortcutParameter
      if (param && typeof param.value === "string") {
        path = param.value
      }
    }
    if (!path) {
      const urls = Intent.urlsParameter
      if (urls && urls.length > 0) {
        path = urls[0]
      }
    }
    if (!path) {
      const texts = Intent.textsParameter
      if (texts && texts.length > 0 && texts[0].startsWith("/")) {
        path = texts[0]
      }
    }
    if (!path) {
      await Navigation.present({
        element: <ErrorPage title="未找到文件" detail="没有接收到可分析的文件路径" />,
        modalPresentationStyle: "pageSheet",
      })
      return
    }

    const fileName = Path.basename(path)

    // 读取文件
    let content: string
    try {
      content = FileManager.readAsStringSync(path)
    } catch {
      try {
        if (FileManager.isiCloudEnabled && FileManager.isFileStoredIniCloud(path)) {
          await FileManager.downloadFileFromiCloud(path)
        }
        content = FileManager.readAsStringSync(path)
      } catch {
        try {
          const tmpPath = FileManager.temporaryDirectory + "/" + Path.basename(path)
          await FileManager.copyFile(path, tmpPath)
          content = FileManager.readAsStringSync(tmpPath)
        } catch {
          await Navigation.present({
            element: <ErrorPage title="文件读取失败" detail={"无法读取文件：" + fileName} />,
            modalPresentationStyle: "pageSheet",
          })
          return
        }
      }
    }

    // 解析
    const data = parseContent(content)
    if (data.battery.length === 0) {
      await Navigation.present({
        element: <ErrorPage title="未找到电池数据" detail={"文件「" + fileName + "」中没有电池分析记录，请确认分享的是包含电池数据的 .synced 文件，且充电循环过，第二天才会有电池数据，NAND 数据不一定有"} />,
        modalPresentationStyle: "pageSheet",
      })
      return
    }

    // 保存历史记录
    const dtype = detectDevice(data.metadata, fileName)
    const configRec = data.battery.find((r: Record<string, any>) => r.name === "BatteryConfigValueHistogram_WithAllSafetyKeys_V2" || r.name === "BatteryConfigValueHistogramFinal_V2")
    const obcRec = data.battery.find((r: Record<string, any>) => r.name === "OBC_Battery_Health_v3")
    const cycles = configRec?.message?.last_value_CycleCount ?? obcRec?.message?.sum_of_CycleCount ?? null
    // 计算健康度
    const rawMax = configRec?.message?.last_value_AppleRawMaxCapacity
    const nomCap = configRec?.message?.last_value_NominalChargeCapacity
    const health = (rawMax != null && nomCap != null && nomCap > 0) ? ((rawMax / nomCap) * 100).toFixed(1) + "%" : null
    const history = loadHistory()
    addHistoryEntry(history, fileName, dtype, data, cycles, health)

    // 直接显示分享文件的分析结果
    await Navigation.present({
      element: <AnalysisPage data={data} fileName={fileName} />,
      modalPresentationStyle: "pageSheet",
    })
  } catch {
    // 静默失败
  } finally {
    Script.exit()
  }
}

void run()
