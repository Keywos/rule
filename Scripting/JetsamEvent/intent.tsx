import { Script, Intent, Navigation, NavigationStack, List, Section, Text, Button, Path } from "scripting"
import { parseContent, resolveEventTimestamp } from "./parser"
import { AnalysisPage, detectDevice } from "./views"
import { addHistoryEntry, loadHistory } from "./history"

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

// 处理可能的 file:// 前缀与百分号编码
function normalizePath(raw: string): string {
  let p = raw
  if (p.startsWith("file://")) {
    p = p.slice("file://".length)
    try { p = decodeURIComponent(p) } catch {}
  }
  return p
}

async function run() {
  try {
    let path: string | null = null

    const files = Intent.fileURLsParameter
    if (files && files.length > 0) {
      path = normalizePath(files[0])
    }
    if (!path) {
      const param = Intent.shortcutParameter
      if (param && typeof param.value === "string") {
        path = normalizePath(param.value)
      }
    }
    if (!path) {
      const urls = Intent.urlsParameter
      if (urls && urls.length > 0) {
        path = normalizePath(urls[0])
      }
    }
    if (!path) {
      const texts = Intent.textsParameter
      if (texts && texts.length > 0 && texts[0].startsWith("/")) {
        path = normalizePath(texts[0])
      }
    }
    if (!path) {
      // 兜底：分享时系统可能自动创建文件书签
      const bookmarks = FileManager.getAllFileBookmarks()
      if (bookmarks && bookmarks.length > 0) {
        path = bookmarks[0].path
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

    // 读取文件（分享的文件为安全作用域，可能需先拷贝）
    let content: string
    const readContent = (p: string): string => FileManager.readAsStringSync(p)

    try {
      content = readContent(path)
    } catch {
      try {
        if (FileManager.isiCloudEnabled && FileManager.isFileStoredIniCloud(path)) {
          await FileManager.downloadFileFromiCloud(path)
        }
        content = readContent(path)
      } catch {
        try {
          const tmpPath = FileManager.temporaryDirectory + "/" + Path.basename(path)
          await FileManager.copyFile(path, tmpPath)
          content = readContent(tmpPath)
        } catch (copyErr) {
          await Navigation.present({
            element: <ErrorPage title="文件读取失败" detail={"无法读取文件：" + fileName + "\n" + (copyErr instanceof Error ? copyErr.message : String(copyErr))} />,
            modalPresentationStyle: "pageSheet",
          })
          return
        }
      }
    }

    if (!content || content.trim().length === 0) {
      await Navigation.present({
        element: <ErrorPage title="文件为空" detail={"文件「" + fileName + "」内容为空"} />,
        modalPresentationStyle: "pageSheet",
      })
      return
    }

    // 解析
    const data = parseContent(content)
    if (data.processes.length === 0) {
      await Navigation.present({
        element: <ErrorPage title="未找到进程数据" detail={"文件「" + fileName + "」中没有进程信息，请确认分享的是 JetsamEvent .ips 崩溃报告"} />,
        modalPresentationStyle: "pageSheet",
      })
      return
    }

    // 保存历史记录（时间用文件事件时间，而非当前时间）
    const dtype = detectDevice(data.product, fileName)
    const history = loadHistory()
    addHistoryEntry(history, fileName, dtype, data, resolveEventTimestamp(data))

    // 直接显示分享文件的分析结果
    await Navigation.present({
      element: <AnalysisPage data={data} fileName={fileName} />,
      modalPresentationStyle: "pageSheet",
    })
  } catch (err) {
    // 显示错误而不是静默失败
    try {
      await Navigation.present({
        element: <ErrorPage title="处理失败" detail={err instanceof Error ? err.message : String(err)} />,
        modalPresentationStyle: "pageSheet",
      })
    } catch {}
  } finally {
    Script.exit()
  }
}

void run()
