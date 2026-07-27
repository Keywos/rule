// app.tsx — 主 App（只显示历史记录，不读本地文件）

import { Script, Navigation, NavigationStack, List, Section, Text, Button, HStack, useState } from "scripting"
import { AnalysisSections, HistoryDetailPage, detectDevice } from "./views"
import { loadHistory, deleteHistoryEntry } from "./history"
import { type HistoryEntry } from "./history"

// ─── 历史记录列表页 ───

function HistoryListPage() {
  const dismiss = Navigation.useDismiss()
  const [history, setHistory] = useState(loadHistory())

  const handleSelect = (entry: HistoryEntry) => {
    Navigation.present({
      element: <HistoryDetailPage entry={entry} />,
      modalPresentationStyle: "pageSheet",
    })
  }

  const handleDelete = (index: number) => {
    setHistory(deleteHistoryEntry(history, index))
  }

  return (
    <NavigationStack>
      <List
        navigationTitle="📋 历史记录"
        navigationBarTitleDisplayMode="large"
        navigationBarBackButtonHidden={true}
        toolbar={{ cancellationAction: <Button systemImage="pencil.slash" title="关闭" action={dismiss} /> }}
      >
      {history.length === 0 ? (
        <Section header={<Text>📭 暂无记录</Text>}>
          <Text font="subheadline" foregroundStyle="#8E8E93">分析过的文件会自动保存在这里</Text>
        </Section>
      ) : (
        <Section header={<Text>{history.length} 条记录</Text>}>
          {history.map((entry: HistoryEntry, i: number) => {
            const dt = detectDevice(entry.data.metadata, entry.fileName)
            const dlabel = dt === "iPhone" ? "📱 iPhone" : dt === "Watch" ? "⌚ Watch" : "未知"
            const date = new Date(entry.timestamp)
            const dateStr = (date.getMonth() + 1) + "月" + date.getDate() + "日 " + date.getHours() + ":" + String(date.getMinutes()).padStart(2, "0")
            const cycles = entry.cycleCount
            return (
              <HStack
                key={i}
                trailingSwipeActions={{
                  allowsFullSwipe: true,
                  actions: [
                    <Button title="删除" role="destructive" action={() => handleDelete(i)} />,
                  ],
                }}
              >
                <Button
                  title={dlabel + " | " + dateStr + (cycles != null ? " | " + cycles + "次" : "") + (entry.health ? " | " + entry.health : "")}
                  action={() => handleSelect(entry)}
                />
              </HStack>
            )
          })}
        </Section>
      )}
    </List>
    </NavigationStack>
  )
}

// ─── 主 App ───

export function App() {
  const dismiss = Navigation.useDismiss()

  const handleOpenHistory = () => {
    Navigation.present({
      element: <HistoryListPage />,
      modalPresentationStyle: "pageSheet",
    })
  }

  return (
    <NavigationStack>
      <List
        navigationTitle="🔋 电池 & 硬件分析"
        navigationBarTitleDisplayMode="large"
        toolbar={{
          cancellationAction: <Button systemImage="pencil.slash" title="关闭" action={dismiss} />,
          topBarTrailing: <Button title="历史" action={handleOpenHistory} />,
        }}
      >
        <Section header={<Text>📭 暂无数据</Text>}>
          <Text font="subheadline" foregroundStyle="#8E8E93">
            请从「分享」中导入 .synced 文件进行分析
          </Text>
        </Section>
      </List>
    </NavigationStack>
  )
}
