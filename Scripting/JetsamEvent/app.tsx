// app.tsx — 主 App（显示 JetsamEvent 历史记录列表）

import { Navigation, NavigationStack, List, Section, Text, Button, HStack, useState } from "scripting"
import { HistoryDetailPage, detectDevice, deviceLabel } from "./views"
import { loadHistory, deleteHistoryEntry } from "./history"
import { fmtDateTimeShort } from "./parser"
import { type HistoryEntry } from "./history"

// ─── 主 App ───

export function App() {
  const dismiss = Navigation.useDismiss()
  const [history, setHistory] = useState(loadHistory())

  const handleSelect = (entry: HistoryEntry) => {
    Navigation.present({
      element: <HistoryDetailPage entry={entry} />,
      modalPresentationStyle: "pageSheet",
    })
  }

  const handleDelete = (index: number) => {
    setHistory(prev => deleteHistoryEntry(prev, index))
  }

  return (
    <NavigationStack>
      <List
        navigationTitle="🔍 Jetsam 分析"
        navigationBarTitleDisplayMode="large"
        toolbar={{ cancellationAction: <Button systemImage="pencil.slash" title="关闭" action={dismiss} /> }}
      >
        {history.length === 0 ? (
          <Section header={<Text>📭 暂无数据</Text>}>
            <Text font="subheadline" foregroundStyle="#8E8E93">
              请从「分享」中导入 JetsamEvent-xxxxx.ips 文件进行分析
            </Text>
          </Section>
        ) : (
          <Section header={<Text>📋 历史记录 ({history.length})</Text>}>
            {history.map((entry: HistoryEntry, i: number) => {
              const dt = detectDevice(entry.data.product, entry.fileName)
              const killedCount = entry.data.killed.length
              const procCount = entry.data.processes.length
              const largest = entry.data.largestProcess
              const meta = [
                deviceLabel(dt),
                fmtDateTimeShort(entry.timestamp),
                procCount + "进程",
                killedCount > 0 ? "被杀" + killedCount : null,
                largest || null,
              ].filter(Boolean).join(" | ")
              return (
                <HStack
                  key={entry.fileName}
                  trailingSwipeActions={{
                    allowsFullSwipe: true,
                    actions: [
                      <Button title="删除" role="destructive" action={() => handleDelete(i)} />,
                    ],
                  }}
                >
                  <Button
                    title={meta}
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
