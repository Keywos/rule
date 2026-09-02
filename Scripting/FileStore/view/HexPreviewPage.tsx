// 二进制文件 Hex 预览页（只读）
import { Navigation, NavigationStack, VStack, HStack, Text, Button, Image, useState, useEffect, useMemo, Editor, Divider } from "scripting"
import { fmtSize } from "../manager/utils"

const HEX_LINE_BYTES = 16
const HEX_PREVIEW_MAX_BYTES = 512 * 1024 // 单次预览最多转储 512 KiB，防止超大文件卡死

export interface HexDumpResult {
  text: string
  shown: number
  total: number
}

/** 把字节数组格式化成经典 hexdump：偏移 + 两组 8 字节 HEX + ASCII 列 */
export function formatHexDump(bytes: Uint8Array, maxBytes: number = HEX_PREVIEW_MAX_BYTES): HexDumpResult {
  const total = bytes.length
  const shown = Math.min(total, maxBytes)
  const lines: string[] = []
  for (let off = 0; off < shown; off += HEX_LINE_BYTES) {
    const end = Math.min(off + HEX_LINE_BYTES, shown)
    const hexLeft: string[] = []
    const hexRight: string[] = []
    const ascii: string[] = []
    for (let i = off; i < end; i++) {
      const b = bytes[i]
      const hex = b.toString(16).padStart(2, "0")
      if (i - off < 8) hexLeft.push(hex)
      else hexRight.push(hex)
      ascii.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".")
    }
    const left = hexLeft.join(" ").padEnd(23)
    const right = hexRight.join(" ")
    const asciiStr = ascii.join("").padEnd(HEX_LINE_BYTES, " ")
    lines.push(`${off.toString(16).padStart(8, "0")}  ${left}  ${right}  |${asciiStr}|`)
  }
  return { text: lines.join("\n"), shown, total }
}

export function HexPreviewPage({ path, fileName, fileSize }: { path: string; fileName: string; fileSize?: number }) {
  const dismiss = Navigation.useDismiss()
  const [dump, setDump] = useState<string | null>(null)
  const [error, setError] = useState(false)
  const [meta, setMeta] = useState<HexDumpResult | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const data = await FileManager.readAsData(path)
        const buf = data.toArrayBuffer()
        const bytes = new Uint8Array(buf)
        const result = formatHexDump(bytes)
        if (!cancelled) {
          setDump(result.text)
          setMeta(result)
        }
      } catch (e) {
        console.log("Hex 预览失败:", e)
        if (!cancelled) setError(true)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [path])

  const controller = useMemo(() => {
    if (dump == null) return null
    return new EditorController({ content: dump, ext: "txt", readOnly: true })
  }, [dump])

  useEffect(() => {
    return () => {
      controller?.dispose()
    }
  }, [controller])

  return (
    <NavigationStack>
      <VStack spacing={0} frame={{ maxWidth: "infinity", maxHeight: "infinity" }}
        navigationTitle={fileName}
        navigationBarTitleDisplayMode="inline"
        toolbar={{
          topBarTrailing: [
            <Button key="close" title="关闭" action={() => dismiss()} />,
          ],
        }}
      >
        <VStack spacing={4} padding={16} alignment="leading">
          <HStack spacing={10} alignment="center">
            <Image systemName="number" frame={{ width: 22, height: 22 }} foregroundStyle="systemOrange" />
            <Text font="headline">Hex 二进制预览</Text>
          </HStack>
          <Text font="caption" foregroundStyle="secondaryLabel">
            {meta ? `${fmtSize(meta.total)} · 共 ${meta.total} 字节${meta.shown < meta.total ? ` · 仅显示前 ${meta.shown} 字节（${Math.round((meta.shown / meta.total) * 100)}%）` : ""}` : fmtSize(fileSize ?? 0)}
            {" · 只读"}
          </Text>
        </VStack>
        <Divider />
        {error ? (
          <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }} alignment="center" spacing={12}>
            <Image systemName="exclamationmark.triangle" foregroundStyle="systemOrange" frame={{ width: 48, height: 48 }} />
            <Text font="body" foregroundStyle="secondaryLabel">无法读取文件内容</Text>
          </VStack>
        ) : controller ? (
          <Editor
            background="#FFFFFF"
            controller={controller}
            searchEnabled
            showAccessoryView={true}
            scriptName={fileName}
            frame={{ maxWidth: "infinity", maxHeight: "infinity" }}
          />
        ) : (
          <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
            <Text padding={16} foregroundStyle="secondaryLabel">加载中...</Text>
          </VStack>
        )}
      </VStack>
    </NavigationStack>
  )
}
