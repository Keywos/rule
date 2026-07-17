// 统一 EditorController+Editor 通用组件

// 三种模式：
//   fullscreen — 全屏 inline 编辑器（NavigationStack + 系统导航栏 + 工具栏更多按钮 + 原生搜索 + 自动保存）
//   present    — 导航栈弹出编辑器（NavigationStack + 关闭按钮 + 工具栏更多按钮 + 原生搜索 + 自动保存）
//   preview    — 分享预览编辑器（NavigationStack + 文件头部 + 原生搜索 + 无自动保存）

import { useColorScheme, Navigation, NavigationStack, VStack, HStack, Text, Button, Divider, Image, useState, useEffect, useMemo, useRef, Editor, Path, EmptyView, Menu, ScrollView, Markdown } from "scripting"
import { getEditorExt } from "../manager/editorConfig"
import { getFileIcon, fmtSize, langMap, ensureLocalFile } from "../manager/utils"
import { minifyJSPreserveNames, minifyJSPreserveNamesAndComments, minifyJSAggressive } from "../manager/jsFormatter"
import { minifyHTML } from "../manager/htmlFormatter"
import { formatWithPrettier } from "../manager/prettierFormatter"
import { showToast } from "../manager/ToastManager"

function MarkdownPreview({ content, fileName }: { content: string; fileName: string }) {
  const dismiss = Navigation.useDismiss()
   const colorSchemeMd = useColorScheme()
    const bgColor = colorSchemeMd === 'dark' ? '#17181C' : '#FFFFFF'
  return (
    <NavigationStack>
      <ScrollView
        background={bgColor}
        navigationTitle={fileName}
        navigationBarTitleDisplayMode="inline"
        toolbar={{ topBarTrailing: [<Button key="close" title="关闭" action={() => dismiss()} />] }}
      >
        <Markdown
        safeAreaPadding={{ top: 20, horizontal: 8 }} content={content} theme="github" useDefaultHighlighterTheme scrollable={false} />
      </ScrollView>
    </NavigationStack>
  )
}

const ENCODING_OPTIONS = [
  { value: "utf-8", label: "UTF-8" },
  { value: "utf-16", label: "UTF-16" },
  { value: "ascii", label: "ASCII" },
  { value: "gbk", label: "GBK (简体中文)" },
  { value: "gb18030", label: "GB18030 (中文)" },
  { value: "shiftJIS", label: "Shift-JIS (日本語)" },
  { value: "japaneseEUC", label: "EUC-JP (日本語)" },
  { value: "isoLatin1", label: "ISO Latin 1" },
  { value: "windowsCP1252", label: "Windows-1252" },
  { value: "utf16LittleEndian", label: "UTF-16 LE" },
  { value: "utf16BigEndian", label: "UTF-16 BE" },
] as const

export interface EditorPageProps {
  /** 文件路径 */
  path: string
  /** 预读内容（preview 模式必传；其他模式可选，不传则自动读文件） */
  content?: string
  /** 文件名（preview 模式必传；其他模式可选，自动从 path 取 basename） */
  fileName?: string
  /** 文件大小（仅 preview 模式头部显示用） */
  fileSize?: number

  // ── 展示模式 ──
  /** fullscreen = Home/Mount 风格; present = 弹出编辑; preview = 分享预览 */
  mode?: "fullscreen" | "present" | "preview"

  /** present 模式专用：关闭后的回调（用于 openEditorDirectly resolve） */
  onClose?: () => void

  /** 深度搜索结果跳转：打开后自动滚动到指定行（1-based） */
  scrollToLine?: number
}

export function EditorPage(props: EditorPageProps) {
  const { path, content: initialContent, fileName: propFileName, fileSize: propFileSize, mode = "fullscreen", onClose, scrollToLine } = props

  const fileName = propFileName || Path.basename(path)
  const ext = Path.extname(fileName)
  const normalizedExt = ext.toLowerCase()
  const isMarkdownFile = normalizedExt === ".md"
  const isHTMLFile = normalizedExt === ".html" || normalizedExt === ".htm"
  const isJavaScriptFile = [".js", ".mjs", ".cjs", ".jsx"].includes(normalizedExt)
  const isJSONFile = normalizedExt === ".json"
  const editorExt = getEditorExt(ext)

  // ============ 所有 hooks 必须在此，不能有任何条件 return 分割 ============
  const colorScheme = useColorScheme()
  const bgColor = colorScheme === 'dark' ? '#0c1016' : '#FFFFFF'

  // 非 preview 模式不要直接信任入口传入的 initialContent：
  // 有些编码/安全域文件会在入口处被读成空字符串，导致编辑器一直空白。
  // 这里统一重新从文件路径读取；失败时再用 initialContent 兜底。
  const [content, setContent] = useState(mode === "preview" ? (initialContent ?? null) : null)
  const [ready, setReady] = useState(mode === "preview" ? !!initialContent : false)
  const [loadError, setLoadError] = useState(false)
  const [encoding, setEncoding] = useState<string>("utf-8")       // 用户选择
  const [actualEncoding, setActualEncoding] = useState<string>("utf-8") // 实际读取
  // 只有确认内容是成功读取/用户明确编辑后，才允许写回文件。
  // 防止编码切换解码失败得到空字符串，然后自动保存/关闭保存把原文件清空。
  const [saveEnabled, setSaveEnabled] = useState(mode === "preview" ? false : !!(initialContent && initialContent.length > 0))
  const [loadTrigger, setLoadTrigger] = useState(0)

  const handleEncodingChange = async (newEncoding: string) => {
    if (newEncoding === encoding) return
    if (mode === "preview") return
    setLoadError(false)
    setSaveEnabled(false)
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
    setReady(false)
    setContent(null)
    setEncoding(newEncoding)
    setLoadTrigger(t => t + 1)
  }

  const handleFormat = async () => {
    if (!controllerRef.current) return
    const current = controllerRef.current.content
    try {
      if (isJSONFile) {
        const parsed = JSON.parse(current.replace(/^\uFEFF/, ""))
        const formatted = `${JSON.stringify(parsed, null, 2)}\n`
        controllerRef.current.selectAll()
        controllerRef.current.replaceSelection(formatted)
        await FileManager.writeAsString(path, formatted, actualEncoding as any)
        return
      }
      controllerRef.current.content = await formatWithPrettier(current, fileName)
    } catch (e) {
      console.log("格式化失败:", e)
      if (isJSONFile) {
        showToast("JSON格式化失败：文件中存在无效语法")
      }
    }
  }
  const handleJSPreserveMinify = async () => {
    if (!controllerRef.current) return
    const current = controllerRef.current.content
    try {
      controllerRef.current.content = await minifyJSPreserveNames(current)
    } catch (e) {
      console.log("JS压缩(保留变量名)失败:", e)
    }
  }
  const handleJSAggressiveMinify = async () => {
    if (!controllerRef.current) return
    const current = controllerRef.current.content
    try {
      controllerRef.current.content = await minifyJSAggressive(current)
    } catch (e) {
      console.log("JS压缩(不保留变量名)失败:", e)
    }
  }
  const handleJSPreserveNamesAndComments = async () => {
    if (!controllerRef.current) return
    const current = controllerRef.current.content
    try {
      controllerRef.current.content = await minifyJSPreserveNamesAndComments(current)
    } catch (e) {
      console.log("JS压缩(保留注释/变量名)失败:", e)
    }
  }
  const handleJSONMinify = async () => {
    if (!controllerRef.current) return
    try {
      const parsed = JSON.parse(controllerRef.current.content.replace(/^\uFEFF/, ""))
      const minified = JSON.stringify(parsed)
      controllerRef.current.selectAll()
      controllerRef.current.replaceSelection(minified)
      await FileManager.writeAsString(path, minified, actualEncoding as any)
    } catch (e) {
      console.log("JSON压缩失败:", e)
      showToast("JSON压缩失败：文件中存在无效语法")
    }
  }
  const handleHTMLMinify = () => {
    if (!controllerRef.current) return
    try {
      controllerRef.current.content = minifyHTML(controllerRef.current.content)
    } catch (e) {
      console.log("HTML压缩失败:", e)
    }
  }
  const handleHTMLCSSMinify = () => {
    if (!controllerRef.current) return
    try {
      controllerRef.current.content = minifyHTML(controllerRef.current.content, true)
    } catch (e) {
      console.log("HTML及CSS压缩失败:", e)
    }
  }
  const handleHTMLFormat = async () => {
    if (!controllerRef.current) return
    try {
      controllerRef.current.content = await formatWithPrettier(controllerRef.current.content, ".html")
    } catch (e) {
      console.log("HTML格式化失败:", e)
    }
  }
  const handleHTMLPreview = async () => {
    if (!controllerRef.current) return
    const webView = new WebViewController()
    try {
      await webView.loadHTML(controllerRef.current.content, `file://${Path.dirname(path)}/`)
      await webView.present({ fullscreen: true, navigationTitle: fileName })
    } catch (e) {
      console.log("HTML预览失败:", e)
    } finally {
      webView.dispose()
    }
  }
  const handleMarkdownFormat = async () => {
    if (!controllerRef.current) return
    try {
      controllerRef.current.content = await formatWithPrettier(controllerRef.current.content, ".md")
    } catch (e) {
      console.log("Markdown格式化失败:", e)
    }
  }
  const handleMarkdownPreview = async () => {
    if (!controllerRef.current) return
    await Navigation.present({
      element: <MarkdownPreview content={controllerRef.current.content} fileName={fileName} />,
      modalPresentationStyle: "fullScreen",
    })
  }

  useEffect(() => {
    // preview 模式使用传进来的内容，不从文件读；其它模式必须从文件重新读取，避免 initialContent 为空导致空白。
    if (mode === "preview") return

    let cancelled = false
    const load = async () => {
      try {
        await ensureLocalFile(path)
        let fileSize = -1
        try {
          const stat = await FileManager.stat(path)
          fileSize = typeof stat.size === "number" ? stat.size : -1
        } catch { }
        const isUsableText = (value: string | null | undefined) => value != null && (value.length > 0 || fileSize === 0)

        const fallbackEncodings = ["utf-8", "utf-16", "gb18030", "gbk", "ascii"] as const
        for (const enc of fallbackEncodings) {
          try {
            const alt = await FileManager.readAsString(path, enc as any)
            console.log(enc)
            if (isUsableText(alt)) {
              if (!cancelled) {
                setContent(alt)
                setActualEncoding(enc)
                setEncoding(enc)
                setSaveEnabled(true)
                setLoadError(false)
                setReady(true)
              }
              return
            }
          } catch { }
        }

        // readAsString 失败/返回空时，直接从 Data 解码兜底，避免非空文件打开空白。
        try {
          const data = await FileManager.readAsData(path)
          const dataSize = data?.size ?? 0
          for (const enc of fallbackEncodings) {
            try {
              const alt = data.toRawString(enc as any)
              if (alt != null && (alt.length > 0 || dataSize === 0)) {
                if (!cancelled) {
                  setContent(alt)
                  setActualEncoding(enc)
                  setEncoding(enc)
                  setSaveEnabled(true)
                  setLoadError(false)
                  setReady(true)
                }
                return
              }
            } catch { }
          }
          if (dataSize > 0) {
            try {
              const decoded = data.toDecodedString("utf8")
              if (!cancelled) {
                setContent(decoded)
                setEncoding("utf-8")
                setSaveEnabled(true)
                setLoadError(false)
                setReady(true)
              }
              return
            } catch { }
          }
        } catch { }

        if (!cancelled) {
          // 所有读取方式都失败时，优先使用入口传入的非空内容；再不行才空内容打开。
          // 如果只能空内容打开，禁止保存，避免把原文件覆盖成空文件。
          const fallbackContent = initialContent && initialContent.length > 0 ? initialContent : ""
          setContent(fallbackContent)
          setEncoding("utf-8")
          setSaveEnabled(fallbackContent.length > 0)
          setLoadError(false)
          setReady(true)
        }
      } catch {
        if (!cancelled) {
          // 读取异常也不要阻止打开编辑器，优先使用入口内容兜底。
          // 如果只能空内容打开，禁止保存，避免把原文件覆盖成空文件。
          const fallbackContent = initialContent && initialContent.length > 0 ? initialContent : ""
          setContent(fallbackContent)
          setEncoding("utf-8")
          setSaveEnabled(fallbackContent.length > 0)
          setLoadError(false)
          setReady(true)
        }
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [path, initialContent, mode, loadTrigger])

  // ─── 创建 EditorController ───
  const controller = useMemo(() => {
    if (content == null) return null
    return new EditorController({
      content,
      ext: editorExt,
      readOnly: false,
    })
  }, [content, editorExt])

  // ─── 自动保存（preview 模式无自动保存） ───
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const controllerRef = useRef<EditorController | null>(null)
  controllerRef.current = controller
  const disposedRef = useRef(false)

  useEffect(() => {
    if (!controller || mode === "preview") return

    controller.onContentChanged = (newContent: string) => {
      // 如果当前内容来自“解码失败后的空白兜底”，不要把空白自动写回原文件。
      // 用户真正输入了内容后再重新允许保存。
      if (!saveEnabled && newContent.length === 0) return
      if (!saveEnabled && newContent.length > 0) setSaveEnabled(true)

      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      saveTimerRef.current = setTimeout(async () => {
        try {
          await FileManager.writeAsString(path, newContent, actualEncoding as any)
        } catch (e) {
          console.log("自动保存失败:", e)
        }
      }, 1000)
    }

    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      // 消除 onContentChanged 回调残留
      if (controller) controller.onContentChanged = undefined
    }
  }, [controller, path, mode, encoding, saveEnabled])

  // ─── 释放 controller ───
  useEffect(() => {
    return () => {
      if (!disposedRef.current) {
        controller?.dispose()
      }
    }
  }, [controller])

  // ─── 跳转到指定行（深度搜索跳转） ───
  const scrollToLineRef = useRef(scrollToLine)
  scrollToLineRef.current = scrollToLine
  const scrollCancelledRef = useRef(false)
  useEffect(() => {
    if (!controller) return
    const line = scrollToLineRef.current
    if (typeof line !== "number" || line <= 0) return

    // 多次尝试，等待 Editor 组件完全挂载
    let attempts = 0
    const maxAttempts = 8
    const retryMs = 400
    scrollCancelledRef.current = false

    function tryScroll() {
      if (scrollCancelledRef.current) return
      attempts++
      try {
        controller!.scrollToLine(line as number)
        console.log("scrollToLine 行" + line + " (尝试" + attempts + ")")
      } catch (e) {
        console.log("scrollToLine 尝试" + attempts + "失败:", e)
      }
      if (attempts < maxAttempts && !scrollCancelledRef.current) {
        setTimeout(tryScroll, retryMs)
      }
    }

    const timer = setTimeout(tryScroll, 600)
    return () => {
      clearTimeout(timer)
      scrollCancelledRef.current = true
    }
  }, [controller])

  // ─── present 模式的关闭（不能在条件分支内调用 Navigation.useDismiss） ───
  const dismiss = Navigation.useDismiss()
  const presentDismiss = mode === "present" ? dismiss : undefined

  // ============ 以下可以是条件逻辑和渲染 ============

  const handleClose = () => {
    // 保存最终内容
    if (controllerRef.current && mode !== "preview") {
      const timer = saveTimerRef.current
      if (timer) clearTimeout(timer)
      const finalContent = controllerRef.current.content
      // 解码失败只得到空内容时，关闭也不能把原文件覆盖为空。
      if (saveEnabled || finalContent.length > 0) {
        FileManager.writeAsString(path, finalContent, actualEncoding as any).catch(() => { })
      }
    }
    controllerRef.current?.dispose()
    disposedRef.current = true
    presentDismiss?.()
    onClose?.()
  }

  // ─── 加载 / 错误状态（preview 模式不展示加载状态） ───
  if (mode !== "preview") {
    if (!ready) {
      return (
        <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
          <Text padding={16} foregroundStyle="secondaryLabel">
            加载中...
          </Text>
        </VStack>
      )
    }
    if (loadError || !controller) {
      return (
        <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
          <Text padding={16} foregroundStyle="secondaryLabel">
            无法打开文件
          </Text>
        </VStack>
      )
    }
  }

  // ─── 渲染函数 ───

  // ─── 文件头部（仅 preview 模式） ───
  const renderFileHeader = () => {
    if (mode !== "preview") return <EmptyView />
    const c = content ?? ""
    const initLines = c.split("\n")
    const initWords = c.split(/\s+/).filter((w) => w.length > 0).length
    return (
      <VStack spacing={4} padding={16} alignment="leading">
        <HStack spacing={10} alignment="center">
          <Image systemName={getFileIcon(ext, false)} frame={{ width: 22, height: 22 }} />
          <Text font="headline">{fileName}</Text>
        </HStack>
        <Text font="caption" foregroundStyle="secondaryLabel">
          {fmtSize(propFileSize ?? 0)} · {initLines.length} 行 · {initWords} 字 · {c.length} 字符
          {langMap[ext.toLowerCase()] ? ` · ${langMap[ext.toLowerCase()]}` : ""}
          {ext ? ` · ${ext}` : ""}
        </Text>
      </VStack>
    )
  }

  // ─── 各模式渲染 ───
  if (mode === "present") {
    return (
      <NavigationStack>
        <VStack spacing={0} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} tabBarVisibility="hidden"
          navigationTitle={fileName}
          ignoresSafeArea={{ regions: "container", edges: ["bottom"] }}navigationBarTitleDisplayMode="inline"
          toolbar={{
            topBarLeading: [
              <Button key="close" title="关闭" systemImage="xmark" action={handleClose} />,
            ],
            topBarTrailing: [
              <Menu key="more-menu" title="" systemImage="ellipsis">
                <Menu title="编码">
                  {ENCODING_OPTIONS.map((enc) => (
                    <Button
                      key={enc.value}
                      title={enc.label}
                      systemImage={actualEncoding === enc.value ? "checkmark" : undefined}
                      action={() => handleEncodingChange(enc.value)}
                    />
                  ))}
                </Menu>
                <Divider />
                <Button
                  title="格式化"
                  action={handleFormat}
                />
                {isMarkdownFile && (
                  <Button
                    title="MD预览"
                    systemImage="eye"
                    action={handleMarkdownPreview}
                  />
                )}
                {isJavaScriptFile && (
                  <>
                    <Button title="保留变量名压缩" action={handleJSPreserveMinify} />
                    <Button title="保留注释、变量名压缩" action={handleJSPreserveNamesAndComments} />
                    <Button title="不保留变量名压缩" action={handleJSAggressiveMinify} />
                  </>
                )}
                {isJSONFile && (
                  <Button title="JSON压缩" action={handleJSONMinify} />
                )}
                {isHTMLFile && (
                  <>
                    <Button title="HTML压缩" action={handleHTMLMinify} />
                    <Button title="HTML压缩（含CSS）" action={handleHTMLCSSMinify} />
                    <Button title="HTML预览" systemImage="eye" action={handleHTMLPreview} />
                  </>
                )}
              </Menu>,
            ],
          }}
        >
          <Divider />
          <Editor
            background={bgColor}
            controller={controller!}
            searchEnabled
            showAccessoryView={true}
            scriptName={fileName}
            frame={{ maxWidth: "infinity", maxHeight: "infinity" }}
          />
        </VStack>
      </NavigationStack>
    )
  }


  if (mode === "fullscreen") {
    return (
      <VStack spacing={1} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} tabBarVisibility="hidden"
        ignoresSafeArea={{ regions: "container", edges: ["bottom"] }}
        navigationTitle={fileName}
        navigationBarTitleDisplayMode="inline"
        toolbar={{
          topBarTrailing: [
              <Menu key="encoding-menu" title="" systemImage="ellipsis">
              <Menu title="编码">
                {ENCODING_OPTIONS.map((enc) => (
                  <Button
                    key={enc.value}
                    title={enc.label}
                    systemImage={actualEncoding === enc.value ? "checkmark" : undefined}
                    action={() => handleEncodingChange(enc.value)}
                  />
                ))}
              </Menu>
              <Divider />
              <Button
                title="格式化"
                action={handleFormat}
              />
              {isMarkdownFile && (
                <Button
                  title="MD预览"
                  systemImage="eye"
                  action={handleMarkdownPreview}
                />
              )}
              {isJavaScriptFile && (
                <>
                  <Button title="保留变量名压缩" action={handleJSPreserveMinify} />
                  <Button title="保留注释、变量名压缩" action={handleJSPreserveNamesAndComments} />
                  <Button title="不保留变量名压缩" action={handleJSAggressiveMinify} />
                </>
              )}
              {isJSONFile && (
                <Button title="JSON压缩" action={handleJSONMinify} />
              )}
              {isHTMLFile && (
                <>
                  <Button title="HTML压缩" action={handleHTMLMinify} />
                  <Button title="HTML压缩（含CSS）" action={handleHTMLCSSMinify} />
                  <Button title="HTML预览" systemImage="eye" action={handleHTMLPreview} />
                </>
              )}
            </Menu>,
          ],
        }}
      >
        <Divider />

        <Editor

          background={bgColor}
          controller={controller!}
          searchEnabled
          showAccessoryView={true}
          scriptName={fileName}
          frame={{ maxWidth: "infinity", maxHeight: "infinity" }}
        />
      </VStack>
    )
  }

  // preview 模式
  return (
    <NavigationStack>
      <VStack ignoresSafeArea={{ regions: "container", edges: ["bottom"] }} alignment="leading" spacing={0}>
        {renderFileHeader()}
        <Divider />
        <Editor
          background={bgColor} controller={controller!} searchEnabled showAccessoryView={true} scriptName={fileName} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} />
      </VStack>
    </NavigationStack>
  )
}