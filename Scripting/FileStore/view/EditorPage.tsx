// 统一 EditorController+Editor 通用组件

// 三种模式：
//   fullscreen — 全屏 inline 编辑器（NavigationStack + 系统导航栏 + 工具栏更多按钮 + 原生搜索 + 自动保存）
//   present    — 导航栈弹出编辑器（NavigationStack + 关闭按钮 + 工具栏更多按钮 + 原生搜索 + 自动保存）
//   preview    — 分享预览编辑器（NavigationStack + 文件头部 + 原生搜索 + 无自动保存）

import { useColorScheme, Navigation, NavigationStack, VStack, HStack, Text, Button, Divider, Image, useState, useEffect, useMemo, useRef, Editor, Path, EmptyView, Menu, ScrollView, Markdown, Script, ZStack } from "scripting"
import { getEditorExt } from "../manager/editorConfig"
import { getFileIcon, fmtSize, langMap, ensureLocalFile, isPlausibleText, uniquePath } from "../manager/utils"
import { minifyJSPreserveNames, minifyJSPreserveNamesAndComments, minifyJSAggressive } from "../manager/jsFormatter"
import { minifyHTML } from "../manager/htmlFormatter"
import { formatWithPrettier } from "../manager/prettierFormatter"
import { showToast } from "../manager/ToastManager"
import { HexPreviewPage } from "./HexPreviewPage"
import { ToastOverlay } from "./ToastOverlay"

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

/** 单遍扫描统计行数与字数，避免 split 创建大数组 */
function countLinesAndWords(text: string): { lineCount: number; wordCount: number } {
  if (text.length === 0) return { lineCount: 0, wordCount: 0 }
  let lineCount = 1
  let wordCount = 0
  let inWord = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (ch === '\n') lineCount++
    if (ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r') {
      inWord = false
    } else if (!inWord) {
      inWord = true
      wordCount++
    }
  }
  return { lineCount, wordCount }
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

  /** 挂载后弹 Toast 通知消息（如“已保存到 File Store”） */
  savedMessage?: string
}

export function EditorPage(props: EditorPageProps) {
  const { path, content: initialContent, fileName: propFileName, fileSize: propFileSize, mode = "fullscreen", onClose, scrollToLine, savedMessage } = props

  const fileName = propFileName || Path.basename(path)
  const ext = Path.extname(fileName)
  const normalizedExt = ext.toLowerCase()
  const isMarkdownFile = normalizedExt === ".md"
  const isHTMLFile = normalizedExt === ".html" || normalizedExt === ".htm"
  const isSVGFile = normalizedExt === ".svg"
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
  // 文件未能解码为文本（二进制/未知编码）时置 true：整个会话禁用保存，
  // 切换编码成功重新加载后自动恢复。
  const [decodeFailed, setDecodeFailed] = useState(false)
  const [loadTrigger, setLoadTrigger] = useState(0)
  // 格式化/压缩进行中标记（用于展示“正在格式化”提示，并防止重入）
  const [formatting, setFormatting] = useState(false)

  const handleEncodingChange = async (newEncoding: string) => {
    if (newEncoding === encoding) return
    if (mode === "preview") return
    try {
      await flushFinalSave()
    } catch (e) {
      console.log("切换编码前保存失败:", e)
      showToast("保存失败，未切换编码")
      return
    }
    setLoadError(false)
    setSaveEnabled(false)
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
    setReady(false)
    setContent(null)
    setEncoding(newEncoding)
    setLoadTrigger(t => t + 1)
  }

  /**
   * 统一执行格式化/压缩：结果通过编辑器的 selectAll + replaceSelection 写回
   * （避免直接赋值 content 触发整份文档重载卡顿），完成后排队保存。
   *
   * 说明：terser/prettier 解析大文件非常消耗 CPU，且本环境 Thread.runInBackground 里的
   * JS 计算不走 JIT（实测慢 ~7 倍），也没有 Worker，因此只能保持主线程直接调用。
   * 大文件先弹窗确认并展示提示条、超大文件直接拒绝，避免界面长时间无响应甚至崩溃。
   */
  const FORMAT_WARN_LIMIT = 256 * 1024 // 超过该字符数先弹窗确认 + 展示提示条
  const FORMAT_HARD_LIMIT = 3 * 1024 * 1024 // 超过该字符数直接拒绝（防止卡死/崩溃）

  const runFormatting = async (compute: (current: string) => Promise<string> | string) => {
    const controller = controllerRef.current
    if (!controller || formattingRef.current) return

    const size = controller.content.length
    if (size > FORMAT_HARD_LIMIT) {
      showToast(`文件过大（${fmtSize(size)}），为避免卡顿/崩溃已取消格式化`)
      return
    }
    if (size > FORMAT_WARN_LIMIT) {
      const ok = await Dialog.confirm({
        title: "继续格式化？",
        message: `文件较大（${fmtSize(size)}），处理可能需要较长时间，期间界面可能暂时无响应。是否继续？`,
        cancelLabel: "取消",
        confirmLabel: "继续",
      })
      if (!ok) return
    }

    const showBanner = size > FORMAT_WARN_LIMIT
    formattingRef.current = true
    if (showBanner) {
      setFormatting(true)
      // 让出一次事件循环，使提示条先渲染出来，再开始阻塞主线程的重计算
      await new Promise<void>((resolve) => { setTimeout(() => resolve(), 50) })
    }
    try {
      const formatted = await compute(controller.content)
      const target = controllerRef.current
      if (!target) return
      target.selectAll()
      target.replaceSelection(formatted)
      void enqueueSave(formatted, actualEncodingRef.current)
    } catch (e) {
      console.log("格式化失败:", e)
    } finally {
      formattingRef.current = false
      if (showBanner) setFormatting(false)
    }
  }

  const handleFormat = async () => {
    if (!controllerRef.current) return
    if (isJSONFile) {
      const current = controllerRef.current.content
      try {
        const parsed = JSON.parse(current.replace(/^\uFEFF/, ""))
        const formatted = `${JSON.stringify(parsed, null, 2)}\n`
        controllerRef.current.selectAll()
        controllerRef.current.replaceSelection(formatted)
        await enqueueSave(formatted, actualEncodingRef.current)
        return
      } catch (e) {
        console.log("格式化失败:", e)
        showToast("JSON格式化失败：文件中存在无效语法")
      }
      return
    }
    await runFormatting((current) => formatWithPrettier(current, fileName))
  }
  const handleJSPreserveMinify = async () => {
    await runFormatting((current) => minifyJSPreserveNames(current))
  }
  const handleJSAggressiveMinify = async () => {
    await runFormatting((current) => minifyJSAggressive(current))
  }
  const handleJSPreserveNamesAndComments = async () => {
    await runFormatting((current) => minifyJSPreserveNamesAndComments(current))
  }
  const handleJSONMinify = async () => {
    if (!controllerRef.current) return
    try {
      const parsed = JSON.parse(controllerRef.current.content.replace(/^\uFEFF/, ""))
      const minified = JSON.stringify(parsed)
      controllerRef.current.selectAll()
      controllerRef.current.replaceSelection(minified)
      await enqueueSave(minified, actualEncodingRef.current)
    } catch (e) {
      console.log("JSON压缩失败:", e)
      showToast("JSON压缩失败：文件中存在无效语法")
    }
  }
  const handleHTMLMinify = async () => {
    await runFormatting((current) => minifyHTML(current))
  }
  const handleHTMLCSSMinify = async () => {
    await runFormatting((current) => minifyHTML(current, true))
  }
  const handleHTMLFormat = async () => {
    await runFormatting((current) => formatWithPrettier(current, ".html"))
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
  const handleSVGPreview = async () => {
    if (!controllerRef.current) return
    const webView = new WebViewController()
    const previewHTML = `<!doctype html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: light dark; }
    html, body { min-height: 100%; margin: 0; background: #FFFFFF; }
    @media (prefers-color-scheme: dark) {
      html, body { background: #060606; }
    }
  </style>
</head>
<body>${controllerRef.current.content}</body>
</html>`
    try {
      await webView.loadHTML(previewHTML, `file://${Path.dirname(path)}/`)
      await webView.present({ navigationTitle: fileName })
    } catch (e) {
      console.log("SVG预览失败:", e)
    } finally {
      webView.dispose()
    }
  }
  const handleMarkdownFormat = async () => {
    await runFormatting((current) => formatWithPrettier(current, ".md"))
  }
  const handleMarkdownPreview = async () => {
    if (!controllerRef.current) return
    await Navigation.present({
      element: <MarkdownPreview content={controllerRef.current.content} fileName={fileName} />,
      modalPresentationStyle: "fullScreen",
    })
  }

  // 二进制 Hex 预览：直接读原始字节转十六进制转储，独立只读页面，不经过解码也不写回。
  const handleHexPreview = async () => {
    try {
      await ensureLocalFile(path)
      await Navigation.present({
        element: <HexPreviewPage path={path} fileName={fileName} fileSize={propFileSize} />,
        modalPresentationStyle: "fullScreen",
      })
    } catch (e) {
      console.log("二进制预览失败:", e)
      showToast("二进制预览失败")
    }
  }

  // ── 挂载后弹 Toast（如“已保存到 File Store”） ──
  useEffect(() => {
    if (!savedMessage) return
    const t = setTimeout(() => showToast(savedMessage), 350)
    return () => clearTimeout(t)
  }, [savedMessage])

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

        // 大文件保护：编辑器不适合超大文本（整份读入内存 + EditorController 副本会卡死/崩溃）。
        // 与格式化硬限制同一思路，超过即拒绝并用提示引导使用 Hex 预览。
        const EDITOR_OPEN_HARD_LIMIT = 30 * 1024 * 1024 // 30MB
        if (fileSize > EDITOR_OPEN_HARD_LIMIT) {
          if (!cancelled) {
            setLoadError(true)
            showToast(`文件过大（${fmtSize(fileSize)}），请在编辑器中查看二进制预览或换用其它查看器`)
          }
          return
        }

        const isUsableText = (value: string | null | undefined) => {
          // 只有明确知道文件大小为 0 时才接受空字符串；stat 失败/未知大小不能把空字符串当成功。
          // 同时用 isPlausibleText 拦截二进制/解码失败产生的乱码（替换字符、NUL、控制字符）。
          return value != null && isPlausibleText(value) && (value.length > 0 || fileSize === 0)
        }

        const fallbackEncodings = ["utf-8", "utf-16", "gb18030", "gbk", "ascii"] as const
        for (const enc of fallbackEncodings) {
          try {
            const alt = await FileManager.readAsString(path, enc as any)
            if (isUsableText(alt)) {
              if (!cancelled) {
                setContent(alt)
                baseContentRef.current = alt
                setActualEncoding(enc)
                setEncoding(enc)
                setSaveEnabled(true)
                setDecodeFailed(false)
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
              if (alt != null && (alt.length > 0 || dataSize === 0) && isPlausibleText(alt)) {
                if (!cancelled) {
                  setContent(alt)
                  baseContentRef.current = alt
                  setActualEncoding(enc)
                  setEncoding(enc)
                  setSaveEnabled(true)
                  setDecodeFailed(false)
                  setLoadError(false)
                  setReady(true)
                }
                return
              }
            } catch { }
          }
          if (dataSize > 0) {
            try {
              // toDecodedString 会把坏字节替换成 U+FFFD，二进制文件解码后必然含替换字符 → 拒绝
              const decoded = data.toDecodedString("utf8")
              if (decoded != null && isPlausibleText(decoded)) {
                if (!cancelled) {
                  setContent(decoded)
                  baseContentRef.current = decoded
                  setEncoding("utf-8")
                  setSaveEnabled(true)
                  setDecodeFailed(false)
                  setLoadError(false)
                  setReady(true)
                }
                return
              }
            } catch { }
          }
        } catch { }

        if (!cancelled) {
          // 所有读取方式都失败（二进制/无法解码）时：
          // - 入口传入的内容若本身是合法文本才允许作为兜底（readTextFile 已过滤乱码）；
          // - 否则以空内容打开并标记 decodeFailed：编辑器禁用保存，避免把乱码/空白覆盖回原文件。
          const fallbackContent = initialContent && initialContent.length > 0 && isPlausibleText(initialContent) ? initialContent : ""
          setContent(fallbackContent)
          baseContentRef.current = fallbackContent
          setEncoding("utf-8")
          setSaveEnabled(fallbackContent.length > 0)
          setDecodeFailed(fallbackContent.length === 0)
          setLoadError(false)
          setReady(true)
        }
      } catch {
        if (!cancelled) {
          // 读取异常也不要阻止打开编辑器，优先使用入口内容兜底。
          // 兜底内容不是合法文本时禁用保存，避免把乱码/空白覆盖原文件。
          const fallbackContent = initialContent && initialContent.length > 0 && isPlausibleText(initialContent) ? initialContent : ""
          setContent(fallbackContent)
          baseContentRef.current = fallbackContent
          setEncoding("utf-8")
          setSaveEnabled(fallbackContent.length > 0)
          setDecodeFailed(fallbackContent.length === 0)
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
  const disposedRef = useRef(false)
  const saveQueueRef = useRef<Promise<void>>(Promise.resolve())
  const latestContentRef = useRef(initialContent ?? "")
  // 上次成功从磁盘加载的内容：用于判断编辑器内容是否有改动。
  // 未改动时关闭/退出不必写回，避免只读/安全域位置误报保存失败。
  const baseContentRef = useRef<string | null>(null)
  const saveEnabledRef = useRef(saveEnabled)
  const actualEncodingRef = useRef(actualEncoding)
  const decodeFailedRef = useRef(decodeFailed)
  const closingRef = useRef(false)
  const formattingRef = useRef(false)
  controllerRef.current = controller
  saveEnabledRef.current = saveEnabled
  actualEncodingRef.current = actualEncoding
  decodeFailedRef.current = decodeFailed

  const enqueueSave = async (contentToSave: string, encodingToSave: string): Promise<void> => {
    // 解码失败（二进制/未知编码）时绝不写回原文件，防止把乱码/错误文本覆盖进去。
    // 切换编码成功重新加载后 decodeFailed 会复位，保存自动恢复。
    if (decodeFailedRef.current) {
      console.log("跳过保存：文件未能成功解码为文本")
      return
    }
    const write = async () => {
      await FileManager.writeAsString(path, contentToSave, encodingToSave as any)
      // 已成功写盘：把它作为新的基线，后续关闭/退出时无需重复写回。
      baseContentRef.current = contentToSave
    }
    const pending = saveQueueRef.current.then(write, write)
    saveQueueRef.current = pending.catch((error) => {
      console.log("保存失败:", error)
    })
    return pending
  }

  const flushFinalSave = async (): Promise<void> => {
    if (mode === "preview") return
    if (saveTimerRef.current) {
      clearTimeout(saveTimerRef.current)
      saveTimerRef.current = null
    }
    const finalContent = controllerRef.current?.content ?? latestContentRef.current
    // 内容与磁盘加载结果一致时无需写回：避免只读/安全域位置在关闭时误报保存失败，
    // 也避免“仅查看未编辑”的会话产生不必要的写入。
    const unchanged = baseContentRef.current !== null && finalContent === baseContentRef.current
    if (!unchanged && (saveEnabledRef.current || finalContent.length > 0)) {
      latestContentRef.current = finalContent
      await enqueueSave(finalContent, actualEncodingRef.current)
    } else {
      await saveQueueRef.current
    }
  }

  useEffect(() => {
    if (!controller || mode === "preview") return

    latestContentRef.current = controller.content
    controller.onContentChanged = (newContent: string) => {
      latestContentRef.current = newContent
      // 解码失败（二进制/未知编码）：不自动保存，用户输入也不会重新启用保存；
      // 只能通过“编码”菜单切换编码成功重新加载后恢复。
      if (decodeFailedRef.current) return
      // 如果当前内容来自“解码失败后的空白兜底”，不要把空白自动写回原文件。
      // 用户真正输入了内容后再重新允许保存。
      if (!saveEnabledRef.current && newContent.length === 0) return
      if (!saveEnabledRef.current && newContent.length > 0) setSaveEnabled(true)

      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      const encodingToSave = actualEncodingRef.current
      saveTimerRef.current = setTimeout(() => {
        void enqueueSave(newContent, encodingToSave).catch(() => {})
      }, 1000)
    }

    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      if (controller) controller.onContentChanged = undefined
    }
  }, [controller, path, mode])

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

  // ============ 以下可以是条件逻辑和渲染 ============

  const handleSaveToFileStore = async () => {
    // 通过 App Group 共享目录 + URL scheme 跳转主 App 保存
    // 这样即使在扩展进程（分享进来编辑），也能正确保存到主 App 的 Documents/File Store
    if (!controllerRef.current) return
    const content = controllerRef.current.content
    if (!content) return
    const appGroupDir = FileManager.appGroupDocumentsDirectory
    if (!appGroupDir) {
      showToast("无法访问共享目录")
      return
    }
    const saveDir = Path.join(appGroupDir, "_editor_save")
    try {
      await FileManager.createDirectory(saveDir, true)
      const tmpPath = Path.join(saveDir, fileName)
      await FileManager.writeAsString(tmpPath, content, actualEncodingRef.current as any)
      const runURL = Script.createRunURLScheme(Script.name, {
        fileURL: tmpPath,
        action: "saveToFileStore",
      })
      await Safari.openURL(runURL)
    } catch (e) {
      console.log("保存到 File Store 失败:", e)
      showToast("保存失败")
    }
  }

  const handleClose = async () => {
    if (closingRef.current) return
    closingRef.current = true
    try {
      await flushFinalSave()
    } catch (e) {
      console.log("关闭前保存失败:", e)
      // 保存失败时不要无路可走（分享进来的文件常位于只读/安全域位置）：
      // 询问用户是否放弃更改直接退出，确认后仍然 dismiss，避免被困在页面上。
      const discard = await Dialog.confirm({
        title: "保存失败",
        message: "无法写回该文件（可能位置只读或已被移动）。放弃更改并退出？",
        cancelLabel: "取消",
        confirmLabel: "放弃更改退出",
      })
      if (!discard) {
        closingRef.current = false
        return
      }
      if (saveTimerRef.current) {
        clearTimeout(saveTimerRef.current)
        saveTimerRef.current = null
      }
      controllerRef.current?.dispose()
      disposedRef.current = true
      dismiss()
      onClose?.()
      return
    }
    controllerRef.current?.dispose()
    disposedRef.current = true
    dismiss()
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
    // 单遍扫描统计行数/字数，避免对大内容做 split 产生两份大数组（大文件会卡 UI）
    const stats = countLinesAndWords(c)
    return (
      <VStack spacing={4} padding={16} alignment="leading">
        <HStack spacing={10} alignment="center">
          <Image systemName={getFileIcon(ext, false)} frame={{ width: 22, height: 22 }} />
          <Text font="headline">{fileName}</Text>
        </HStack>
        <Text font="caption" foregroundStyle="secondaryLabel">
          {fmtSize(propFileSize ?? 0)} · {stats.lineCount} 行 · {stats.wordCount} 字 · {c.length} 字符
          {langMap[ext.toLowerCase()] ? ` · ${langMap[ext.toLowerCase()]}` : ""}
          {ext ? ` · ${ext}` : ""}
        </Text>
      </VStack>
    )
  }

  // ─── 格式化进行中提示条 ───
  const renderFormattingBanner = () => {
    if (!formatting) return <EmptyView />
    return (
      <HStack spacing={6} alignment="center" padding={{ vertical: 8, horizontal: 12 }}>
        <Image systemName="hourglass" foregroundStyle="secondaryLabel" frame={{ width: 16, height: 16 }} />
        <Text font="footnote" foregroundStyle="secondaryLabel">正在格式化大文件，请稍候…</Text>
      </HStack>
    )
  }

  // ─── 解码失败提示条（二进制/未知编码时禁用保存） ───
  const renderDecodeFailedBanner = () => {
    if (!decodeFailed) return <EmptyView />
    return (
      <VStack spacing={4} alignment="leading" padding={{ vertical: 8, horizontal: 12 }}>
        <HStack spacing={6} alignment="center">
          <Image systemName="exclamationmark.triangle.fill" foregroundStyle="systemOrange" frame={{ width: 16, height: 16 }} />
          <Text font="footnote" fontWeight="semibold">无法解码为文本</Text>
        </HStack>
        <Text font="footnote" foregroundStyle="secondaryLabel">
          该文件可能是二进制文件或使用了未知编码，已禁用保存（防止乱码覆盖原文件）。可在“编码”菜单切换编码后重新加载。
        </Text>
      </VStack>
    )
  }

  // ─── 各模式渲染 ───
  if (mode === "present") {
    return (
      <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
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
                <Button
                  title="保存到 File Store"
                  systemImage="folder.badge.plus"
                  action={handleSaveToFileStore}
                />
                <Divider />
                <Menu title="编码">
                  {ENCODING_OPTIONS.map((enc) => (
                    <Button
                      key={enc.value}
                      title={enc.label}
                      systemImage={actualEncoding === enc.value ? "checkmark" : undefined}
                      action={() => handleEncodingChange(enc.value)}
                    />
                  ))}
                  <Divider />
                  <Button title="二进制预览（Hex）" systemImage="number" action={handleHexPreview} />
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
                {isSVGFile && (
                  <Button title="预览 SVG" systemImage="eye" action={handleSVGPreview} />
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
          {renderDecodeFailedBanner()}
          {renderFormattingBanner()}
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
      <ToastOverlay />
      </ZStack>
    )
  }


  if (mode === "fullscreen") {
    return (
      <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <VStack spacing={1} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} tabBarVisibility="hidden"
        onDisappear={() => {
          if (!closingRef.current) void flushFinalSave()
        }}
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
                <Divider />
                <Button title="二进制预览（Hex）" systemImage="number" action={handleHexPreview} />
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
              {isSVGFile && (
                <Button title="预览 SVG" systemImage="eye" action={handleSVGPreview} />
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
        {renderDecodeFailedBanner()}
        {renderFormattingBanner()}
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
      <ToastOverlay />
      </ZStack>
    )
  }

  // preview 模式
  return (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
    <NavigationStack>
      <VStack ignoresSafeArea={{ regions: "container", edges: ["bottom"] }} alignment="leading" spacing={0}>
        {renderFileHeader()}
        <Divider />
        <Editor
          background={bgColor} controller={controller!} searchEnabled showAccessoryView={true} scriptName={fileName} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} />
      </VStack>
    </NavigationStack>
    <ToastOverlay />
    </ZStack>
  )
}