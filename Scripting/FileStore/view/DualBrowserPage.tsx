// 双浏览器页面 - 左右两个文件浏览器并排显示，中间可拖拽调整比例

import { HStack, VStack, ZStack, Image, Text, GeometryReader, useState, useEffect, useRef, useCallback, useMemo, Path, Button, ToolbarItem } from "scripting"
import { GeneralBrowser } from "./GeneralBrowser"
import { AppSettings, readSettings, saveSettings } from "../manager/Settings"
import { Bookmark } from "../manager/BookmarkManager"
import { invalidateDirectoryCache, FileInfo, getFileCategory } from "../manager/utils"

interface DualBrowserPageProps {
  settings: AppSettings
  refreshKey: number
  setRefreshKey: (fn: (k: number) => number) => void
  onSettingsChange?: (settings: AppSettings) => void
  bookmarks?: Bookmark[]
  isHomeScreenHost?: boolean
  secondaryToolbarLeadingItems?: any
  // 保存到 File Store 后需要高亮的文件完整路径
  initialHighlightPath?: string
  // 是否处于焦点状态（TabView 当前 Tab）
  isFocused?: boolean
}

export function DualBrowserPage({
  settings,
  refreshKey,
  bookmarks,
  onSettingsChange,
  isHomeScreenHost,
  secondaryToolbarLeadingItems,
  initialHighlightPath,
  isFocused = true,
}: DualBrowserPageProps) {
  // 跨栏复制文件乐观更新注入
  const leftAddFilesRef = useRef<(files: FileInfo[]) => void>(() => { })
  const rightAddFilesRef = useRef<(files: FileInfo[]) => void>(() => { })
  const leftFolderCountUpdateRef = useRef<(folderPath: string, count: number) => void>(() => { })
  const rightFolderCountUpdateRef = useRef<(folderPath: string, count: number) => void>(() => { })

  // ── 左右各自独立的 settings（从专属持久键初始化，避免交叉覆盖） ──
  const [leftSettings, setLeftSettings] = useState<AppSettings>(() => ({
    ...settings,
    homeCurrentPath: settings.dualLeftPath || settings.homeCurrentPath,
    homeDirectoryBookmarkName: settings.dualLeftBookmarkName || settings.homeDirectoryBookmarkName,
  }))

  const [rightSettings, setRightSettings] = useState<AppSettings>(() => ({
    ...settings,
    homeCurrentPath: settings.dualRightPath || settings.homeCurrentPath,
    homeDirectoryBookmarkName: settings.dualRightBookmarkName || settings.homeDirectoryBookmarkName,
  }))

  // 父级 settings 变化时同步非导航字段（全屏等）
  useEffect(() => {
    setLeftSettings((prev) => ({ ...prev, showExitButton: settings.showExitButton }))
    setRightSettings((prev) => ({ ...prev, showExitButton: settings.showExitButton }))
  }, [settings])

  // 各自独立的 settings 变更处理器
  const handleLeftSettingsChange = useCallback((newSettings: AppSettings) => {
    // 检测导航变更 → 保存到专属键，同时保留对方的最新状态
    if (newSettings.homeCurrentPath !== leftSettings.homeCurrentPath) {
      saveSettings({
        ...settings,
        dualLeftPath: newSettings.homeCurrentPath,
        dualLeftBookmarkName: newSettings.homeDirectoryBookmarkName,
        dualRightPath: rightSettings.homeCurrentPath,
        dualRightBookmarkName: rightSettings.homeDirectoryBookmarkName,
      })
    }
    setLeftSettings(newSettings)
  }, [leftSettings, rightSettings, settings])

  const handleRightSettingsChange = useCallback((newSettings: AppSettings) => {
    if (newSettings.homeCurrentPath !== rightSettings.homeCurrentPath) {
      saveSettings({
        ...settings,
        dualRightPath: newSettings.homeCurrentPath,
        dualRightBookmarkName: newSettings.homeDirectoryBookmarkName,
        dualLeftPath: leftSettings.homeCurrentPath,
        dualLeftBookmarkName: leftSettings.homeDirectoryBookmarkName,
      })
    }
    setRightSettings(newSettings)
  }, [leftSettings, rightSettings, settings])

  // 左右各自独立的 refreshKey，互不影响
  const [leftKey, setLeftKey] = useState(0)
  const [rightKey, setRightKey] = useState(0)

  // ── 高亮新增或刚刚导入的文件 ──
  // GeneralBrowser 的 highlightFile 使用文件名，所以这里从完整路径提取 basename。
  const [leftHighlightFile, setLeftHighlightFile] =
    useState<string | undefined>(() =>
      initialHighlightPath
        ? Path.basename(initialHighlightPath)
        : undefined
    )

  const [rightHighlightFile, setRightHighlightFile] =
    useState<string | undefined>()

  useEffect(() => {
    if (!leftHighlightFile) return

    const target = leftHighlightFile

    const timer = setTimeout(() => {
      setLeftHighlightFile((current) =>
        current === target ? undefined : current
      )
    }, 3000)

    return () => clearTimeout(timer)
  }, [leftHighlightFile])

  useEffect(() => {
    if (!rightHighlightFile) return

    const target = rightHighlightFile

    const timer = setTimeout(() => {
      setRightHighlightFile((current) =>
        current === target ? undefined : current
      )
    }, 3000)

    return () => clearTimeout(timer)
  }, [rightHighlightFile])

  // 从 URL Scheme 保存到 File Store 后，高亮左栏对应文件 3 秒。
  useEffect(() => {
    if (!initialHighlightPath) return

    const fileName = Path.basename(initialHighlightPath)

    setLeftHighlightFile((current) =>
      current === fileName ? current : fileName
    )
  }, [initialHighlightPath])


  // 当全局 refreshKey 变化时，两边都刷新
  useEffect(() => {
    setLeftKey((k) => k + 1)
    setRightKey((k) => k + 1)
  }, [refreshKey])

  // ── 跨栏共享剪贴板
  const [sharedCopiedPath, setSharedCopiedPath] = useState<string | null>(null)

  const handleExternalCopy = useCallback((path: string) => {
    setSharedCopiedPath(path || null)
  }, [])

  // ── 左右各自当前目录（用于复制到对方） ──
  const [leftDir, setLeftDir] = useState<string>("")
  const [rightDir, setRightDir] = useState<string>("")

  const handleLeftDirChange = useCallback((dir: string) => {
    setLeftDir(dir)
  }, [])

  const handleRightDirChange = useCallback((dir: string) => {
    setRightDir(dir)
  }, [])

  // ── 布局相关状态（复制提示文案需要根据 layoutDir 区分左右/上下，须先于复制处理函数声明） ──
  // 左右比例 (0~1)，0.5 = 各占一半；从持久化设置恢复，退出后记住拖动条位置
  const [ratio, setRatio] = useState(typeof settings.dualRatio === "number" ? settings.dualRatio : 0.5)
  // 布局方向：horizontal（左右分栏）或 vertical（上下分栏）
  const [layoutDir, setLayoutDir] = useState(settings.dualLayoutDir as "horizontal" | "vertical")
  // 双栏显示开关：关闭时保留两侧路径、布局方向和比例
  const [isDualMode, setIsDualMode] = useState(settings.dualModeEnabled)

  // 把文件复制到右侧当前目录
  const handleCopyLeftToRight = useCallback(
    async (filePath: string) => {
      if (!rightDir) {
        await Dialog.alert({ title: "提示", message: "右侧尚未进入任何目录", buttonLabel: "确定" })
        return
      }
      try {
        const baseName = Path.basename(filePath)
        const ext = Path.extname(baseName)
        const nameBody = Path.basename(baseName, ext)
        let destPath = Path.join(rightDir, baseName)
        let counter = 1
        while (await FileManager.exists(destPath)) {
          destPath = Path.join(rightDir, `${nameBody}_${counter}${ext}`)
          counter++
        }
        await FileManager.copyFile(filePath, destPath)
        // 乐观更新：立即在右侧显示复制的文件（同步注入，不等 isDirectory）
        {
          const destExt = Path.extname(destPath)
          rightAddFilesRef.current([
            {
              name: Path.basename(destPath),
              path: destPath,
              isDirectory: false,
              isLink: false,
              size: 0,
              creationDate: Date.now(),
              modificationDate: Date.now(),
              extension: destExt,
              category: getFileCategory(destExt) as any,
              mimeType: "",
              icon: "doc.text",
              iconColor: "systemGray",
            },
          ])
        }
        // 复制完成后刷新右侧并高亮新文件
        invalidateDirectoryCache(rightDir)
        setRightHighlightFile(Path.basename(destPath))
        setRightKey((k) => k + 1)
        // setTimeout(() => setRightHighlightFile(undefined), 3000)
        // 左右分栏提示右侧，上下分栏提示下方
        showCopyToastAction(layoutDir === "horizontal" ? "已复制到右侧目录" : "已复制到下方目录")
      } catch (e) {
        console.log("复制到右侧目录失败:", e)
        await Dialog.alert({ title: "错误", message: "复制失败：" + String(e), buttonLabel: "确定" })
      }
    },
    [rightDir, layoutDir],
  )

  // 把文件复制到左侧当前目录
  const handleCopyRightToLeft = useCallback(
    async (filePath: string) => {
      if (!leftDir) {
        await Dialog.alert({ title: "提示", message: "左侧尚未进入任何目录", buttonLabel: "确定" })
        return
      }
      try {
        const baseName = Path.basename(filePath)
        const ext = Path.extname(baseName)
        const nameBody = Path.basename(baseName, ext)
        let destPath = Path.join(leftDir, baseName)
        let counter = 1
        while (await FileManager.exists(destPath)) {
          destPath = Path.join(leftDir, `${nameBody}_${counter}${ext}`)
          counter++
        }
        await FileManager.copyFile(filePath, destPath)
        // 乐观更新：立即在左侧显示复制的文件（同步注入，不等 isDirectory）
        {
          const destExt = Path.extname(destPath)
          leftAddFilesRef.current([
            {
              name: Path.basename(destPath),
              path: destPath,
              isDirectory: false,
              isLink: false,
              size: 0,
              creationDate: Date.now(),
              modificationDate: Date.now(),
              extension: destExt,
              category: getFileCategory(destExt) as any,
              mimeType: "",
              icon: "doc.text",
              iconColor: "systemGray",
            },
          ])
        }
        // 复制完成后刷新左侧并高亮新文件
        invalidateDirectoryCache(leftDir)
        setLeftHighlightFile(Path.basename(destPath))
        setLeftKey((k) => k + 1)
        // setTimeout(() => setLeftHighlightFile(undefined), 3000)
        // 左右分栏提示左侧，上下分栏提示上方
        showCopyToastAction(layoutDir === "horizontal" ? "已复制到左侧目录" : "已复制到上方目录")
      } catch (e) {
        console.log("复制到左侧目录失败:", e)
        await Dialog.alert({ title: "错误", message: "复制失败：" + String(e), buttonLabel: "确定" })
      }
    },
    [leftDir, layoutDir],
  )

  // 复制到对方目录的顶部提示
  const [showCopyToast, setShowCopyToast] = useState(false)
  const [copyToastMessage, setCopyToastMessage] = useState("")
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  // 组件卸载时清除活跃的 toast 超时，避免在已卸载的组件上 setState
  useEffect(
    () => () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current)
    },
    [],
  )

  const showCopyToastAction = (msg: string) => {
    setCopyToastMessage(msg)
    setShowCopyToast(true)
    if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current)
    copyTimeoutRef.current = setTimeout(() => setShowCopyToast(false), 2000)
  }

  /*   const handleToggleLayout = () => {
      setLayoutDir((prev) => (prev === "horizontal" ? "vertical" : "horizontal"))
    } */

  const dualModeToolbarItem = useMemo(() => (
    <ToolbarItem placement="topBarLeading">
      <Button
        title={isDualMode ? "关闭双栏模式" : "开启双栏模式"}
        systemImage={isDualMode ? "r.square.on.square.fill" : "r.square.fill"}
        action={() => {
          setIsDualMode((prev) => {
            const dualModeEnabled = !prev
            const newSettings = { ...settings, dualModeEnabled }
            saveSettings(newSettings)
            onSettingsChange?.(newSettings)
            return dualModeEnabled
          })
        }}
      />
    </ToolbarItem>
  ), [isDualMode, settings, onSettingsChange])

  // ── layoutDir 变化时持久化保存 ──
  // useEffect(() => {
  //   saveSettings({ ...settings, dualLayoutDir: layoutDir })
  // }, [layoutDir])

  // ── ratio 变化时持久化保存（拖动结束才更新，避免拖动过程中频繁写入） ──
  /*  useEffect(() => {
     const rounded = Math.round(ratio * 1000) / 1000;
     saveSettings({ ...settings, dualRatio: rounded });
   }, [ratio]); */

  // 拖拽松手后的比例保存
  const handleRatioChangeEnd = (newRatio: number) => {
    const rounded = Math.round(newRatio * 1000) / 1000
    setRatio(rounded)
    // 读取当前磁盘上的最新配置，防止覆盖左右栏刚刚切换的路径
    const currentSettings = readSettings()
    const nextSettings = { ...currentSettings, dualRatio: rounded }
    saveSettings(nextSettings)
    onSettingsChange?.(nextSettings)
  }

  // 切换横竖分栏布局的保存
  const handleToggleLayout = () => {
    const nextDir: "horizontal" | "vertical" = layoutDir === "horizontal" ? "vertical" : "horizontal"
    withAnimation(Animation.smooth({ duration: 0.4 }), () => setLayoutDir(nextDir))
    const currentSettings = readSettings()
    const nextSettings = { ...currentSettings, dualLayoutDir: nextDir }
    saveSettings(nextSettings)
    onSettingsChange?.(nextSettings)
  }

  const leftBrowser = useMemo(() => (
    <GeneralBrowser
      isHomePage={true}
      isHomeScreenHost={isHomeScreenHost}
      settings={leftSettings}
      onSettingsChange={handleLeftSettingsChange}
      refreshKey={leftKey}
      showFolderItemCounts={settings.showFolderItemCounts ?? true}
      highlightFile={leftHighlightFile}
      externalCopiedPath={sharedCopiedPath}
      onExternalCopy={handleExternalCopy}
      onDirChange={handleLeftDirChange}
      toolbarLeadingItems={dualModeToolbarItem}
      oppositeDirName={rightDir ? (layoutDir === "horizontal" ? "复制到右侧目录" : "复制到下方目录") : undefined}
      onCopyToOppositeDir={rightDir ? handleCopyLeftToRight : undefined}
      addFilesRef={leftAddFilesRef}
      folderCountUpdateRef={leftFolderCountUpdateRef}
      bookmarks={bookmarks}
      isFocused={isFocused}
      onFolderCountChanged={(folderPath, count) => rightFolderCountUpdateRef.current(folderPath, count)}
      onFilesAdded={(files) => {
        if (leftDir === rightDir && rightDir) rightAddFilesRef.current(files)
      }}
      onDropCompleted={() => setRightKey((key) => key + 1)}
    />
  ), [
    isHomeScreenHost, leftSettings, handleLeftSettingsChange, leftKey, settings.showFolderItemCounts,
    leftHighlightFile, sharedCopiedPath, handleExternalCopy, handleLeftDirChange, dualModeToolbarItem,
    rightDir, layoutDir, handleCopyLeftToRight, bookmarks, isFocused, leftDir,
  ])

  const rightBrowser = useMemo(() => (
    <GeneralBrowser
      isHomePage={true}
      isHomeScreenHost={isHomeScreenHost}
      settings={rightSettings}
      onSettingsChange={handleRightSettingsChange}
      refreshKey={rightKey}
      showFolderItemCounts={settings.showFolderItemCounts ?? true}
      highlightFile={rightHighlightFile}
      externalCopiedPath={sharedCopiedPath}
      onExternalCopy={handleExternalCopy}
      onDirChange={handleRightDirChange}
      toolbarLeadingItems={secondaryToolbarLeadingItems}
      oppositeDirName={leftDir ? (layoutDir === "horizontal" ? "复制到左侧目录" : "复制到上方目录") : undefined}
      onCopyToOppositeDir={leftDir ? handleCopyRightToLeft : undefined}
      initialLoadDelay={300}
      addFilesRef={rightAddFilesRef}
      folderCountUpdateRef={rightFolderCountUpdateRef}
      bookmarks={bookmarks}
      isFocused={isFocused}
      onFolderCountChanged={(folderPath, count) => leftFolderCountUpdateRef.current(folderPath, count)}
      onFilesAdded={(files) => {
        if (leftDir === rightDir && leftDir) leftAddFilesRef.current(files)
      }}
      onDropCompleted={() => setLeftKey((key) => key + 1)}
    />
  ), [
    isHomeScreenHost, rightSettings, handleRightSettingsChange, rightKey, settings.showFolderItemCounts,
    rightHighlightFile, sharedCopiedPath, handleExternalCopy, handleRightDirChange, secondaryToolbarLeadingItems,
    leftDir, layoutDir, handleCopyRightToLeft, bookmarks, isFocused, rightDir,
  ])

  return (
    <VStack
      ignoresSafeArea={{ edges: ["bottom"] }}
      toast={{
        isPresented: showCopyToast,
        onChanged: setShowCopyToast,
        content: (
          <HStack spacing={8}>
            <Image systemName="checkmark.circle.fill" foregroundStyle="white" />
            <Text foregroundStyle="white" font={13}>
              {copyToastMessage}
            </Text>
          </HStack>
        ),
        position: "top",
      }}
    >
      <GeometryReader>
        {(proxy) => {
          const totalW = proxy.size.width
          const totalH = proxy.size.height

          return (
            <ZStack animation={{ animation: Animation.smooth({ duration: 0.5 }), value: layoutDir }}>
              {/* ── 内容分栏（根据 layoutDir 选择左右或上下） ── */}
              {!isDualMode ? (
                <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }} spacing={0}>
                  {leftBrowser}
                </VStack>
              ) : layoutDir === "horizontal" ? (
                <HStack spacing={0}>
                  <VStack frame={{ width: Math.max(40, totalW * ratio) }} spacing={0}>
                    {leftBrowser}
                  </VStack>

                  <VStack frame={{ width: Math.max(40, totalW * (1 - ratio)) }} spacing={0}>
                    {rightBrowser}
                  </VStack>
                </HStack>
              ) : (
                <VStack spacing={0}>
                  <VStack frame={{ height: Math.max(40, totalH * ratio) }} spacing={0}>
                    {leftBrowser}
                  </VStack>

                  <VStack frame={{ height: Math.max(40, totalH * (1 - ratio)) }} spacing={0}>
                    {rightBrowser}
                  </VStack>
                </VStack>
              )}

              {isDualMode ? (
                <DraggableDivider
                  layoutDir={layoutDir}
                  totalW={totalW}
                  totalH={totalH}
                  ratio={ratio}
                  onDragEnd={handleRatioChangeEnd}
                  onToggleLayout={handleToggleLayout}
                />
              ) : null}

            </ZStack>
          )
        }}
      </GeometryReader>
    </VStack>
  )
}

// ── 单独的可拖拽分隔线组件（隔离 dragOffset 状态，避免拖动时重绘整个页面） ──
function DraggableDivider({
  layoutDir,
  totalW,
  totalH,
  ratio,
  onDragEnd,
  onToggleLayout,
}: {
  layoutDir: "horizontal" | "vertical"
  totalW: number
  totalH: number
  ratio: number
  onDragEnd: (newRatio: number) => void
  onToggleLayout: () => void
}) {
  // dragOffset 是本组件内部状态，变化时只重绘此组件和分隔线，不影响父级和两个 GeneralBrowser
  const [dragOffset, setDragOffset] = useState(0)
  // 拖拽标记：有实际拖动时抑制松手后的 tap 手势，避免拖到边缘时误触布局切换
  const wasDraggedRef = useRef(false)
  // 触感触发器：每次事件递增，触发 sensoryFeedback
  const [hapticTrigger, setHapticTrigger] = useState(0)
  const [hapticEndTrigger, setHapticEndTrigger] = useState(0)
  const [isSwitchingLayout, setIsSwitchingLayout] = useState(false)

  const splitCenterX = totalW * ratio - totalW / 2
  const splitCenterY = totalH * ratio - totalH / 2
  const previewOffset = layoutDir === "horizontal" ? { x: splitCenterX + dragOffset, y: 0 } : { x: 0, y: splitCenterY + dragOffset }

  const handleDragChanged = (details: {
    translation: {
      width: number
      height: number
    }
  }) => {
    const offset = layoutDir === "horizontal" ? details.translation.width : details.translation.height
    setDragOffset(offset)
    if (Math.abs(offset) > 5) {
      if (!wasDraggedRef.current) {
        // 首次有意义的拖拽移动 → 触感反馈
        setHapticTrigger((v) => v + 1)
      }
      wasDraggedRef.current = true
    }
  }

  const handleDragEnded = () => {
    const total = layoutDir === "horizontal" ? totalW : totalH
    if (total > 0) {
      const newRatio = ratio + dragOffset / total
      const clamped = Math.max(0.1, Math.min(0.9, newRatio))
      onDragEnd(clamped) // 只负责向上传递计算结果
    }
    setDragOffset(0)
    setHapticTrigger((v) => v + 1)
    setTimeout(() => {
      wasDraggedRef.current = false
    }, 100)
  }


  const handleTap = () => {
    if (wasDraggedRef.current) return
    setHapticTrigger((v) => v + 1)
    setIsSwitchingLayout(true)
    setTimeout(() => setIsSwitchingLayout(false), 200)
    // 立即切换布局，无需等待触感反馈（触感反馈异步执行不阻塞渲染）
    onToggleLayout()
  }


  return (
    <VStack
    //frame={layoutDir === 'horizontal' ? { width: 1, height: totalH } : { width: totalW, height: 1 }}
    //background={"rgba(128,128,128,0.5)"}
    //frame={layoutDir === 'horizontal' ? { width: 1, height: totalH } : { width: totalW, height: 1 }}
    //background={"rgba(128,128,128,0.5)"}
    >
      <VStack sensoryFeedback={{ trigger: hapticEndTrigger, feedback: "selection" }}>
        <VStack
          frame={layoutDir === "horizontal" ? { width: 35, height: 150 } : { width: 120, height: 35 }}
          background={"rgba(0,0,0,0.0001)"}
          offset={previewOffset}
          sensoryFeedback={{ trigger: hapticTrigger, feedback: "impact" }}
          onTapGesture={handleTap}
          onDragGesture={{
            minDistance: 0,
            coordinateSpace: "global",
            onChanged: handleDragChanged,
            onEnded: handleDragEnded,
          }}
        >
          <VStack
            frame={layoutDir === "horizontal" ? { width: 4, height: 130 } : { width: 100, height: 4 }}
            // background={isSwitchingLayout ? "rgba(55, 145, 170, 0.5)" : "regularMaterial"}
            overlay={<VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }} background="rgba(128,128,128,0.25)" />}
            clipShape="capsule"
          />
        </VStack>
      </VStack>
    </VStack>
  )
}
