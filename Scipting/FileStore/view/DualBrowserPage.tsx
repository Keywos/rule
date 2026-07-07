// 双浏览器页面 - 左右两个文件浏览器并排显示，中间可拖拽调整比例

import { HStack, VStack, ZStack, Image, Text, GeometryReader, useState, useEffect, useRef, useCallback, Path } from "scripting";
import { GeneralBrowser } from "./GeneralBrowser";
import { AppSettings, saveSettings } from "../manager/Settings";
import { invalidateDirectoryCache, FileInfo, getFileCategory } from "../manager/utils";

interface DualBrowserPageProps {
  settings: AppSettings;
  refreshKey: number;
  setRefreshKey: (fn: (k: number) => number) => void;
  onSettingsChange?: (settings: AppSettings) => void;
}

export function DualBrowserPage({ settings, refreshKey }: DualBrowserPageProps) {
  // 跨栏复制文件乐观更新注入
  const leftAddFilesRef = useRef<(files: FileInfo[]) => void>(() => {});
  const rightAddFilesRef = useRef<(files: FileInfo[]) => void>(() => {});
  const leftFolderCountUpdateRef = useRef<(folderPath: string, count: number) => void>(() => {});
  const rightFolderCountUpdateRef = useRef<(folderPath: string, count: number) => void>(() => {});

  // ── 左右各自独立的 settings（从专属持久键初始化，避免交叉覆盖） ──
  const [leftSettings, setLeftSettings] = useState<AppSettings>(() => ({
    ...settings,
    homeCurrentPath: settings.dualLeftPath || settings.homeCurrentPath,
    homeDirectoryBookmarkName: settings.dualLeftBookmarkName || settings.homeDirectoryBookmarkName,
  }));

  const [rightSettings, setRightSettings] = useState<AppSettings>(() => ({
    ...settings,
    homeCurrentPath: settings.dualRightPath || settings.homeCurrentPath,
    homeDirectoryBookmarkName: settings.dualRightBookmarkName || settings.homeDirectoryBookmarkName,
  }));

  // 父级 settings 变化时同步非导航字段（全屏等）
  useEffect(() => {
    setLeftSettings((prev) => ({ ...prev, showExitButton: settings.showExitButton }));
    setRightSettings((prev) => ({ ...prev, showExitButton: settings.showExitButton }));
  }, [settings]);

  // 各自独立的 settings 变更处理器
  const handleLeftSettingsChange = (newSettings: AppSettings) => {
    // 检测导航变更 → 保存到专属键，同时保留对方的最新状态
    if (newSettings.homeCurrentPath !== leftSettings.homeCurrentPath) {
      saveSettings({
        ...settings,
        dualLeftPath: newSettings.homeCurrentPath,
        dualLeftBookmarkName: newSettings.homeDirectoryBookmarkName,
        dualRightPath: rightSettings.homeCurrentPath,
        dualRightBookmarkName: rightSettings.homeDirectoryBookmarkName,
      });
    }
    setLeftSettings(newSettings);
  };

  const handleRightSettingsChange = (newSettings: AppSettings) => {
    if (newSettings.homeCurrentPath !== rightSettings.homeCurrentPath) {
      saveSettings({
        ...settings,
        dualRightPath: newSettings.homeCurrentPath,
        dualRightBookmarkName: newSettings.homeDirectoryBookmarkName,
        dualLeftPath: leftSettings.homeCurrentPath,
        dualLeftBookmarkName: leftSettings.homeDirectoryBookmarkName,
      });
    }
    setRightSettings(newSettings);
  };

  // 左右各自独立的 refreshKey，互不影响
  const [leftKey, setLeftKey] = useState(0);
  const [rightKey, setRightKey] = useState(0);

  // ── 高亮对方新增的文件 ──
  const [leftHighlightFile, setLeftHighlightFile] = useState<string>();
  const [rightHighlightFile, setRightHighlightFile] = useState<string>();

  // 当全局 refreshKey 变化时，两边都刷新
  useEffect(() => {
    setLeftKey((k) => k + 1);
    setRightKey((k) => k + 1);
  }, [refreshKey]);

  // ── 跨栏共享剪贴板
  const [sharedCopiedPath, setSharedCopiedPath] = useState<string | null>(null);

  const handleExternalCopy = useCallback((path: string) => {
    setSharedCopiedPath(path || null);
  }, []);

  // ── 左右各自当前目录（用于复制到对方） ──
  const [leftDir, setLeftDir] = useState<string>("");
  const [rightDir, setRightDir] = useState<string>("");

  const handleLeftDirChange = useCallback((dir: string) => {
    setLeftDir(dir);
  }, []);

  const handleRightDirChange = useCallback((dir: string) => {
    setRightDir(dir);
  }, []);

  // 把文件复制到右侧当前目录
  const handleCopyLeftToRight = useCallback(
    async (filePath: string) => {
      if (!rightDir) {
        await Dialog.alert({ title: "提示", message: "右侧尚未进入任何目录", buttonLabel: "确定" });
        return;
      }
      try {
        const baseName = Path.basename(filePath);
        const ext = Path.extname(baseName);
        const nameBody = Path.basename(baseName, ext);
        let destPath = Path.join(rightDir, baseName);
        let counter = 1;
        while (await FileManager.exists(destPath)) {
          destPath = Path.join(rightDir, `${nameBody}_${counter}${ext}`);
          counter++;
        }
        await FileManager.copyFile(filePath, destPath);
        // 乐观更新：立即在右侧显示复制的文件（同步注入，不等 isDirectory）
        {
          const destExt = Path.extname(destPath);
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
          ]);
        }
        // 复制完成后刷新右侧并高亮新文件
        invalidateDirectoryCache(rightDir);
        setRightHighlightFile(Path.basename(destPath));
        setRightKey((k) => k + 1);
        setTimeout(() => setRightHighlightFile(undefined), 3000);
        showCopyToastAction("已复制到右侧目录");
      } catch (e) {
        console.log("复制到右侧目录失败:", e);
        await Dialog.alert({ title: "错误", message: "复制失败：" + String(e), buttonLabel: "确定" });
      }
    },
    [rightDir],
  );

  // 把文件复制到左侧当前目录
  const handleCopyRightToLeft = useCallback(
    async (filePath: string) => {
      if (!leftDir) {
        await Dialog.alert({ title: "提示", message: "左侧尚未进入任何目录", buttonLabel: "确定" });
        return;
      }
      try {
        const baseName = Path.basename(filePath);
        const ext = Path.extname(baseName);
        const nameBody = Path.basename(baseName, ext);
        let destPath = Path.join(leftDir, baseName);
        let counter = 1;
        while (await FileManager.exists(destPath)) {
          destPath = Path.join(leftDir, `${nameBody}_${counter}${ext}`);
          counter++;
        }
        await FileManager.copyFile(filePath, destPath);
        // 乐观更新：立即在左侧显示复制的文件（同步注入，不等 isDirectory）
        {
          const destExt = Path.extname(destPath);
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
          ]);
        }
        // 复制完成后刷新左侧并高亮新文件
        invalidateDirectoryCache(leftDir);
        setLeftHighlightFile(Path.basename(destPath));
        setLeftKey((k) => k + 1);
        setTimeout(() => setLeftHighlightFile(undefined), 3000);
        showCopyToastAction("已复制到左侧目录");
      } catch (e) {
        console.log("复制到左侧目录失败:", e);
        await Dialog.alert({ title: "错误", message: "复制失败：" + String(e), buttonLabel: "确定" });
      }
    },
    [leftDir],
  );

  // ── 左右比例 (0~1)，0.5 = 各占一半 ──
  const [ratio, setRatio] = useState(0.5);

  // ── 布局方向：horizontal（左右分栏）或 vertical（上下分栏） ──
  const [layoutDir, setLayoutDir] = useState(settings.dualLayoutDir as "horizontal" | "vertical");

  // ── 复制到对方目录的顶部提示 ──
  const [showCopyToast, setShowCopyToast] = useState(false);
  const [copyToastMessage, setCopyToastMessage] = useState("");
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // 组件卸载时清除活跃的 toast 超时，避免在已卸载的组件上 setState
  useEffect(
    () => () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    },
    [],
  );

  const showCopyToastAction = (msg: string) => {
    setCopyToastMessage(msg);
    setShowCopyToast(true);
    if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    copyTimeoutRef.current = setTimeout(() => setShowCopyToast(false), 2000);
  };

  const handleToggleLayout = () => {
    setLayoutDir((prev) => (prev === "horizontal" ? "vertical" : "horizontal"));
  };

  // ── layoutDir 变化时持久化保存 ──
  useEffect(() => {
    saveSettings({ ...settings, dualLayoutDir: layoutDir });
  }, [layoutDir]);

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
          const totalW = proxy.size.width;
          const totalH = proxy.size.height;

          return (
            <ZStack>
              {/* ── 内容分栏（根据 layoutDir 选择左右或上下） ── */}
              {layoutDir === "horizontal" ? (
                <HStack spacing={0}>
                  <VStack frame={{ width: Math.max(40, totalW * ratio) }} spacing={0}>
                    <GeneralBrowser
                      isHomePage={true}
                      settings={leftSettings}
                      onSettingsChange={handleLeftSettingsChange}
                      // onFullscreen={onFullscreen}
                      refreshKey={leftKey}
                      showFolderItemCounts={settings.showFolderItemCounts ?? true}
                      highlightFile={leftHighlightFile}
                      externalCopiedPath={sharedCopiedPath}
                      onExternalCopy={handleExternalCopy}
                      onDirChange={handleLeftDirChange}
                      oppositeDirName={rightDir ? (layoutDir === "horizontal" ? "复制到右侧目录" : "复制到下方目录") : undefined}
                      onCopyToOppositeDir={rightDir ? handleCopyLeftToRight : undefined}
                      addFilesRef={leftAddFilesRef}
                      folderCountUpdateRef={leftFolderCountUpdateRef}
                      onFolderCountChanged={(folderPath, count) => {
                        rightFolderCountUpdateRef.current(folderPath, count);
                      }}
                      onFilesAdded={(files) => {
                        if (leftDir === rightDir && rightDir) {
                          rightAddFilesRef.current(files);
                        }
                      }}
                      onDropCompleted={() => setRightKey((k) => k + 1)}
                    />
                  </VStack>

                  <VStack frame={{ width: Math.max(40, totalW * (1 - ratio)) }} spacing={0}>
                    <GeneralBrowser
                      isHomePage={true}
                      settings={rightSettings}
                      onSettingsChange={handleRightSettingsChange}
                      refreshKey={rightKey}
                      showFolderItemCounts={settings.showFolderItemCounts ?? true}
                      highlightFile={rightHighlightFile}
                      externalCopiedPath={sharedCopiedPath}
                      onExternalCopy={handleExternalCopy}
                      onDirChange={handleRightDirChange}
                      oppositeDirName={leftDir ? (layoutDir === "horizontal" ? "复制到左侧目录" : "复制到上方目录") : undefined}
                      onCopyToOppositeDir={leftDir ? handleCopyRightToLeft : undefined}
                      initialLoadDelay={300}
                      addFilesRef={rightAddFilesRef}
                      folderCountUpdateRef={rightFolderCountUpdateRef}
                      onFolderCountChanged={(folderPath, count) => {
                        leftFolderCountUpdateRef.current(folderPath, count);
                      }}
                      onFilesAdded={(files) => {
                        if (leftDir === rightDir && leftDir) {
                          leftAddFilesRef.current(files);
                        }
                      }}
                      onDropCompleted={() => setLeftKey((k) => k + 1)}
                    />
                  </VStack>
                </HStack>
              ) : (
                <VStack spacing={0}>
                  <VStack frame={{ height: Math.max(40, totalH * ratio) }} spacing={0}>
                    <GeneralBrowser
                      isHomePage={true}
                      settings={leftSettings}
                      onSettingsChange={handleLeftSettingsChange}
                      refreshKey={leftKey}
                      showFolderItemCounts={settings.showFolderItemCounts ?? true}
                      highlightFile={leftHighlightFile}
                      externalCopiedPath={sharedCopiedPath}
                      onExternalCopy={handleExternalCopy}
                      onDirChange={handleLeftDirChange}
                      oppositeDirName={rightDir ? "复制到下方目录" : undefined}
                      onCopyToOppositeDir={rightDir ? handleCopyLeftToRight : undefined}
                      addFilesRef={leftAddFilesRef}
                      folderCountUpdateRef={leftFolderCountUpdateRef}
                      onFolderCountChanged={(folderPath, count) => {
                        rightFolderCountUpdateRef.current(folderPath, count);
                      }}
                      onFilesAdded={(files) => {
                        if (leftDir === rightDir && rightDir) {
                          rightAddFilesRef.current(files);
                        }
                      }}
                      onDropCompleted={() => setRightKey((k) => k + 1)}
                    />
                  </VStack>

                  <VStack frame={{ height: Math.max(40, totalH * (1 - ratio)) }} spacing={0}>
                    <GeneralBrowser
                      isHomePage={true}
                      settings={rightSettings}
                      onSettingsChange={handleRightSettingsChange}
                      refreshKey={rightKey}
                      showFolderItemCounts={settings.showFolderItemCounts ?? true}
                      highlightFile={rightHighlightFile}
                      externalCopiedPath={sharedCopiedPath}
                      onExternalCopy={handleExternalCopy}
                      onDirChange={handleRightDirChange}
                      oppositeDirName={leftDir ? "复制到上方目录" : undefined}
                      onCopyToOppositeDir={leftDir ? handleCopyRightToLeft : undefined}
                      initialLoadDelay={300}
                      addFilesRef={rightAddFilesRef}
                      folderCountUpdateRef={rightFolderCountUpdateRef}
                      onFolderCountChanged={(folderPath, count) => {
                        leftFolderCountUpdateRef.current(folderPath, count);
                      }}
                      onFilesAdded={(files) => {
                        if (leftDir === rightDir && leftDir) {
                          leftAddFilesRef.current(files);
                        }
                      }}
                      onDropCompleted={() => setLeftKey((k) => k + 1)}
                    />
                  </VStack>
                </VStack>
              )}

              <DraggableDivider layoutDir={layoutDir} totalW={totalW} totalH={totalH} ratio={ratio} onDragEnd={(newRatio) => setRatio(newRatio)} onToggleLayout={handleToggleLayout} />
            </ZStack>
          );
        }}
      </GeometryReader>
    </VStack>
  );
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
  layoutDir: "horizontal" | "vertical";
  totalW: number;
  totalH: number;
  ratio: number;
  onDragEnd: (newRatio: number) => void;
  onToggleLayout: () => void;
}) {
  // dragOffset 是本组件内部状态，变化时只重绘此组件和分隔线，不影响父级和两个 GeneralBrowser
  const [dragOffset, setDragOffset] = useState(0);
  // 拖拽标记：有实际拖动时抑制松手后的 tap 手势，避免拖到边缘时误触布局切换
  const wasDraggedRef = useRef(false);
  // 触感触发器：每次事件递增，触发 sensoryFeedback
  const [hapticTrigger, setHapticTrigger] = useState(0);
  const [hapticEndTrigger, setHapticEndTrigger] = useState(0);

  const splitCenterX = totalW * ratio - totalW / 2;
  const splitCenterY = totalH * ratio - totalH / 2;
  const previewOffset = layoutDir === "horizontal" ? { x: splitCenterX + dragOffset, y: 0 } : { x: 0, y: splitCenterY + dragOffset };

  const handleDragChanged = (details: {
    translation: {
      width: number;
      height: number;
    };
  }) => {
    const offset = layoutDir === "horizontal" ? details.translation.width : details.translation.height;
    setDragOffset(offset);
    if (Math.abs(offset) > 5) {
      if (!wasDraggedRef.current) {
        // 首次有意义的拖拽移动 → 触感反馈
        setHapticTrigger((v) => v + 1);
      }
      wasDraggedRef.current = true;
    }
  };

  const handleDragEnded = () => {
    const total = layoutDir === "horizontal" ? totalW : totalH;
    if (total > 0) {
      const newRatio = ratio + dragOffset / total;
      const clamped = Math.max(0.1, Math.min(0.9, newRatio));
      onDragEnd(clamped);
    }
    setDragOffset(0);
    // 拖拽结束触感反馈
    setHapticTrigger((v) => v + 1);
    // 拖拽结束后稍后重置标记，避免 lift-up 触发的 tap 误触发
    setTimeout(() => {
      wasDraggedRef.current = false;
    }, 100);
  };

  const handleTap = () => {
    if (wasDraggedRef.current) return;
    setHapticTrigger((v) => v + 1); // 先触发触感反馈（render cycle 1）
    // 等反馈播放后再切换布局，确保用户先感知触感再看到画面变化
    setTimeout(() => {
      onToggleLayout();
      // 布局渲染后播放较轻的触感反馈
      setTimeout(() => {
        setHapticEndTrigger((v) => v + 1);
      }, 80);
    }, 50);
  };

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
            background="regularMaterial"
            overlay={<VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }} background="rgba(128,128,128,0.25)" />}
            clipShape="capsule"
          />
        </VStack>
      </VStack>
    </VStack>
  );
}
