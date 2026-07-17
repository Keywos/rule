// 通用媒体预览组件 - ImageViewer 和 VideoViewer

import {
  Navigation, NavigationStack, VStack, Text,
  Spacer, Image, VideoPlayer, useState, useRef, Button,
  MagnifyGesture, DragGesture, TapGesture,
  useObservable, useEffect, useColorScheme,
  LivePhotoView, Size, Path, EmptyView, NavigationDestination, ToolbarItem,
  Markdown, ScrollView, 
} from 'scripting'

import { unpackLivePhoto } from '../manager/LivePhotoPacker'
import { FilePreviewView } from './FilePreview'
import { EditorPage } from './EditorPage'
import { FileInfo, getFileCategory, ensureLocalFile, readTextFile, safeUnzip } from '../manager/utils'
import { FileInfoPage } from './FileListItem'
import { GeneralBrowser } from './GeneralBrowser'

/* ───── 共享手势 hook ───── */

function useZoomGestures(initialScale: number = 1) {
  const [scale, setScale] = useState(initialScale)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const baseScaleRef = useRef(initialScale)
  const baseOffsetRef = useRef({ x: 0, y: 0 })
  const scaleRef = useRef(initialScale)
  const offsetRef = useRef({ x: 0, y: 0 })

  // 手势对象只创建一次
  const gestureRef = useRef<any>(null)
  if (!gestureRef.current) {
    const updateScale = (s: number) => { scaleRef.current = s; setScale(s) }
    const updateOffset = (o: { x: number; y: number }) => { offsetRef.current = o; setOffset(o) }
    const resetView = () => {
      baseScaleRef.current = initialScale
      baseOffsetRef.current = { x: 0, y: 0 }
      updateScale(initialScale)
      updateOffset({ x: 0, y: 0 })
    }
    gestureRef.current = {
      gesture: {
        gesture: TapGesture(2)
          .onEnded(() => {
            if (scaleRef.current > initialScale) { resetView() }
            else { baseScaleRef.current = initialScale * 2; updateScale(initialScale * 2) }
          }),
        isEnabled: true,
      },
      simultaneousGesture: {
        gesture: DragGesture({ minDistance: 10 })
          .onChanged((v: any) => {
            if (scaleRef.current > initialScale) {
              updateOffset({
                x: baseOffsetRef.current.x + v.translation.width,
                y: baseOffsetRef.current.y + v.translation.height,
              })
            }
          })
          .onEnded(() => { baseOffsetRef.current = offsetRef.current }),
        isEnabled: false, // 初始 false，渲染时同步
      },
      highPriorityGesture:
        MagnifyGesture()
          .onChanged((v: any) => {
            const oldScale = scaleRef.current
            const newScale = baseScaleRef.current * v.magnification
            const anchor = v.startAnchor
            const ratio = newScale / oldScale
            const oldOff = offsetRef.current
            updateOffset({
              x: anchor.x * (1 - ratio) + oldOff.x * ratio,
              y: anchor.y * (1 - ratio) + oldOff.y * ratio,
            })
            updateScale(newScale)
          })
          .onEnded(() => {
            const s = scaleRef.current
            baseScaleRef.current = s
          }),
    }
  }

  // 每次渲染同步 simultaneousGesture.isEnabled 与 scale
  gestureRef.current.simultaneousGesture = {
    ...gestureRef.current.simultaneousGesture,
    isEnabled: scale > initialScale,
  }

  return { scale, offset, gestureProps: gestureRef.current }
}

/* ───── ImageViewer ───── */

interface ImageViewerProps {
  filePath: string
  nested?: boolean
}

export function ImageViewer({ filePath, nested }: ImageViewerProps) {
  const { scale, offset, gestureProps } = useZoomGestures(1.0)
  const colorScheme = useColorScheme()
  const bgColor = colorScheme === 'dark' ? '#000000' : '#F2F3F7'

  // tab 隐藏/显示都加 easeIn 动画
  const [hideTab, setHideTab] = useState(false)
  useEffect(() => {
    const shouldHide = scale >= 1.01
    if (shouldHide !== hideTab) {
      withAnimation(Animation.easeIn(0.3), () => setHideTab(shouldHide))
    }
  }, [scale])

  const content = (
    <VStack alignment="center" background={bgColor}
      {...gestureProps}
      ignoresSafeArea={true}
      tabBarVisibility={hideTab ? 'hidden' : undefined}
      navigationBarVisibility={hideTab ? 'hidden' : 'visible'}
      navigationBarTitleDisplayMode="inline"
      onDisappear={() => {
        if (hideTab) {
          withAnimation(Animation.easeIn(0.3), () => setHideTab(false))
        }
      }}
    >
      <Image filePath={filePath} resizable={true} aspectRatio={{ contentMode: 'fit' }}
        frame={{ maxWidth: 'infinity', maxHeight: 'infinity' }}
        scaleEffect={scale}
        offset={offset}
      />
    </VStack>
  )

  if (nested) return content
  return (
    <NavigationStack>
      {content}
    </NavigationStack>
  )
}

/* ───── VideoViewer ───── */

interface VideoViewerProps {
  player: AVPlayer | null
  nested?: boolean
}

export function VideoViewer({ player, nested }: VideoViewerProps) {
  const isPortrait = Device.isPortrait
  const { scale, offset, gestureProps } = useZoomGestures(isPortrait ? 0.85 : 1)
  const [rotation, setRotation] = useState(0)
  const rotate = () => setRotation(r => (r + 90) % 360)

  // tab 隐藏/显示都加 easeIn 动画
  const [hideTab, setHideTab] = useState(false)
  useEffect(() => {
    const shouldHide = scale >=0.9
    if (shouldHide !== hideTab) {
      withAnimation(Animation.easeIn(0.3), () => setHideTab(shouldHide))
    }
  }, [scale])

  const content = (
    <VStack alignment="center" spacing={0} background="#000000"
      {...gestureProps}
      ignoresSafeArea={true}
      defersSystemGestures="top"
      tabBarVisibility={hideTab ? 'hidden' : undefined}
      navigationBarVisibility={hideTab ? 'hidden' : 'visible'}
      navigationBarTitleDisplayMode="inline"
      onDisappear={() => {
        if (hideTab) {
          withAnimation(Animation.easeIn(0.3), () => setHideTab(false))
        }
        player?.pause();
        player?.stop();
      }}
      toolbar={{
        topBarTrailing: hideTab ? [] : [
          <Button title="旋转" systemImage="rotate.right"
            foregroundStyle="white" action={rotate} />,
        ],
      }}
    >
      <Spacer frame={{ height: 40 }} />
      {player ? <VideoPlayer player={player} scaleEffect={scale} offset={offset} rotationEffect={rotation} /> : <EmptyView />}
      <Spacer frame={{ height: 60 }} />
    </VStack>
  )

  if (nested) return content
  return (
    <NavigationStack>
      {content}
    </NavigationStack>
  )
}

/* ───── 视频播放包装 - 从文件路径创建 AVPlayer ───── */

function VideoViewerInner({ filePath, nested }: { filePath: string; nested?: boolean }) {
  const [player] = useState<AVPlayer>(() => {
    const av = new AVPlayer()
    av.setSource(filePath)
    av.onReadyToPlay = () => { av.play() }
    return av
  })

  useEffect(() => {
    return () => {
      player.pause()
      player.stop()
      player.dispose()
    }
  }, [])

  return <VideoViewer player={player} nested={nested} />
}

/* ───── 导出组件：视频播放器页面 ───── */
export function VideoViewerPage({ filePath, nested }: { filePath: string; nested?: boolean }) {
  return <VideoViewerInner key={filePath} filePath={filePath} nested={nested} />
}

/* ───── 导出组件：文件预览页面 ───── */
export function FilePreviewPage({ file }: { file: FileInfo }) {
  const [loading, setLoading] = useState(true);
  const [content, setContent] = useState<string | null>(null);
  const cat = file.category;

  useEffect(() => {
    (async () => {
      try {
        const text = await readTextFile(file.path);
        if (text != null) setContent(text);
      } catch {}
      setLoading(false);
    })();
  }, []);

  if (cat === 'text' || cat === 'code' || cat === 'data') {
    return <EditorPage path={file.path} />;
  }
  if (loading) return <VStack><Text padding={16} foregroundStyle='secondaryLabel'>加载中...</Text></VStack>;
  return <FilePreviewView fileInfo={file} content={content} />;
}

/* ───── Markdown 预览页面 ───── */

function MarkdownPreviewPage({ filePath }: { filePath: string }) {
    const colorSchemeMd = useColorScheme()
    const bgColor = colorSchemeMd === 'dark' ? '#17181C' : '#FFFFFF'
  const [content, setContent] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const fileName = Path.basename(filePath)

  useEffect(() => {
    (async () => {
      let text: string | null = null
      try {
        await ensureLocalFile(filePath);
        text = await FileManager.readAsString(filePath);
      } catch (e) {
        console.log('读取 Markdown 失败(utf8):', e)
        for (const enc of ["utf-8", "utf-16", "ascii"] as const) {
          try {
            text = await FileManager.readAsString(filePath, enc);
            if (text != null) break;
          } catch {}
        }
      }
      if (text != null) setContent(text)
      setLoading(false)
    })()
  }, [])

  if (loading) {
    return (
      <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
        <Text padding={16} foregroundStyle='secondaryLabel'>加载中...</Text>
      </VStack>
    )
  }

  if (content == null) {
    return (
      <VStack
        frame={{ maxWidth: "infinity", maxHeight: "infinity" }}
        navigationTitle={fileName}
      >
        <Text padding={16} foregroundStyle='secondaryLabel'>无法读取文件内容，请尝试用"编辑"打开</Text>
      </VStack>
    )
  }

  return (
    <VStack 
      frame={{ maxWidth: "infinity", maxHeight: "infinity" }} ignoresSafeArea={{ edges: ["bottom"], regions: "container" }} 
     tabBarVisibility="hidden"
     background={bgColor}
      >      
    <ScrollView
      navigationTitle={fileName}
    > 
      <Markdown
        safeAreaPadding={{ top: 20, horizontal: 8 }}
        content={content}
        theme="github"
        useDefaultHighlighterTheme={true}
        scrollable={false}
      />
    </ScrollView>
    </VStack>
  )
}

/* ───── Archive 临时目录浏览器 ───── */
function ArchiveBrowserDirectory({ dirPath, rootPath, rootName, navPath, onSaveAndExit, onDiscardAndExit }: { dirPath: string; rootPath: string; rootName: string; navPath: any; onSaveAndExit: () => void; onDiscardAndExit: () => void }) {
  return (
    <GeneralBrowser
      dirPath={dirPath}
      dirName={dirPath === rootPath ? rootName : Path.basename(dirPath)}
      rootPath={rootPath}
      rootName={rootName}
      navPath={navPath}
      // ❌ 关闭按钮仅在压缩包根目录显示；进入子目录后由系统返回箭头负责返回，不显示该按钮。
      toolbarLeadingItems={dirPath === rootPath ? <ToolbarItem placement="topBarLeading"><Button title="关闭" systemImage="xmark" action={onDiscardAndExit} /></ToolbarItem> : undefined}
       toolbarTrailingItems={<ToolbarItem placement="topBarTrailing"><Button title="保存并退出" systemImage="checkmark" action={onSaveAndExit} /></ToolbarItem>}
      navigationDestination={
        <NavigationDestination>
          {(page) => {
            if (page.startsWith("browser:")) {
              return <ArchiveBrowserDirectory dirPath={page.slice(8)} rootPath={rootPath} rootName={rootName} navPath={navPath} onSaveAndExit={onSaveAndExit} onDiscardAndExit={onDiscardAndExit} />
            }
            return <FileNavigationDest page={page} navigationPath={navPath} />
          }}
        </NavigationDestination>
      }
    />
  )
}

export function ArchiveBrowserPage({ filePath, navigationPath }: { filePath: string; navigationPath?: any }) {
  const [extractDir, setExtractDir] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isSaving, setIsSaving] = useState(false)
  const dismiss = Navigation.useDismiss()
  const localNavPath = useObservable<string[]>([])
  const navPath = navigationPath || localNavPath

  useEffect(() => {
    let disposed = false
    const tempDir = Path.join(FileManager.temporaryDirectory, `archive-view-${Date.now()}-${Math.random().toString(36).slice(2)}`)

    ;(async () => {
      try {
        await ensureLocalFile(filePath)
        await FileManager.createDirectory(tempDir, true)
        await safeUnzip(filePath, tempDir)
        if (!disposed) setExtractDir(tempDir)
      } catch (e) {
        console.log("准备压缩文件目录失败:", e)
        if (!disposed) setError("无法读取压缩文件内容")
      }
    })()

    return () => {
      disposed = true
      try { FileManager.remove(tempDir) } catch {}
    }
  }, [filePath])

  const handleSaveAndExit = async () => {
    if (!extractDir || isSaving) return
    setIsSaving(true)
    try {
      const ts = Date.now()
      const savePath = `${filePath}.saving-${ts}.zip`
      // 1. 先把新压缩包写出到临时路径；失败时原文件保持不变。
      await FileManager.zip(extractDir, savePath, false)

      // 2. 把原文件改名为备份（而不是直接删除），为新包腾出原名位置。
      //    若后续 rename 失败，可把备份改回原名，避免原文件丢失。
      const bakPath = `${filePath}.bak-${ts}`
      let movedAside = false
      try {
        if (await FileManager.exists(filePath)) {
          await FileManager.rename(filePath, bakPath)
          movedAside = true
        }
      } catch (e) {
        // 原文件无法移到一旁：清理刚生成的新包后报错，原文件未受影响。
        try { await FileManager.remove(savePath) } catch {}
        throw e
      }

      try {
        // 3. 新包就位（原名槽位已空）。
        await FileManager.rename(savePath, filePath)
      } catch (e) {
        // 新包就位失败：尝试把备份恢复回原名，保证原文件不丢失。
        if (movedAside) {
          try { await FileManager.rename(bakPath, filePath) } catch {}
        }
        throw e
      }

      // 4. 成功：删除备份并退出。
      if (movedAside) {
        try { await FileManager.remove(bakPath) } catch {}
      }
      dismiss()
    } catch (e) {
      console.log("保存压缩文件失败:", e)
      setError("保存压缩文件失败")
      setIsSaving(false)
    }
  }

  const handleDiscardAndExit = async () => {
    const confirmed = await Dialog.confirm({
      title: "不保存并返回",
      message: "关闭后不会保存对压缩包所做的修改。",
      cancelLabel: "取消",
      confirmLabel: "不保存并返回",
    })
    if (confirmed) dismiss()
  }

  const content = error ? (
    <VStack alignment="center" spacing={12} padding={32}>
      <Image systemName="exclamationmark.triangle" foregroundStyle="systemOrange" frame={{ width: 48, height: 48 }} />
      <Text>{error}</Text>
    </VStack>
  ) : !extractDir ? (
    <VStack alignment="center" padding={32}>
      <Text foregroundStyle="secondaryLabel">正在读取压缩文件…</Text>
    </VStack>
  ) : (
    <ArchiveBrowserDirectory dirPath={extractDir} rootPath={extractDir} rootName={Path.basename(filePath)} navPath={navPath} onSaveAndExit={handleSaveAndExit} onDiscardAndExit={handleDiscardAndExit} />
  )

  // 独立模态页从首次渲染起就保持 NavigationStack，避免加载完成时切换根视图。
  return navigationPath ? content : <NavigationStack path={localNavPath}>{content}</NavigationStack>
}

/* ───── 共享文件导航分发（image/video/preview/livephoto/editor/info/markdown）───── */
export function FileNavigationDest({ page, navigationPath }: { page: string; navigationPath?: any }) {
  if (page.startsWith('image:')) {
    return <ImageViewer filePath={page.slice(6)} nested />
  }
  if (page.startsWith('video:')) {
    return <VideoViewerPage filePath={page.slice(6)} nested />
  }
  if (page.startsWith('archive:')) {
    return <ArchiveBrowserPage filePath={page.slice(8)} navigationPath={navigationPath} />
  }
  if (page.startsWith('preview:')) {
    const fp = page.slice(8)
    return <FilePreviewPage file={{ path: fp, name: Path.basename(fp), size: 0, modificationDate: 0, creationDate: 0, isDirectory: false, isLink: false, extension: Path.extname(fp), category: getFileCategory(Path.extname(fp)), mimeType: '', icon: '', iconColor: 'systemGray' } as FileInfo} />
  }
  if (page.startsWith('livephoto:')) {
    return <LivePhotoPreviewPage livePath={page.slice(10)} nested />
  }
  if (page.startsWith('editor:')) {
    let filePath = page.slice(7)
    let scrollToLine: number | undefined
    const lineIdx = filePath.indexOf('::L')
    if (lineIdx !== -1) {
      scrollToLine = parseInt(filePath.slice(lineIdx + 3), 10)
      filePath = filePath.slice(0, lineIdx)
    }
    return <EditorPage path={filePath} scrollToLine={scrollToLine} />
  }
  if (page.startsWith('markdown:')) {
    return <MarkdownPreviewPage filePath={page.slice(9)} />
  }
  if (page.startsWith('info:')) {
    return <FileInfoPage filePath={page.slice(5)} />
  }
  return <VStack></VStack>
}

/* ───── 实况照片预览页面 ───── */
export function LivePhotoPreviewPage({ livePath, nested }: { livePath: string; nested?: boolean }) {
  // const dismiss = Navigation.useDismiss()
  const livePhoto = useObservable<LivePhoto | null>(null);
  const [lpSize, setLpSize] = useState<Size | null>(null);
  const tmpPathsRef = useRef<string[]>([]);
  const cancelRef = useRef<(() => void) | null>(null);

  // 手势状态
  const [scale, setScale] = useState(1.0);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const baseScaleRef = useRef(1.0);
  const baseOffsetRef = useRef({ x: 0, y: 0 });
  const scaleRef = useRef(1.0);
  const offsetRef = useRef({ x: 0, y: 0 });


  // 每次视图出现时递增，用于 key 强制重建 LivePhotoView（清除原生缩放手势状态）
  const appearKeyRef = useRef(0);
  const [viewKey, setViewKey] = useState(0);

  const updateScale = (s: number) => { scaleRef.current = s; setScale(s); };
  const updateOffset = (o: { x: number; y: number }) => { offsetRef.current = o; setOffset(o); };
  const resetView = () => {
    baseScaleRef.current = 1.0;
    baseOffsetRef.current = { x: 0, y: 0 };
    updateScale(1.0);
    updateOffset({ x: 0, y: 0 });
  };

  // 从 .live 文件加载一个全新的 LivePhoto 对象
  const reloadLivePhoto = async () => {
    // 取消进行中的加载
    if (cancelRef.current) {
      cancelRef.current();
      cancelRef.current = null;
    }
    try {
      const data = await FileManager.readAsData(livePath);
      if (data) {
        const unpacked = unpackLivePhoto(data);
        if (unpacked) {
          const baseName = Path.basename(livePath, '.live');
          // 使用时间戳避免临时文件名称冲突
          const stamp = String(Date.now());
          const imgTmp = Path.join(FileManager.temporaryDirectory, `${baseName}_${stamp}.${unpacked.imageExt}`);
          await FileManager.writeAsData(imgTmp, unpacked.imageData);
          tmpPathsRef.current.push(imgTmp);
          const vidTmp = Path.join(FileManager.temporaryDirectory, `${baseName}_${stamp}.mov`);
          await FileManager.writeAsData(vidTmp, unpacked.videoData);
          tmpPathsRef.current.push(vidTmp);
          const cancel = await LivePhoto.from({
            imagePath: imgTmp,
            videoPath: vidTmp,
            targetSize: null,
            placeholderImage: null,
            contentMode: 'aspectFit',
            onResult: (result, info) => {
              if (result && !info.degraded) {
                livePhoto.setValue(result);
                setLpSize(result.size);
              }
            }
          });
          cancelRef.current = cancel;
        }
      }
    } catch (e) {
      console.log('加载实况照片失败:', e);
    }
  };

  // 视图出现时：重置手势 + 清空 LivePhoto + 重建视图 + 重新加载全新 LivePhoto
  const handleAppear = () => {
    resetView();
    livePhoto.setValue(null);
    appearKeyRef.current++;
    setViewKey(appearKeyRef.current);
    reloadLivePhoto();
  };

  // 首次 mount 时加载
  useEffect(() => {
    reloadLivePhoto();
    return () => {
      if (cancelRef.current) {
        cancelRef.current();
        cancelRef.current = null;
      }
      for (const p of tmpPathsRef.current) {
        try { FileManager.remove(p); } catch {}
      }
    };
  }, []);

  // 手势属性
  const gestureProps = {
    gesture: {
      gesture: TapGesture(2)
        .onEnded(() => {
          if (scaleRef.current > 1.0) { resetView(); }
          else { baseScaleRef.current = 2.0; updateScale(2.0); }
        }),
      isEnabled: true,
    },
    simultaneousGesture: {
      gesture: DragGesture({ minDistance: 10 })
        .onChanged((v: any) => {
          if (scaleRef.current > 1.0) {
            updateOffset({
              x: baseOffsetRef.current.x + v.translation.width,
              y: baseOffsetRef.current.y + v.translation.height,
            });
          }
        })
        .onEnded(() => { baseOffsetRef.current = offsetRef.current; }),
      isEnabled: scale > 1.0,
    },
    highPriorityGesture:
      MagnifyGesture()
        .onChanged((v: any) => {
          const oldScale = scaleRef.current;
          const newScale = baseScaleRef.current * v.magnification;
          const anchor = v.startAnchor;
          const ratio = newScale / oldScale;
          const oldOff = offsetRef.current;
          updateOffset({
            x: anchor.x * (1 - ratio) + oldOff.x * ratio,
            y: anchor.y * (1 - ratio) + oldOff.y * ratio,
          });
          updateScale(newScale);
        })
        .onEnded(() => {
          const s = scaleRef.current;
          baseScaleRef.current = s;
        }),
  };

  if (nested) {
    return (
      <VStack alignment="center" spacing={0}
        onAppear={handleAppear}
        ignoresSafeArea={true}
        tabBarVisibility={scale >= 1.01 ? 'hidden' : undefined}
        navigationBarVisibility={scale >= 1.01 ? 'hidden' : 'visible'}
        animation={{
          animation: Animation.smooth({ duration: 0.3 }),
          value: scale >= 1.01,
        }}
        background="clear"
        {...gestureProps}
      >
        <VStack key={viewKey} frame={{maxWidth: 'infinity'}} aspectRatio={{value: lpSize ? lpSize.width / lpSize.height : undefined, contentMode: 'fit'}}>
          <LivePhotoView
            livePhoto={livePhoto}
            scaleEffect={scale}
            offset={offset}
          />
        </VStack>
      </VStack>
    );
  }

  return (
    <NavigationStack statusBarHidden={true}>
      <VStack alignment="center" spacing={0}
        onAppear={handleAppear}
        ignoresSafeArea={true}
        tabBarVisibility={scale >= 1.01 ? 'hidden' : undefined}
        navigationBarVisibility={scale >= 1.01 ? 'hidden' : 'visible'}
        animation={{
          animation: Animation.smooth({ duration: 0.3 }),
          value: scale >= 1.01,
        }}
        background="clear"
        {...gestureProps}
      >
        <VStack key={viewKey} frame={{maxWidth: 'infinity'}} aspectRatio={{value: lpSize ? lpSize.width / lpSize.height : undefined, contentMode: 'fit'}}>
          <LivePhotoView
            livePhoto={livePhoto}
            scaleEffect={scale}
            offset={offset}
          />
        </VStack>
      </VStack>
    </NavigationStack>
  );
}
