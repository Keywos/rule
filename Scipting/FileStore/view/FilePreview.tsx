// 文件预览视图 - 文本/代码使用 Editor 组件 + searchable 原生搜索

import {
  Navigation, NavigationStack, VStack, HStack, Text, Button,
  Image, useState, useEffect, useMemo, useRef, Path, 
  Spacer,
} from 'scripting'
import { getFileCategory, langMap, FileInfo } from '../manager/utils'
import { getEditorExt } from '../manager/editorConfig'

/* ───── 代码编辑器预览组件 ───── */
function CodeEditorPreview({ fileInfo, content }: { fileInfo: FileInfo; content: string }) {
  const ext = fileInfo.extension.toLowerCase()
  const editorExt = getEditorExt(ext)
  const dismiss = Navigation.useDismiss()

  const controller = useMemo(() => {
    return new EditorController({
      content,
      ext: editorExt,
      readOnly: false,
    })
  }, [content, editorExt])

  // 内容变化时自动保存（带防抖）
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleSave = async (currentContent: string) => {
    try {
      await FileManager.writeAsString(fileInfo.path, currentContent)
    } catch (e) {
      console.log('保存失败:', e)
    }
  }

  // 启动时直接用 controller.present() 打开原生编辑器
  useEffect(() => {
    let disposed = false

    // 监听内容变化，自动保存
    controller.onContentChanged = (newContent: string) => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      saveTimerRef.current = setTimeout(() => {
        handleSave(newContent)
      }, 1000) // 1秒防抖
    }

    // 直接打开编辑器
    controller.present({
      navigationTitle: fileInfo.name,
    }).then(() => {
      // 编辑器关闭时，保存最终内容
      if (disposed) return
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      handleSave(controller.content)
      controller.dispose()
      dismiss()
    }).catch((e) => {
      console.log('编辑器展示失败:', e)
      if (!disposed) {
        controller.dispose()
        dismiss()
      }
    })

    return () => {
      disposed = true
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
      controller.onContentChanged = undefined
    }
  }, [])

  // 返回空容器，编辑器由 controller.present() 直接展示
  return <VStack></VStack>
}

/* ───── 通用文件预览视图 ───── */
interface FilePreviewViewProps {
  fileInfo: FileInfo
  content: string | null
  isFullscreen?: boolean
}

export function FilePreviewView({ fileInfo, content, isFullscreen = false }: FilePreviewViewProps) {
  const ext = fileInfo.extension.toLowerCase()
  const category = getFileCategory(ext)

  // ─── 顶层 hooks（不得放在条件分支内） ───
  const [player, setPlayer] = useState<AVPlayer | null>(null)
  const [isPlaying, setIsPlaying] = useState(false)
  const dismiss = Navigation.useDismiss()

  useEffect(() => {
    if (category !== 'audio') return
    return () => {
      // cleanup 在 player state 更新时存在作用域延迟, 用 ref 会更安全
      if (player) {
        player.stop()
        player.dispose()
      }
    }
  }, [player, category])

  const handlePlay = () => {
    if (category !== 'audio') return
    if (!player) {
      const av = new AVPlayer()
      av.setSource(fileInfo.path)
      av.onReadyToPlay = () => { av.play(); setIsPlaying(true) }
      av.onEnded = () => setIsPlaying(false)
      av.onError = () => setIsPlaying(false)
      setPlayer(av)
    } else {
      if (isPlaying) { player.pause(); setIsPlaying(false) }
      else { player.play(); setIsPlaying(true) }
    }
  }

  const toggleFullscreen = async () => {
    if (category !== 'audio') return
    if (isFullscreen) {
      dismiss()
    } else {
      dismiss()
      setTimeout(async () => {
        await Navigation.present({
          element: (
            <NavigationStack>
              <VStack alignment="center" spacing={0} background="#000000"
                navigationBarTitleDisplayMode="inline"
                toolbarBackground={{ style: 'black' as any, bars: ['navigationBar'] as any }}
                toolbarColorScheme={{ colorScheme: 'dark' as any, bars: ['navigationBar'] as any }}
                toolbar={{
                  topBarLeading: [
                    <Button title="关闭" systemImage="xmark" foregroundStyle="white" action={() => dismiss()} />,
                  ],
                }}
                ignoresSafeArea={true}
              >
                <VStack alignment="center" spacing={16} padding={32}>
                  <Image systemName="waveform.circle.fill" frame={{ width: 100, height: 100 }} foregroundStyle="accentColor" />
                  <Text font="headline">{fileInfo.name}</Text>
                  <HStack spacing={16}>
                    <Button title={isPlaying ? '暂停' : '播放'} systemImage={isPlaying ? 'pause.circle.fill' : 'play.circle.fill'} action={handlePlay} />
                  </HStack>
                </VStack>
                <Spacer frame={{ height: 100 }} />
              </VStack>
            </NavigationStack>
          ),
          modalPresentationStyle: 'fullScreen',
        })
      }, 300)
    }
  }

  // ─── 文本/代码/数据 → 代码编辑器 ───
  if (content !== null && (category === 'text' || category === 'code' || category === 'data')) {
    return <CodeEditorPreview fileInfo={fileInfo} content={content} />
  }

  // ─── PDF ───
  if (category === 'pdf') {
    return (
      <VStack alignment="center" spacing={16} padding={32}>
        <Image systemName="doc.richtext" foregroundStyle="systemRed" frame={{ width: 60, height: 60 }} />
        <Text font="headline">{fileInfo.name}</Text>
        <Text font="body" foregroundStyle="secondaryLabel">PDF 文档</Text>
      </VStack>
    )
  }

  // ─── 音频 ───
  if (category === 'audio') {
    return (
      <NavigationStack>
        <VStack alignment="center" spacing={0} background="#000000"
          navigationBarTitleDisplayMode="inline"
          toolbarBackground={{ style: 'black' as any, bars: ['navigationBar'] as any }}
          toolbarColorScheme={{ colorScheme: 'dark' as any, bars: ['navigationBar'] as any }}
          toolbar={{
            topBarLeading: [
               <Button title={isFullscreen ? "关闭" : "全屏"} systemImage={isFullscreen ? "xmark" : "arrow.up.left.and.arrow.down.right"} foregroundStyle="white" action={toggleFullscreen} />,
            ],
          }}
          ignoresSafeArea={true}
        >
          <VStack alignment="center" spacing={16} padding={32}>
            <Image systemName="waveform.circle.fill" frame={{ width: 100, height: 100 }} foregroundStyle="accentColor" />
            <Text font="headline">{fileInfo.name}</Text>
            <HStack spacing={16}>
              <Button title={isPlaying ? '暂停' : '播放'} systemImage={isPlaying ? 'pause.circle.fill' : 'play.circle.fill'} action={handlePlay} />
              {player ? <Button title="停止" systemImage="stop.circle.fill" action={() => { player.stop(); setIsPlaying(false) }} /> : <></>}
            </HStack>
          </VStack>
          <Spacer frame={{ height: 100 }} />
        </VStack>
      </NavigationStack>
    )
  }

  // ─── 压缩文件 ───
  if (category === 'archive') {
    const handleUnzip = async () => {
      try {
        const destDir = Path.join(Path.dirname(fileInfo.path), Path.basename(fileInfo.name, ext))
        await FileManager.unzip(fileInfo.path, destDir)
      } catch (e) { console.log('解压失败:', e) }
    }

    return (
      <VStack alignment="center" spacing={16} padding={32}>
        <Image systemName="archivebox.fill" foregroundStyle="secondaryLabel" frame={{ width: 60, height: 60 }} />
        <Text font="headline">{fileInfo.name}</Text>
        <Text font="body" foregroundStyle="secondaryLabel">压缩文件</Text>
        <Button title="解压" systemImage="archivebox" action={handleUnzip} />
      </VStack>
    )
  }

  // ─── 通用 ───
  return (
    <VStack alignment="center" spacing={16} padding={32}>
      <Image systemName={fileInfo.icon} frame={{ width: 80, height: 80 }} foregroundStyle="secondaryLabel" />
      <Text font="headline">{fileInfo.name}</Text>
      <Text font="body" foregroundStyle="secondaryLabel">
        {langMap[ext] || ext.toUpperCase().replace('.', '') + ' 文件'}
      </Text>
    </VStack>
  )
}
