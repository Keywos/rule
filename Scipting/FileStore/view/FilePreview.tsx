// 文件预览视图 - 文本/代码使用 Editor 组件 + searchable 原生搜索

import { Navigation, NavigationStack, VStack, HStack, Text, Button, Image, useState, useEffect, useMemo, useRef, Spacer, EmptyView } from "scripting";
import { getFileCategory, langMap, FileInfo } from "../manager/utils";
import { getEditorExt } from "../manager/editorConfig";

/* ───── PDF QuickLook 预览组件 ───── */
function PDFQuickLookPreview({ fileInfo }: { fileInfo: FileInfo }) {
  const [previewDone, setPreviewDone] = useState(false)

  useEffect(() => {
    let disposed = false

    QuickLook.previewURLs([fileInfo.path], true)
      .then(() => {
        if (!disposed) {
          setPreviewDone(true)
        }
      })
      .catch((e: any) => {
        console.log('PDF 预览失败:', e)
        if (!disposed) {
          setPreviewDone(true)
        }
      })

    return () => {
      disposed = true
    }
  }, [])

  if (previewDone) {
    return (
      <VStack alignment="center" spacing={16} padding={32}>
        <Image systemName="doc.richtext" foregroundStyle="systemRed" frame={{ width: 60, height: 60 }} />
        <Text font="headline">{fileInfo.name}</Text>
        <Text font="body" foregroundStyle="secondaryLabel">PDF 文档</Text>
        <Button
          title="重新预览"
          systemImage="eye"
          action={() => {
            setPreviewDone(false)
            setTimeout(() => {
              QuickLook.previewURLs([fileInfo.path], true)
                .then(() => { setPreviewDone(true) })
                .catch(() => { setPreviewDone(true) })
            }, 100)
          }}
        />
      </VStack>
    )
  }

  // QuickLook 预览由系统直接展示
  return <VStack></VStack>
}

/* ───── 代码编辑器预览组件 ───── */
function CodeEditorPreview({ fileInfo, content }: { fileInfo: FileInfo; content: string }) {
  const ext = fileInfo.extension.toLowerCase();
  const editorExt = getEditorExt(ext);
  const dismiss = Navigation.useDismiss();

  const controller = useMemo(() => {
    return new EditorController({
      content,
      ext: editorExt,
      readOnly: false,
    });
  }, [content, editorExt]);

  // 内容变化时自动保存（带防抖）
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleSave = async (currentContent: string) => {
    try {
      await FileManager.writeAsString(fileInfo.path, currentContent);
    } catch (e) {
      console.log("保存失败:", e);
    }
  };

  // 启动时直接用 controller.present() 打开原生编辑器
  useEffect(() => {
    let disposed = false;

    // 监听内容变化，自动保存
    controller.onContentChanged = (newContent: string) => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
      saveTimerRef.current = setTimeout(() => {
        handleSave(newContent);
      }, 1000); // 1秒防抖
    };

    // 直接打开编辑器
    controller
      .present({
        navigationTitle: fileInfo.name,
      })
      .then(() => {
        // 编辑器关闭时，保存最终内容
        if (disposed) return;
        if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
        handleSave(controller.content);
        controller.dispose();
        dismiss();
      })
      .catch((e) => {
        console.log("编辑器展示失败:", e);
        if (!disposed) {
          controller.dispose();
          dismiss();
        }
      });

    return () => {
      disposed = true;
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
      controller.onContentChanged = undefined;
    };
  }, []);

  // 返回空容器，编辑器由 controller.present() 直接展示
  return <VStack></VStack>;
}

/* ───── 通用文件预览视图 ───── */
interface FilePreviewViewProps {
  fileInfo: FileInfo;
  content: string | null;
  // isFullscreen?: boolean
}

export function FilePreviewView({ fileInfo, content }: FilePreviewViewProps) {
  const ext = fileInfo.extension.toLowerCase();
  const category = getFileCategory(ext);

  // ─── 顶层 hooks（不得放在条件分支内） ───
  const [player, setPlayer] = useState<AVPlayer | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  //const dismiss = Navigation.useDismiss()

  useEffect(() => {
    if (category !== "audio") return;
    return () => {
      // cleanup 在 player state 更新时存在作用域延迟, 用 ref 会更安全
      if (player) {
        player.stop();
        player.dispose();
      }
    };
  }, [player, category]);

  const handlePlay = () => {
    if (category !== "audio") return;
    if (!player) {
      const av = new AVPlayer();
      av.setSource(fileInfo.path);
      av.onReadyToPlay = () => {
        av.play();
        setIsPlaying(true);
      };
      av.onEnded = () => setIsPlaying(false);
      av.onError = () => setIsPlaying(false);
      setPlayer(av);
    } else {
      if (isPlaying) {
        player.pause();
        setIsPlaying(false);
      } else {
        player.play();
        setIsPlaying(true);
      }
    }
  };

  // ─── 文本/代码/数据 → 代码编辑器 ───
  if (content !== null && (category === "text" || category === "code" || category === "data")) {
    return <CodeEditorPreview fileInfo={fileInfo} content={content} />;
  }

  // ─── PDF → QuickLook 系统预览 ───
  if (category === "pdf") {
    return <PDFQuickLookPreview fileInfo={fileInfo} />
  }

  // ─── 音频 ───
  if (category === "audio") {
    return (
      <NavigationStack>
        <VStack
          alignment="center"
          spacing={0}
          background="#000000"
          navigationBarTitleDisplayMode="inline"
          toolbarBackground={{ style: "black" as any, bars: ["navigationBar"] as any }}
          toolbarColorScheme={{ colorScheme: "dark" as any, bars: ["navigationBar"] as any }}
          ignoresSafeArea={true}
        >
          <VStack alignment="center" spacing={16} padding={32}>
            <Image systemName="waveform.circle.fill" frame={{ width: 100, height: 100 }} foregroundStyle="accentColor" />
            <Text font="headline">{fileInfo.name}</Text>
            <HStack spacing={16}>
              <Button title={isPlaying ? "暂停" : "播放"} systemImage={isPlaying ? "pause.circle.fill" : "play.circle.fill"} action={handlePlay} />
              {player ? (
                <Button
                  title="停止"
                  systemImage="stop.circle.fill"
                  action={() => {
                    player.stop();
                    setIsPlaying(false);
                  }}
                />
              ) : (
                <EmptyView />
              )}
            </HStack>
          </VStack>
          <Spacer frame={{ height: 100 }} />
        </VStack>
      </NavigationStack>
    );
  }

  // ─── 通用 ───
  return (
    <VStack alignment="center" spacing={16} padding={32}>
      <Image systemName={fileInfo.icon} frame={{ width: 80, height: 80 }} foregroundStyle="secondaryLabel" />
      <Text font="headline">{fileInfo.name}</Text>
      <Text font="body" foregroundStyle="secondaryLabel">
        {langMap[ext] || ext.toUpperCase().replace(".", "") + " 文件"}
      </Text>
    </VStack>
  );
}
