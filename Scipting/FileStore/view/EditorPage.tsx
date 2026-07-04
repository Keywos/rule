// 统一 EditorController+Editor 通用组件

// 三种模式：
//   fullscreen — 全屏 inline 编辑器（VStack + ignoresSafeArea + 20px顶栏 + 原生搜索 + 自动保存）
//   present    — 导航栈弹出编辑器（NavigationStack + 关闭按钮 + 原生搜索 + 自动保存）
//   preview    — 分享预览编辑器（NavigationStack + 文件头部 + 原生搜索 + 无自动保存）

import { useColorScheme, Navigation, NavigationStack, VStack, HStack, ZStack, Text, Button, Divider, Image, useState, useEffect, useMemo, useRef, Editor, Path, EmptyView } from "scripting";
import { getEditorExt } from "../manager/editorConfig";
import { getFileIcon, fmtSize, langMap } from "../manager/utils";

export interface EditorPageProps {
  /** 文件路径 */
  path: string;
  /** 预读内容（preview 模式必传；其他模式可选，不传则自动读文件） */
  content?: string;
  /** 文件名（preview 模式必传；其他模式可选，自动从 path 取 basename） */
  fileName?: string;
  /** 文件大小（仅 preview 模式头部显示用） */
  fileSize?: number;

  // ── 展示模式 ──
  /** fullscreen = Home/Mount 风格; present = 弹出编辑; preview = 分享预览 */
  mode?: "fullscreen" | "present" | "preview";

  /** present 模式专用：关闭后的回调（用于 openEditorDirectly resolve） */
  onClose?: () => void;

  /** 深度搜索结果跳转：打开后自动滚动到指定行（1-based） */
  scrollToLine?: number;
}

export function EditorPage(props: EditorPageProps) {
  const { path, content: initialContent, fileName: propFileName, fileSize: propFileSize, mode = "fullscreen", onClose, scrollToLine } = props;

  const fileName = propFileName || Path.basename(path);
  const ext = Path.extname(fileName);
  const editorExt = getEditorExt(ext);

  // ============ 所有 hooks 必须在此，不能有任何条件 return 分割 ============
  const colorScheme = useColorScheme()
  const bgColor = colorScheme === 'dark' ? '#0c1016' : '#FFFFFF'

  const [content, setContent] = useState(initialContent ?? null);
  const [ready, setReady] = useState(!!initialContent);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    // preview 模式使用传进来的内容，不从文件读
    if (mode === "preview") return;
    if (initialContent != null) return;

    let cancelled = false;
    const load = async () => {
      try {
        let text = "";
        // 先试不传 encoding（系统自动检测/默认 UTF-8）
        try {
          text = await FileManager.readAsString(path);
        } catch {
          // 尝试各种编码
          for (const enc of ["utf8", "utf-16", "ascii"] as const) {
            try {
              const t = await FileManager.readAsString(path, enc);
              if (t != null) {
                text = t;
                break;
              }
            } catch {}
          }
          // 如果以上都失败，尝试 'utf-8'
          if (!text) {
            try {
              text = await FileManager.readAsString(path, "utf-8");
            } catch {}
          }
        }
        if (!cancelled) {
          setContent(text);
          setReady(true);
        }
      } catch {
        if (!cancelled) {
          setReady(true);
          setLoadError(true);
        }
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [path, initialContent, mode]);

  // ─── 创建 EditorController ───
  const controller = useMemo(() => {
    if (content == null) return null;
    return new EditorController({
      content,
      ext: editorExt,
      readOnly: false,
    });
  }, [content, editorExt]);

  // ─── 自动保存（preview 模式无自动保存） ───
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const controllerRef = useRef<EditorController | null>(null);
  controllerRef.current = controller;
  const disposedRef = useRef(false);

  useEffect(() => {
    if (!controller || mode === "preview") return;

    controller.onContentChanged = (newContent: string) => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
      saveTimerRef.current = setTimeout(async () => {
        try {
          await FileManager.writeAsString(path, newContent);
        } catch (e) {
          console.log("自动保存失败:", e);
        }
      }, 1000);
    };

    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
      // 消除 onContentChanged 回调残留
      if (controller) controller.onContentChanged = undefined;
    };
  }, [controller, path, mode]);

  // ─── 释放 controller ───
  useEffect(() => {
    return () => {
      if (!disposedRef.current) {
        controller?.dispose();
      }
    };
  }, [controller]);

  // ─── 跳转到指定行（深度搜索跳转） ───
  const scrollToLineRef = useRef(scrollToLine);
  scrollToLineRef.current = scrollToLine;
  const scrollCancelledRef = useRef(false);
  useEffect(() => {
    if (!controller) return;
    const line = scrollToLineRef.current;
    if (typeof line !== "number" || line <= 0) return;

    // 多次尝试，等待 Editor 组件完全挂载
    let attempts = 0;
    const maxAttempts = 8;
    const retryMs = 400;
    scrollCancelledRef.current = false;

    function tryScroll() {
      if (scrollCancelledRef.current) return;
      attempts++;
      try {
        controller!.scrollToLine(line as number);
        console.log("scrollToLine 行" + line + " (尝试" + attempts + ")");
      } catch (e) {
        console.log("scrollToLine 尝试" + attempts + "失败:", e);
      }
      if (attempts < maxAttempts && !scrollCancelledRef.current) {
        setTimeout(tryScroll, retryMs);
      }
    }

    const timer = setTimeout(tryScroll, 600);
    return () => {
      clearTimeout(timer);
      scrollCancelledRef.current = true;
    };
  }, [controller]);

  // ─── present 模式的关闭（不能在条件分支内调用 Navigation.useDismiss） ───
  const dismiss = Navigation.useDismiss();
  const presentDismiss = mode === "present" ? dismiss : undefined;

  // ============ 以下可以是条件逻辑和渲染 ============

  const handleClose = () => {
    // 保存最终内容
    if (controllerRef.current && mode !== "preview") {
      const timer = saveTimerRef.current;
      if (timer) clearTimeout(timer);
      FileManager.writeAsString(path, controllerRef.current.content).catch(() => {});
    }
    controllerRef.current?.dispose();
    disposedRef.current = true;
    presentDismiss?.();
    onClose?.();
  };

  // ─── 加载 / 错误状态（preview 模式不展示加载状态） ───
  if (mode !== "preview") {
    if (!ready) {
      return (
        <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
          <Text padding={16} foregroundStyle="secondaryLabel">
            加载中...
          </Text>
        </VStack>
      );
    }
    if (loadError || !controller) {
      return (
        <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
          <Text padding={16} foregroundStyle="secondaryLabel">
            无法打开文件
          </Text>
        </VStack>
      );
    }
  }

  // ─── 渲染函数 ───

  // ─── 文件头部（仅 preview 模式） ───
  const renderFileHeader = () => {
    if (mode !== "preview") return <EmptyView />;
    const c = content ?? "";
    const initLines = c.split("\n");
    const initWords = c.split(/\s+/).filter((w) => w.length > 0).length;
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
    );
  };

  // ─── 各模式渲染 ───
  if (mode === "present") {
    return (
      <VStack spacing={0} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} ignoresSafeArea={{ edges: ["top", "bottom"], regions: "container" }} tabBarVisibility="hidden">
        {/* <HStack background="#0c101651"   
          padding={{ leading: 16, trailing: 12, vertical: 12 }} frame={{ maxWidth: 'infinity', height: 26 }} /> */}
        <HStack
          spacing={0}
          // padding={{ leading: 16, trailing: 12, vertical: 12 }}
          frame={{ maxWidth: "infinity", alignment: "center", height: 100 }}
          background={bgColor}  
        >
          <Text font="headline" padding={{ leading: 16, trailing: 12, vertical: 12, top: 70 }} frame={{ maxWidth: "infinity", alignment: "leading" }}>
            {fileName}
          </Text>
          <HStack padding={{ leading: 16, trailing: 15, vertical: 12, top: 60 }}>
            <Button glassEffect action={handleClose}>
              <ZStack>
                <Image frame={{ width: 38, height: 38 }} systemName="xmark" foregroundStyle="white" />
              </ZStack>
            </Button>
          </HStack>
        </HStack>
        <Divider />
        <Editor 
          background={bgColor} controller={controller!} searchEnabled showAccessoryView={false} scriptName={fileName} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} />
      </VStack>
    );
  }

  if (mode === "fullscreen") {
    return (
      <VStack spacing={0} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} ignoresSafeArea={{ edges: ["top", "bottom"], regions: "container" }} tabBarVisibility="hidden">
        <HStack spacing={0} background={bgColor}  frame={{ maxWidth: "infinity", alignment: "center", height: 100 }}>
          <HStack frame={{ height: 100 }}>
            <Text font="headline" padding={{ vertical: 14, top: 69 }} frame={{ maxWidth: "infinity", alignment: "center" }}>
              {fileName}
            </Text>
          </HStack>
        </HStack>
        <Editor 
          background={bgColor} controller={controller!} searchEnabled showAccessoryView={false} scriptName={fileName} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} />
      </VStack>
    );
  }

  // preview 模式
  return (
    <NavigationStack>
      <VStack alignment="leading" spacing={0}>
        {renderFileHeader()}
        <Divider />
        <Editor 
          background={bgColor}   controller={controller!} searchEnabled showAccessoryView={false} scriptName={fileName} frame={{ maxWidth: "infinity", maxHeight: "infinity" }} />
      </VStack>
    </NavigationStack>
  );
}
