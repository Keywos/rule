// 全屏网页预览 — 左上角浮动返回按钮，不遮挡网页内容

import { Navigation, WebView, ZStack, VStack, Button, useRef, useEffect } from "scripting";

export function WebPreviewPage({ url }: { url: string }) {
  const dismiss = Navigation.useDismiss();
  const controllerRef = useRef<WebViewController | null>(null);
  if (!controllerRef.current) {
    controllerRef.current = new WebViewController();
  }

  useEffect(() => {
    controllerRef.current!.loadURL(url).catch((error) => {
      console.log("[HTTP Preview] 加载失败:", error);
    });
    return () => {
      controllerRef.current?.dispose();
      controllerRef.current = null;
    };
  }, [url]);

  return (
    <ZStack ignoresSafeArea alignment="topLeading" frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <WebView controller={controllerRef.current} />
      <VStack padding={{ top: 48, leading: 12 }}>
        <Button
          title="返 回ㅤ         ㅤㅤ "
          systemImage="chevron.left"
          action={() => dismiss()}
        />
      </VStack>
    </ZStack>
  );
}