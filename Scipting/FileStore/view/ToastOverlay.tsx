// 自定义 Toast 弹窗

import { VStack, HStack, ZStack, Text, Spacer, useRef, EmptyView, useState, useEffect } from "scripting";
import { setToastListener } from "../manager/ToastManager";

export function ToastOverlay() {
  const [message, setMessage] = useState<string | null>(null);
  const [toastOpacity, setToastOpacity] = useState(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const unsub = setToastListener((msg: string) => {
      // 清除上一次的定时器，防止冲突
      if (timerRef.current) clearTimeout(timerRef.current);
      if (hideTimerRef.current) clearTimeout(hideTimerRef.current);

      setMessage(msg);
      withAnimation(Animation.easeOut(0.35), () => {
        setToastOpacity(0.9);
      });

      // 1 秒后渐出
      timerRef.current = setTimeout(() => {
        withAnimation(Animation.easeOut(0.35), () => {
          setToastOpacity(0);
        });
        // 动画结束后移除节点
        hideTimerRef.current = setTimeout(() => {
          setMessage(null);
          setToastOpacity(0);
          hideTimerRef.current = null;
        }, 360);
      }, 1200);
    });
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
      unsub();
    };
  }, []);

  // message 为 null 时完全隐藏（不占位）
  if (message == null) return <EmptyView />;

  return (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
        <HStack
          padding={{ top: 40 }}
          shadow={{
            color: "rgba(0,0,0,0.12)",
            radius: 12,
            x: 0,
            y: 4,
          }}
        >
          <Text padding={15} glassEffect font={15} fontWeight="bold" opacity={toastOpacity}>
            {message}
          </Text>
        </HStack>
        <Spacer />
      </VStack>
    </ZStack>
  );
}
