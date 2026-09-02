// 安装运行环境时的居中加载页面：自动执行安装，完成后自动关闭

import { Navigation, ProgressView, VStack, Text, Spacer, useEffect } from "scripting";

type InstallingViewProps = {
  /** 执行安装的函数，返回是否安装成功（组件会在其 resolve 后自动关闭） */
  install: () => Promise<boolean>;
};

export function InstallingView({ install }: InstallingViewProps) {
  const dismiss = Navigation.useDismiss();

  // 页面出现后自动开始安装，完成后关闭
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ok = await install();
      if (cancelled) return;
      dismiss(ok);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <VStack
      frame={{ maxWidth: "infinity", maxHeight: "infinity" }}
      spacing={14}
      padding={28}
    >
      <Spacer />
      <ProgressView />
      <Text font={17} fontWeight="bold">
        正在安装运行环境…
      </Text>
      <Text font={14} opacity={0.6}>
        首次需要下载依赖，安装完成后自动关闭
      </Text>
      <Spacer />
    </VStack>
  );
}
