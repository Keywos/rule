// 预览容器 - TabView 主布局 + 全屏切换 + 退出

import { Script, Navigation, TabView, Tab, Group, EmptyView, ZStack, useState, useEffect, useRef } from "scripting";
import { getAllBookmarks, Bookmark } from "../manager/BookmarkManager";
import { readSettings, saveSettings } from "../manager/Settings";
// import { HomePage } from "./HomePage";
import { MountDirectoriesPage } from "./MountDirectoriesPage";
import { DualBrowserPage } from "./DualBrowserPage";
import { SettingsTabPage } from "./SettingsTabPage";
import { ToastOverlay } from "./ToastOverlay";
import { showToast } from "../manager/ToastManager";
import { getServerCount, hasActiveServers, stopHttpBackgroundIfIdle } from "../manager/LocalHttpServer";
import { ensureNpmDependencies } from "../manager/npmDeps";

/* ───── 主页视图 ───── */
export function HomeView({ initialToast, initialLeftPath }: { initialToast?: string; initialLeftPath?: string }) {
  const dismiss = Navigation.useDismiss();
  const loadedSettings = readSettings();
  // 指定初始左栏目录时（如导入非文本文件后回到 File Store），覆盖启动页设置：
  // 跳转到“双栏浏览”Tab(0)，并让左栏进入 initialLeftPath 目录。仅影响本次会话起始状态。
  const initialSettings = initialLeftPath
    ? { ...loadedSettings, defaultTab: 0, dualLeftPath: initialLeftPath, dualLeftBookmarkName: null, homeCurrentPath: initialLeftPath, homeDirectoryBookmarkName: null }
    : loadedSettings;
  const [bookmarks, setBookmarks] = useState<Bookmark[]>(() => getAllBookmarks());
  const [refreshKey, setRefreshKey] = useState(0);
  const [clipboardSyncTrigger, setClipboardSyncTrigger] = useState(0);
  // 仅允许 0、1、2 作为可恢复页面；退出 Tab 永不参与启动恢复。
  const initialTabIndex = initialSettings.defaultTab >= 0 && initialSettings.defaultTab <= 2 ? initialSettings.defaultTab : 0;
  const [tabIndex, setTabIndex] = useState(initialTabIndex);
  const [settings, setSettings] = useState(initialSettings);
  const lastContentTabRef = useRef(initialTabIndex);
  const exitingRef = useRef(false);

  // 初次进入时提示当前保活的 HTTP 服务数量；延后一个事件循环，确保 Toast 已完成订阅。
  useEffect(() => {
    const timer = setTimeout(() => {
      const serverCount = getServerCount();
      if (serverCount > 0) {
        showToast(`正在运行 ${serverCount} 个 HTTP 服务`);
      }
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  // 从 URL scheme 跳转（保存到 File Store）时弹 Toast
  useEffect(() => {
    if (!initialToast) return
    const timer = setTimeout(() => showToast(initialToast), 0);
    return () => clearTimeout(timer);
  }, [initialToast]);

  // 恢复保活实例后回到退出前的内容页。先切到另一个内容 Tab，再在下一轮切回，
  // 促使原生控件离开残留的退出 Tab，但不销毁并重建所有页面。
  useEffect(() => Script.onResume((details) => {
    if (!details.resumeFromMinimized) return;
    exitingRef.current = false;
    const serverCount = getServerCount();
    if (serverCount > 0) showToast(`正在运行 ${serverCount} 个 HTTP 服务`);
    const contentTab = lastContentTabRef.current;
    setTabIndex(contentTab === 0 ? 1 : 0);
    setTimeout(() => setTabIndex(contentTab), 0);
  }), []);

  const onRefresh = () => {
    withAnimation(Animation.smooth({ duration: 0.4 }), () => {
      setBookmarks(getAllBookmarks());
      setRefreshKey((k) => k + 1);
    });
  };

  const exitCurrentInstance = async () => {
    // 原生 Tab 的回调可能连续触发；一次退出流程只执行一次。
    if (exitingRef.current) return;
    exitingRef.current = true;
    if (hasActiveServers() && Script.supportsMinimization()) {
      const minimized = await Script.minimize();
      if (minimized) return;
    }
    // 当前实例没有 HTTP 服务（包括第二次启动的 UI 实例）时，释放它自己的
    // BackgroundKeeper 请求并彻底结束；不会影响持有服务的其他实例。
    await stopHttpBackgroundIfIdle();
    Script.exit();
  };

  const handleTabChange = (index: number) => {
    if (index === 3) {
      // 退出时直接最小化/结束，避免同步重建整棵 TabView 造成卡顿；
      // 恢复时会由 onResume 重建并清除原生退出 Tab 的残留选中状态。
      void exitCurrentInstance();
      return;
    }
    lastContentTabRef.current = index;
    setTabIndex(index);
    // 记住默认标签页
    if (index <= 2) {
      setTimeout(() => {
        saveSettings({ ...settings, defaultTab: index });
      }, 233);
    }
    // 切换到首页时刷新剪贴板路径（跨 tab 拷贝文件后粘贴）
    if (index === 0) {
      setClipboardSyncTrigger((k) => k + 1);
    }
  };
  // UI 已就绪（ToastOverlay 已挂载）后，再检查 npm 运行环境，缺失时自动安装并 Toast 提示
  
  (async () => {
  await ensureNpmDependencies();
})();
  return (
    <ZStack alignment="bottomTrailing" frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <TabView
        //tabBarMinimizeBehavior={"onScrollDown"}
        tabBarMinimizeBehavior={settings.tabBarMinimizeOnScroll ? "onScrollDown" : "never"}
        tabIndex={tabIndex}
        onTabIndexChanged={handleTabChange}
        labelStyle="iconOnly"
        tabBarVisibility="hidden"
      >
   {/*      <Tab title="主页" systemImage="book.pages.fill" value={0}>
          <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
            <Group labelStyle="titleAndIcon">
              <HomePage settings={settings} bookmarks={bookmarks} refreshKey={refreshKey} setRefreshKey={setRefreshKey} onSettingsChange={setSettings} clipboardSyncTrigger={clipboardSyncTrigger} />
            </Group>
          </ZStack>
        </Tab> */}

             <Tab title="双栏浏览" systemImage="book.pages.fill" value={0}>
          <Group labelStyle="titleAndIcon">
            <DualBrowserPage settings={settings} refreshKey={refreshKey} setRefreshKey={setRefreshKey} onSettingsChange={setSettings} bookmarks={bookmarks} />
          </Group>
        </Tab>

        
         <Tab title="挂载目录" systemImage="tray.2.fill" value={1}>
          <Group labelStyle="titleAndIcon">
            <MountDirectoriesPage bookmarks={bookmarks} showFolderItemCounts={settings.showFolderItemCounts} onRefresh={onRefresh} onSettingsChange={(newSettings) => setSettings(newSettings)} />
          </Group>
        </Tab>

        <Tab title="设置" systemImage="gearshape.fill" value={2}>
          <Group labelStyle="titleAndIcon">
            <SettingsTabPage
              settings={settings}
              onSettingsChange={(newSettings) => {
                saveSettings(newSettings);
                setSettings(newSettings);
              }}
              bookmarks={bookmarks}
              onSwitchTab={handleTabChange}
            />
          </Group>
        </Tab>

        <Tab title="退出" systemImage="pencil.slash" value={3} role={settings.showExitButton ? "search" : undefined}>
          <EmptyView />
        </Tab>
      </TabView>
      <ToastOverlay />
    </ZStack>
  );
}

