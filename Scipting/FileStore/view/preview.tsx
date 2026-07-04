// 预览容器 - TabView 主布局 + 全屏切换 + 退出

import {
  Script, Navigation,
  TabView, Tab, Group, VStack, ZStack,
  useState, useEffect,
} from 'scripting'
import { getAllBookmarks, Bookmark } from '../manager/BookmarkManager'
import { readSettings, saveSettings } from '../manager/Settings'
import { HomePage } from './HomePage'
import { MountDirectoriesPage } from './MountDirectoriesPage'
import { DualBrowserPage } from './DualBrowserPage'
import { DROP_ACCEPTED_TYPES, handleDropToDirectory } from '../manager/dropHandler'
import { Path } from 'scripting'
import { ToastOverlay } from './ToastOverlay'

/* ───── 全屏切换标志（供 index.tsx 读取） ───── */
export let isTogglingFullscreen = false

/* ───── 主页视图 ───── */
export function HomeView() {
  const dismiss = Navigation.useDismiss()
  const initialSettings = readSettings()
  const [bookmarks, setBookmarks] = useState<Bookmark[]>(() => getAllBookmarks())
  const [refreshKey, setRefreshKey] = useState(0)
  const [clipboardSyncTrigger, setClipboardSyncTrigger] = useState(0)
  const [tabIndex, setTabIndex] = useState(initialSettings.defaultTab <= 2 ? initialSettings.defaultTab : 0)
  const [settings, setSettings] = useState(initialSettings)

  const toggleFullscreen = async () => {
    const newFullscreen = !settings.isFullscreen
    const newSettings = { ...settings, isFullscreen: newFullscreen }
    setSettings(newSettings)
    saveSettings(newSettings)
    isTogglingFullscreen = true
    dismiss()
    setTimeout(async () => {
      await Navigation.present({
        element: <HomeView />,
        modalPresentationStyle: newFullscreen ? 'fullScreen' : 'pageSheet',
      })
      if (!isTogglingFullscreen) {
        Script.exit()
      }
      isTogglingFullscreen = false
    }, 300)
  }

  const onRefresh = () => {
    withAnimation(Animation.smooth({ duration: 0.4 }), () => {
      setBookmarks(getAllBookmarks())
      setRefreshKey(k => k + 1)
    })
  }

  const handleTabChange = (index: number) => {
    setTabIndex(index)
    // 记住默认标签页
    if (index <= 2) {
      setTimeout(() => {
        saveSettings({ ...settings, defaultTab: index })
      }, 789)
    }
    // 切换到首页时刷新剪贴板路径（跨 tab 拷贝文件后粘贴）
    if (index === 0) {
      setClipboardSyncTrigger(k => k + 1)
    }
  }



  return (
    <ZStack
      frame={{ maxWidth: 'infinity', maxHeight: 'infinity' }}
    >
    <TabView
        tabBarMinimizeBehavior={settings.tabBarMinimizeOnScroll ? 'onScrollDown' : 'never'}
      tabIndex={tabIndex}
      onTabIndexChanged={handleTabChange}
      labelStyle="iconOnly"
      tabBarVisibility={settings.isFullscreen ? 'hidden' : 'automatic'}
    >
      <Tab title="主页" systemImage="book.pages.fill" value={0}>
        <ZStack
          frame={{ maxWidth: 'infinity', maxHeight: 'infinity' }}
          onDrop={{
            types: DROP_ACCEPTED_TYPES,
            validateDrop: (info) => {
              const ok = info.hasItemsConforming(DROP_ACCEPTED_TYPES);
              console.log('Tab0 ZStack validateDrop:', ok, 'location:', info.location);
              return ok;
            },
            dropEntered: () => {
              console.log('Tab0 ZStack dropEntered');
            },
            performDrop: (info) => {
              console.log('Tab0 ZStack performDrop');
              const defaultDir = Path.join(FileManager.documentsDirectory, 'File Store')
              const targetDir = settings.homeCurrentPath || defaultDir
              handleDropToDirectory(info, targetDir, () => {
                setRefreshKey(k => k + 1)
              })
              return true
            },
          }}
        >
        <Group labelStyle="titleAndIcon">
          <HomePage
            settings={settings}
            bookmarks={bookmarks}
            refreshKey={refreshKey}
            setRefreshKey={setRefreshKey}
            onFullscreen={toggleFullscreen}
            onSettingsChange={setSettings}
            clipboardSyncTrigger={clipboardSyncTrigger}
          />
        </Group>
        </ZStack>
      </Tab>

      <Tab title="挂载目录" systemImage="tray.2.fill" value={1}>
        <Group labelStyle="titleAndIcon">
          <MountDirectoriesPage
            bookmarks={bookmarks}
            showFolderItemCounts={settings.showFolderItemCounts}
            onRefresh={onRefresh}
            onFullscreen={toggleFullscreen}
            parentFullscreen={settings.isFullscreen}
            onSettingsChange={(newSettings) => setSettings(newSettings)}
          />
        </Group>
      </Tab>

      <Tab title="双栏浏览" systemImage="r.square.on.square.fill" value={2}>
        <Group labelStyle="titleAndIcon">
          <DualBrowserPage
            settings={settings}
            refreshKey={refreshKey}
            setRefreshKey={setRefreshKey}
            onFullscreen={toggleFullscreen}
            onSettingsChange={setSettings}
          />
        </Group>
      </Tab>

      <Tab title="退出" systemImage="pencil.slash" value={3} role={settings.showExitButton ? 'search' : undefined}>
        <ExitView />
      </Tab>


    </TabView>
    <ToastOverlay />
    </ZStack>
  )
}

function ExitView() {
  useEffect(() => { Script.exit() }, [])
  return <VStack></VStack>
}
