// 设置标签 - 显示模式、关于

import {
  Navigation,
  NavigationStack,
  List, Section, Text, Button, Toggle,
  HStack, VStack, Spacer,
  useState, Path,
} from 'scripting'
import { AppSettings } from '../manager/Settings'
import { getMaxIndexFileSizeKB, setMaxIndexFileSizeKB } from '../manager/SearchState'

interface SettingsPageProps {
  settings: AppSettings
  onUpdateSettings: (newSettings: Partial<AppSettings>) => void
  onToggleFullscreen?: () => void
}

export function SettingsPage({ settings, onUpdateSettings, onToggleFullscreen }: SettingsPageProps) {
  const dismiss = Navigation.useDismiss()
  const defaultDir = Path.join(FileManager.documentsDirectory, 'File Store')
  // 本地状态，选完立刻更新显示，无需等 modal 重新传入 props
  const [currentPath, setCurrentPath] = useState(settings.homeCurrentPath || defaultDir)
  const [maxFileSizeKB, setMaxFileSizeKB] = useState(getMaxIndexFileSizeKB())

  const handleBrowse = async () => {
    try {
      const uniqueName = `home_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
      const result = await DocumentPicker.pickDirectoryBookmark({ preferredName: uniqueName })
      if (result) {
        setCurrentPath(result.path)
        onUpdateSettings({ homeCurrentPath: result.path, homeDirectoryBookmarkName: result.bookmarkName })
      }
    } catch (e) {
      console.log('选择文件夹失败:', e)
    }
  }

  const handleInput = async () => {
    try {
      const result = await Dialog.prompt({
        title: '输入文件路径',
        message: '输入文件夹路径',
        defaultValue: currentPath,
        placeholder: '文件夹路径',
        confirmLabel: '确定',
        cancelLabel: '取消',
      })
      if (result != null && result.trim()) {
        const newPath = result.trim()
        const exists = await FileManager.exists(newPath)
        if (!exists) {
          await Dialog.alert({ title: '错误', message: '路径不存在', buttonLabel: '确定' })
          return
        }
        setCurrentPath(newPath)
        onUpdateSettings({ homeCurrentPath: newPath })
      }
    } catch (e) {
      console.log('输入路径失败:', e)
    }
  }

  const handleReset = () => {
    setCurrentPath(defaultDir)
    onUpdateSettings({ homeCurrentPath: null, homeDirectoryBookmarkName: null })
  }

  return (
    <NavigationStack>
      <List
        listStyle="plain"
        navigationTitle="设置"
        navigationBarTitleDisplayMode="inline"
      >
        <Section title="显示模式">
          <Toggle
            title="全屏显示"
            value={settings.isFullscreen}
            onChanged={(value: boolean) => {
              onUpdateSettings({ isFullscreen: value })
              dismiss()
              setTimeout(() => onToggleFullscreen?.(), 100)
            }}
          />
          <Toggle
            title="显示文件夹内项目个数"
            value={settings.showFolderItemCounts ?? true}
            onChanged={(value: boolean) => onUpdateSettings({ showFolderItemCounts: value })}
          />
          <Toggle
            title="滑动时隐藏TAB"
            value={settings.tabBarMinimizeOnScroll ?? true}
            onChanged={(value: boolean) => onUpdateSettings({ tabBarMinimizeOnScroll: value })}
          />
          <Toggle
            title="独立显示退出按钮"
            value={settings.showExitButton}
            onChanged={(value: boolean) => onUpdateSettings({ showExitButton: value })}
          />
        </Section>

        <Section title="首页收藏夹">
          <Button action={handleBrowse}>
            <HStack spacing={12} alignment="center">
              {/* <Image systemName="folder" frame={{ width: 28, height: 28 }} foregroundStyle="systemBlue" /> */}
              <VStack alignment="leading" spacing={2}>
                <Text font="body">选择文件夹</Text>
                <Text font="caption2" foregroundStyle="secondaryLabel">从文件 App 浏览选择</Text>
              </VStack>
            </HStack>
          </Button>
          <Button action={handleInput}>
            <HStack spacing={12} alignment="center">
              {/* <Image systemName="text.cursor" frame={{ width: 28, height: 28 }} foregroundStyle="systemGreen" /> */}
              <VStack alignment="leading" spacing={2}>
                <Text font="body">手动输入路径</Text>
                <Text font="caption2" foregroundStyle="secondaryLabel">直接输入文件夹路径</Text>
              </VStack>
            </HStack>
          </Button>
          <Button action={handleReset}>
            <HStack spacing={12} alignment="center">
              {/* <Image systemName="arrow.counterclockwise" frame={{ width: 28, height: 28 }} foregroundStyle="systemOrange" /> */}
              <VStack alignment="leading" spacing={2}>
                <Text font="body">恢复默认</Text>
                <Text font="caption2" foregroundStyle="secondaryLabel">重置为默认路径</Text>
              </VStack>
            </HStack>
          </Button>
          <HStack spacing={8} alignment="center">
            <Text font="caption2" foregroundStyle="secondaryLabel">当前路径:</Text>
            <Spacer />
            <Text font="caption2" foregroundStyle="tertiaryLabel">{currentPath}</Text>
          </HStack>
        </Section>

        <Section title="深度搜索">
          <Button action={async () => {
            const current = maxFileSizeKB
            const result = await Dialog.prompt({
              title: '最大文件限制',
              message: '输入文件大小限制（KB），大于此值的文件不会被索引',
              defaultValue: String(current),
              placeholder: '50',
              confirmLabel: '保存',
              cancelLabel: '取消',
            })
            if (result != null && result.trim()) {
              const val = parseInt(result.trim())
              if (!isNaN(val) && val > 0) {
                setMaxIndexFileSizeKB(val)
                setMaxFileSizeKB(val)
              }
            }
          }}>
            <HStack spacing={12} alignment="center">
              <VStack alignment="leading" spacing={2}>
                <Text font="body">索引最大文件限制</Text>
                <Text font="caption2" foregroundStyle="secondaryLabel">当前 {maxFileSizeKB} KB，点此修改</Text>
              </VStack>
            </HStack>
          </Button>
        </Section>

       {/*  <Section title="关于">
          <Text foregroundStyle="secondaryLabel">文件管理器 v{appVersion || '1.0.0'}</Text>
        </Section> */}
      </List>
    </NavigationStack>
  )
}
