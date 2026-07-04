import { Bookmark } from '../manager/BookmarkManager'
import { GeneralBrowser } from './GeneralBrowser'
import { AppSettings } from '../manager/Settings'


interface HomePageProps {
  settings: AppSettings
  bookmarks: Bookmark[]
  refreshKey: number
  setRefreshKey: (fn: (k: number) => number) => void
  onFullscreen: () => void
  onSettingsChange?: (settings: AppSettings) => void
  clipboardSyncTrigger?: number
}

export function HomePage({
  settings,
  bookmarks,
  refreshKey,
  onFullscreen,
  onSettingsChange,
  clipboardSyncTrigger,
}: HomePageProps) {
  return (
    <GeneralBrowser
      isHomePage={true}
      settings={settings}
      onSettingsChange={onSettingsChange}
      onFullscreen={onFullscreen}
      bookmarks={bookmarks}
      refreshKey={refreshKey}
      showFolderItemCounts={settings.showFolderItemCounts ?? true}
      clipboardSyncTrigger={clipboardSyncTrigger}
    />
  )
}
