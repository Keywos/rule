import { Button, Group, NavigationStack, Path, Script, ToolbarItem, ZStack, useObservable, useState } from "scripting";
import { Bookmark, getAllBookmarks } from "./manager/BookmarkManager";
import { DROP_ACCEPTED_TYPES, handleDropToDirectory } from "./manager/dropHandler";
import { readSettings } from "./manager/Settings";
import { invalidateDirectoryCache } from "./manager/utils";
import { HomePage } from "./view/HomePage";

export default function HomeScreenDefaultUi() {
  const [settings, setSettings] = useState(() => readSettings());
  const [bookmarks] = useState<Bookmark[]>(() => getAllBookmarks());
  const [refreshKey, setRefreshKey] = useState(0);
  const [clipboardSyncTrigger] = useState(0);
  const homeNavPath = useObservable<string[]>([]);

  const homeDirectory = () => {
    if (settings.homeDirectoryBookmarkName) {
      try {
        const bookmarkedPath = FileManager.bookmarkedPath(settings.homeDirectoryBookmarkName);
        if (bookmarkedPath) return bookmarkedPath;
      } catch (error) {
        console.log("解析首页书签失败:", error);
      }
    }
    return settings.homeCurrentPath || Path.join(FileManager.documentsDirectory, "File Store");
  };

  const homeScreenDrop = {
    types: DROP_ACCEPTED_TYPES,
    validateDrop: (info: DropInfo) => info.hasItemsConforming(DROP_ACCEPTED_TYPES),
    performDrop: (info: DropInfo) => {
      const pages = Array.isArray(homeNavPath.value) ? homeNavPath.value : [];
      const currentPage = [...pages].reverse().find((page) => page.startsWith("browser:"));
      const targetDirectory = currentPage ? currentPage.slice(8).split("::", 1)[0] : homeDirectory();
      void handleDropToDirectory(info, targetDirectory, () => {
        invalidateDirectoryCache(targetDirectory);
        setRefreshKey((key) => key + 1);
      }).catch((error) => console.log("主屏幕拖拽导入失败:", error));
      return true;
    },
  };

  return (
    <NavigationStack path={homeNavPath} onDrop={homeScreenDrop}>
      <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
        <Group labelStyle="titleAndIcon">
        <HomePage
          settings={settings}
          bookmarks={bookmarks}
          refreshKey={refreshKey}
          setRefreshKey={setRefreshKey}
          onSettingsChange={setSettings}
          clipboardSyncTrigger={clipboardSyncTrigger}
          isHomeScreenHost
          navPath={homeNavPath}
          toolbarLeadingItems={
            <ToolbarItem placement="topBarLeading">
              <Button
                title="打开 FileStore"
                systemImage="folder.fill"
                action={() => {
                  void Script.run({ name: "FileStore" });
                }}
              />
            </ToolbarItem>
          }
        />
        </Group>
      </ZStack>
    </NavigationStack>
  );
}
