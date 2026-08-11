import { Button, Group, Script, ToolbarItem, ZStack, useState } from "scripting";
import { Bookmark, getAllBookmarks } from "./manager/BookmarkManager";
import { readSettings } from "./manager/Settings";
import { DualBrowserPage } from "./view/DualBrowserPage";
import { ToastOverlay } from "./view/ToastOverlay";

export default function HomeScreenDefaultUi() {
  const [settings, setSettings] = useState(() => readSettings());
  const [bookmarks] = useState<Bookmark[]>(() => getAllBookmarks());
  const [refreshKey, setRefreshKey] = useState(0);
  return (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <Group labelStyle="titleAndIcon">
        <DualBrowserPage
          settings={settings}
          refreshKey={refreshKey}
          setRefreshKey={setRefreshKey}
          onSettingsChange={setSettings}
          bookmarks={bookmarks}
          isHomeScreenHost
          secondaryToolbarLeadingItems={
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
      <ToastOverlay />
    </ZStack>
  );
}
