// 挂载目录标签 - 已挂载目录列表 + 添加/删除

import {
  Navigation,
  NavigationStack,
  List,
  Section,
  Text,
  Button,
  HStack,
  Image,
  Spacer,
  VStack,
  ZStack,
  useState,
  useEffect,
  Menu,
  Divider,
  useObservable,
  NavigationDestination,
  Path,
  ForEach,
  EmptyView,
} from "scripting";
import {
  addDirectoryBookmark,
  addBookmarkManually,
  removeBookmarkById,
  resolveBookmarkPath,
  renameBookmark,
  Bookmark,
  reorderBookmarks,
  getBuiltinDirectories,
  getAllBookmarks,
} from "../manager/BookmarkManager";
import { copyAndToast, copiedMessage, renameWithPrompt, buildSystemDirDefs } from "../manager/utils";
import { FileListItem } from "./FileListItem";
import { GeneralBrowser } from "./GeneralBrowser";
import { SettingsPage } from "./SettingsPage";
import { saveSettings, readSettings, AppSettings } from "../manager/Settings";
import { FileNavigationDest } from "./MediaViewer";
import { showToast } from "../manager/ToastManager";
import { ToastOverlay } from "./ToastOverlay";

interface MountDirectoriesPageProps {
  bookmarks: Bookmark[];
  showFolderItemCounts: boolean;
  onRefresh: () => void;
  onSettingsChange?: (settings: AppSettings) => void;
}

function getAccessiblePath(bookmark: Bookmark): string | null {
  if (bookmark.bookmarkId) {
    const resolved = resolveBookmarkPath(bookmark.bookmarkId);
    if (resolved) return resolved;
    // 书签已失效（重启/重装后路径变更），回退到原始路径
  }
  return bookmark.path;
}

function sameStringSet(a: Set<string>, b: Set<string>): boolean {
  if (a.size !== b.size) return false;
  for (const value of a) {
    if (!b.has(value)) return false;
  }
  return true;
}

function sameNumberMap(a: Map<string, number>, b: Map<string, number>): boolean {
  if (a.size !== b.size) return false;
  for (const [key, value] of a) {
    if (b.get(key) !== value) return false;
  }
  return true;
}

async function handleRename(bookmark: Bookmark, onRefresh: () => void) {
  const trimmed = await renameWithPrompt(bookmark.name);
  if (trimmed) {
    renameBookmark(bookmark.name, trimmed);
    onRefresh();
  }
}

/* ───── 简介弹窗 ───── */
function BookmarkInfoDialog({ bookmark }: { bookmark: Bookmark }) {
  const dismiss = Navigation.useDismiss();

  const handleCopyPath = async () => {
    await copyAndToast(bookmark.path, "路径");
    showToast(copiedMessage(bookmark.path));
  };

  return (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <NavigationStack>
        <List
          listStyle="plain"
          navigationTitle="简介"
          navigationBarTitleDisplayMode="inline"
          toolbar={{
            topBarLeading: [<Button title="关闭" systemImage="xmark" action={dismiss} />],
          }}
        >
          <Section title="基本信息">
            <HStack spacing={12} alignment="center">
              <Image systemName="folder.fill" frame={{ width: 40, height: 40 }} foregroundStyle="systemBlue" />
              <VStack alignment="leading" spacing={4}>
                <Text font="headline">{bookmark.name}</Text>
                <Text font="caption" foregroundStyle="secondaryLabel">
                  {bookmark.path}
                </Text>
              </VStack>
            </HStack>
          </Section>
          <Section title="路径">
            <Button action={handleCopyPath}>
              <HStack spacing={8} alignment="center">
                <Text font="body" foregroundStyle="secondaryLabel">
                  {bookmark.path}
                </Text>
                <Spacer />
                <Image systemName="doc.on.doc" frame={{ width: 16, height: 16 }} foregroundStyle="systemBlue" />
              </HStack>
            </Button>
          </Section>
        </List>
      </NavigationStack>
      <ToastOverlay />
    </ZStack>
  );
}

export function MountDirectoriesPage({ bookmarks, showFolderItemCounts, onRefresh, onSettingsChange }: MountDirectoriesPageProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<Bookmark[]>([]);
  const [orderedBookmarks, setOrderedBookmarks] = useState<Bookmark[]>(() => [...bookmarks]);
  const [selectMode, setSelectMode] = useState(false);
  const [selectedNames, setSelectedNames] = useState<Set<string>>(new Set());
  // 不可访问的目录路径集合
  const [inaccessiblePaths, setInaccessiblePaths] = useState<Set<string>>(new Set());
  // 每个书签目录内的文件个数
  const [folderCounts, setFolderCounts] = useState<Map<string, number>>(new Map());

  // 同步 orderedBookmarks 当 bookmarks prop 变化（增删操作）
  useEffect(() => {
    setOrderedBookmarks(bookmarks);
  }, [bookmarks]);

  // 异步检查每个书签的目录是否存在 + 统计文件个数
  useEffect(() => {
    (async () => {
      const results = await Promise.all(
        bookmarks.map(async (bm) => {
          try {
            const exists = await FileManager.exists(bm.path);
            if (!exists) {
              return { path: bm.path, inaccessible: true, count: 0 };
            } else if (showFolderItemCounts !== false) {
              const items = await FileManager.readDirectory(bm.path);
              return { path: bm.path, inaccessible: false, count: items.length };
            }
            return { path: bm.path, inaccessible: false, count: 0 };
          } catch {
            return { path: bm.path, inaccessible: true, count: 0 };
          }
        }),
      );
      const badPaths = new Set<string>();
      const counts = new Map<string, number>();
      for (const r of results) {
        if (r.inaccessible) badPaths.add(r.path);
        else if (r.count > 0) counts.set(r.path, r.count);
      }
      setInaccessiblePaths((prev) => (sameStringSet(prev, badPaths) ? prev : badPaths));
      setFolderCounts((prev) => (sameNumberMap(prev, counts) ? prev : counts));
    })();
  }, [bookmarks]);

  // 导航路径（用于文件夹侧滑进入）
  const navPath = useObservable<string[]>([]);

  // 搜索栏是否活跃
  const [showSearch, setShowSearch] = useState(false);

  // 实时搜索
  useEffect(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) {
      setSearchResults([]);
      return;
    }
    const filtered = bookmarks.filter((b) => b.name.toLowerCase().includes(query));
    setSearchResults(filtered);
  }, [searchQuery, bookmarks]);

  const handleRemoveBookmark = (bookmark: Bookmark) => {
    withAnimation(Animation.smooth({ duration: 0.35 }), () => {
      removeBookmarkById(bookmark.bookmarkId, bookmark.path);
      onRefresh();
    });
  };

  const handleAdd = async () => {
    const bookmark = await addDirectoryBookmark();
    if (bookmark) {
      onRefresh();
    }
  };

  // 搜索结果
  const displayBookmarks = searchResults.length > 0 ? searchResults : searchQuery.trim() ? [] : orderedBookmarks;

  // ForEach.data 需要 Observable 数据，且每个 item 必须有 id 字段
  const forEachData = useObservable<({ id: string } & Bookmark)[]>([]);
  useEffect(() => {
    forEachData.setValue(displayBookmarks.map((b) => ({ ...b, id: b.path })));
  }, [displayBookmarks]);

  // 监听 ForEach 拖拽排序，同步回 orderedBookmarks 并持久化
  useEffect(() => {
    if (searchQuery.trim() || searchResults.length > 0) return; // 搜索中不响应重排
    const current = forEachData.value;
    if (current.length === 0) return;
    const orderChanged = current.some((item, i) => item.path !== displayBookmarks[i]?.path);
    if (orderChanged) {
      const reordered: Bookmark[] = current.map((item) => {
        const { id, ...rest } = item;
        return rest;
      });
      reorderBookmarks(reordered);
      setOrderedBookmarks(reordered);
      onRefresh();
    }
  }, [forEachData.value]);

  /** 选择模式 */
  const toggleSelect = (name: string) => {
    const next = new Set(selectedNames);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setSelectedNames(next);
  };

  const handleDeleteSelected = () => {
    withAnimation(Animation.smooth({ duration: 0.35 }), () => {
      for (const name of selectedNames) {
        const bm = bookmarks.find((b) => b.name === name);
        if (bm) {
          removeBookmarkById(bm.bookmarkId, bm.path);
        }
      }
      setSelectedNames(new Set());
      setSelectMode(false);
      onRefresh();
    });
  };

  const handleOpenSettings = () => {
    const currentSettings = readSettings();
    Navigation.present({
      element: (
        <SettingsPage
          settings={currentSettings}
          onUpdateSettings={(updates) => {
            const newSettings = { ...currentSettings, ...updates };
            saveSettings(newSettings);
            onSettingsChange?.(newSettings);
            onRefresh();
          }}
        />
      ),
      modalPresentationStyle: "pageSheet",
    });
  };

  // ── 系统目录缓存（路径可能因容器 UUID 变化而失效，需动态重建） ──
  const SYS_DIR_CACHE_KEY = "FileStore_Dirs";
  function readSysDirCache(): Record<string, { cachedPath: string; displayName?: string }> {
    try {
      const st = (globalThis as any).Storage;
      const raw = st.get?.(SYS_DIR_CACHE_KEY, { shared: true });
      if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw as Record<string, { cachedPath: string; displayName?: string }>;
      if (typeof raw === "string") return JSON.parse(raw);
      const legacy = st.getString?.(SYS_DIR_CACHE_KEY, { shared: true });
      if (legacy) return JSON.parse(legacy);
    } catch {}
    return {};
  }
  function saveSysDirCache(cache: Record<string, { cachedPath: string; displayName?: string }>) {
    try {
      const st = (globalThis as any).Storage;
      st.set?.(SYS_DIR_CACHE_KEY, cache, { shared: true });
    } catch {}
  }

  // 从缓存解析系统目录：有缓存路径就用缓存，否则动态重建
  function resolveSystemDirs() {
    const cache = readSysDirCache();
    const defs = buildSystemDirDefs();
    return defs
      .map((def) => {
        const entry = cache[def.name];
        let path = entry?.cachedPath || "";
        try {
          if (!path) path = def.getPath();
        } catch {
          path = entry?.cachedPath || "";
        }
        return { name: def.name, path, displayName: entry?.displayName, icon: def.icon, tag: def.tag };
      })
      .filter((d) => !!d.path);
  }

  const [systemDirs, setSystemDirs] = useState(() => resolveSystemDirs());
  const [systemDirCounts, setSystemDirCounts] = useState<Map<string, number>>(new Map());
  useEffect(() => {
    (async () => {
      const counts = new Map<string, number>();
      let cache = readSysDirCache();
      let cacheDirty = false;
      const defs = buildSystemDirDefs();
      // 以最新 defs 为准（iCloud/WebDAV 可用性可能变化）
      const updatedDirs = resolveSystemDirs();
      for (let i = 0; i < updatedDirs.length; i++) {
        const sysDir = updatedDirs[i];
        const def = defs.find((d) => d.name === sysDir.name);
        try {
          const exists = await FileManager.exists(sysDir.path);
          if (!exists && def) {
            // 缓存路径失效（UUID变化），重新动态构建
            let newPath = "";
            try {
              newPath = def.getPath();
            } catch {
              continue;
            }
            updatedDirs[i] = { ...sysDir, path: newPath, icon: def.icon, tag: def.tag };
            cache[def.name] = { ...cache[def.name], cachedPath: newPath };
            cacheDirty = true;
            const exists2 = await FileManager.exists(newPath);
            if (exists2 && showFolderItemCounts !== false) {
              const items = await FileManager.readDirectory(newPath);
              counts.set(sysDir.name, items.length);
            }
          } else if (exists && showFolderItemCounts !== false) {
            const items = await FileManager.readDirectory(sysDir.path);
            counts.set(sysDir.name, items.length);
          }
        } catch {
          if (def) {
            let newPath = "";
            try {
              newPath = def.getPath();
            } catch {
              continue;
            }
            if (newPath !== sysDir.path) {
              updatedDirs[i] = { ...sysDir, path: newPath, icon: def.icon, tag: def.tag };
              cache[def.name] = { ...cache[def.name], cachedPath: newPath };
              cacheDirty = true;
            }
          }
        }
      }
      if (cacheDirty || updatedDirs.length !== systemDirs.length || updatedDirs.some((d, i) => d.path !== systemDirs[i]?.path || d.name !== systemDirs[i]?.name)) {
        if (cacheDirty) saveSysDirCache(cache);
        setSystemDirs(updatedDirs);
      }
      setSystemDirCounts(counts);
    })();
  }, [showFolderItemCounts]);

  // 本机目录重命名（持久化）
  const handleSystemRename = async (sysDirName: string) => {
    const currentSysDir = systemDirs.find((d) => d.name === sysDirName);
    const currentName = currentSysDir?.displayName || sysDirName;
    const trimmed = await renameWithPrompt(currentName);
    if (trimmed) {
      const cache = readSysDirCache();
      cache[sysDirName] = { ...cache[sysDirName], displayName: trimmed, cachedPath: cache[sysDirName]?.cachedPath || currentSysDir?.path || "" };
      saveSysDirCache(cache);
      setSystemDirs((prev) => prev.map((d) => (d.name === sysDirName ? { ...d, displayName: trimmed } : d)));
    }
  };

  return (
    <NavigationStack path={navPath}>
      <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
        <List
          listStyle="plain"
          navigationTitle="挂载目录"
          navigationBarTitleDisplayMode="inline"
          searchable={{
            value: searchQuery,
            onChanged: setSearchQuery,
            placement: "navigationBarDrawer",
            prompt: "搜索目录...",
            presented: {
              value: showSearch,
              onChanged: (v: boolean) => {
                setShowSearch(v);
                if (!v) {
                  setSearchQuery("");
                  setSearchResults([]);
                }
              },
            },
          }}
          navigationDestination={
            <NavigationDestination>
              {(page) => {
                if (page.startsWith("browser:")) {
                  let dirPath = page.slice(8);
                  let highlightFile: string | undefined;
                  const sepIdx = dirPath.indexOf("::");
                  if (sepIdx !== -1) {
                    highlightFile = decodeURIComponent(dirPath.slice(sepIdx + 2));
                    dirPath = dirPath.slice(0, sepIdx);
                  }
                  return (
                    <GeneralBrowser
                      dirPath={dirPath}
                      dirName={Path.basename(dirPath)}
                      rootPath={dirPath}
                      navPath={navPath}
                      highlightFile={highlightFile}
                      showFolderItemCounts={showFolderItemCounts}
                      onOpenSettings={handleOpenSettings}
                    />
                  );
                }
                return <FileNavigationDest page={page} />;
              }}
            </NavigationDestination>
          }
          toolbar={{
            topBarTrailing: [
              <Menu title="" systemImage="ellipsis">
                <Button
                  title={selectMode ? "完成选择" : "选择"}
                  systemImage="checkmark.circle"
                  action={() => {
                    if (selectMode) {
                      setSelectMode(false);
                      setSelectedNames(new Set());
                    } else {
                      setSelectMode(true);
                    }
                  }}
                />
                {selectMode && selectedNames.size > 0 ? (
                  <>
                    <Divider />
                    <Button title="取消挂载选中" systemImage="trash" role="destructive" action={handleDeleteSelected} />
                  </>
                ) : (
                  <EmptyView />
                )}
                <Divider />
                <Button title="添加目录" systemImage="folder.badge.plus" action={handleAdd} />
                <Menu title="挂载内置目录" systemImage="internaldrive">
                  {getBuiltinDirectories().map((dir) => (
                    <Button
                      key={dir.path}
                      title={dir.name}
                      systemImage={dir.icon}
                      action={() => {
                        const already = getAllBookmarks().some((b) => b.path === dir.path);
                        if (already) {
                          showToast(`${dir.name} 已在挂载列表中`);
                          return;
                        }
                        const added = addBookmarkManually(dir.path, dir.name);
                        if (added) {
                          showToast(`已挂载 ${dir.name}`);
                          onRefresh();
                        } else {
                          showToast("挂载失败");
                        }
                      }}
                    />
                  ))}
                </Menu>
                <Divider />
                <Button title="设置" systemImage="gearshape" action={handleOpenSettings} />
              </Menu>,
            ],
          }}
        >
          {/* ── 本机 / 系统目录（不可删除） ── */}
          <Section>
            {systemDirs.map((sysDir, idx) => {
              const count = systemDirCounts.get(sysDir.name);
              const sysFile = {
                name: sysDir.name,
                path: sysDir.path,
                isDirectory: true,
                size: 0,
                modificationDate: Date.now(),
                extension: "",
                icon: (sysDir as any).icon || "folder.fill",
                iconColor: "systemGray",
                category: "folder",
              } as any;
              return (
                <FileListItem
                  key={sysDir.name}
                  file={{
                    ...sysFile,
                    name: sysDir.displayName || sysDir.name,
                  }}
                  destination={<GeneralBrowser dirPath={sysDir.path} dirName={sysDir.displayName || sysDir.name} rootPath={sysDir.path} />}
                  subtitle={showFolderItemCounts !== false && count != null ? `${count} 项` : (sysDir as any).tag || "本机"}
                  subtitleForegroundStyle="tertiaryLabel"
                  hideTopSeparator={idx === 0}
                  navPath={navPath}
                  navPageId={"browser:" + sysDir.path}
                  trailingActions={[
                    {
                      title: "简介",
                      systemImage: "info.circle",
                      action: () => {
                        const fakeBm: Bookmark = { name: sysDir.displayName || sysDir.name, path: sysDir.path, bookmarkId: "" };
                        Navigation.present({ element: <BookmarkInfoDialog bookmark={fakeBm} />, modalPresentationStyle: "pageSheet" });
                      },
                    },
                  ]}
                  leadingActions={[{ title: "重命名", systemImage: "pencil", action: () => handleSystemRename(sysDir.name) }]}
                  contextMenuItems={[
                    {
                      title: "简介",
                      systemImage: "info.circle",
                      action: () => {
                        const fakeBm: Bookmark = { name: sysDir.displayName || sysDir.name, path: sysDir.path, bookmarkId: "" };
                        Navigation.present({ element: <BookmarkInfoDialog bookmark={fakeBm} />, modalPresentationStyle: "pageSheet" });
                      },
                    },
                    { title: "重命名", systemImage: "pencil", action: () => handleSystemRename(sysDir.name) },
                  ]}
                />
              );
            })}
          </Section>

          {/* ── 已挂载目录 ── */}
          {displayBookmarks.length > 0 ? (
            <Section>
              <ForEach
                data={forEachData}
                builder={(bookmark, index) => {
                  const dirPath = getAccessiblePath(bookmark);
                  const bookmarkAsFile = {
                    name: bookmark.name,
                    path: bookmark.path,
                    isDirectory: true,
                    size: 0,
                    modificationDate: Date.now(),
                    extension: "",
                    icon: "folder.fill",
                    iconColor: "systemBlue",
                    category: "folder",
                  } as any;
                  const isAccessible = dirPath != null && !inaccessiblePaths.has(bookmark.path);
                  const isSelected = selectedNames.has(bookmark.name);
                  if (selectMode) {
                    return (
                      <FileListItem
                        key={bookmark.id}
                        file={bookmarkAsFile}
                        hideTopSeparator={index === 0}
                        selectMode={{
                          isSelected,
                          onToggle: () => toggleSelect(bookmark.name),
                        }}
                      />
                    );
                  }
                  return (
                    <FileListItem
                      key={bookmark.id}
                      file={bookmarkAsFile}
                      destination={isAccessible ? <GeneralBrowser dirPath={dirPath} dirName={bookmark.name} rootPath={dirPath} /> : undefined}
                      subtitle={
                        isAccessible
                          ? showFolderItemCounts !== false && folderCounts.has(bookmark.path)
                            ? `${folderCounts.get(bookmark.path)} 项`
                            : "文件夹"
                          : "⚠ 软件更新导致路径变化，无法访问，请重新挂载"
                      }
                      subtitleForegroundStyle={isAccessible ? undefined : "red"}
                      hideTopSeparator={index === 0}
                      navPath={isAccessible ? navPath : undefined}
                      navPageId={isAccessible ? "browser:" + bookmark.path : undefined}
                      trailingActions={[
                        { title: "取消挂载", systemImage: "trash", role: "destructive", action: () => handleRemoveBookmark(bookmark) },
                        {
                          title: "简介",
                          systemImage: "info.circle",
                          action: () => {
                            Navigation.present({ element: <BookmarkInfoDialog bookmark={bookmark} />, modalPresentationStyle: "pageSheet" });
                          },
                        },
                      ]}
                      leadingActions={[{ title: "重命名", systemImage: "pencil", action: () => handleRename(bookmark, onRefresh) }]}
                    />
                  );
                }}
                editActions="move"
              />
            </Section>
          ) : null}
        </List>
      </VStack>
    </NavigationStack>
  );
}
