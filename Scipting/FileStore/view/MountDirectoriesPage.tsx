// 挂载目录标签 - 已挂载目录列表 + 添加/删除

import { Navigation, NavigationStack, List, Section, Text, Button, HStack, Image, Spacer, VStack, ZStack, useState, useEffect, Menu, Divider, useObservable, NavigationDestination, Path } from "scripting";
import { addDirectoryBookmark, removeBookmarkById, resolveBookmarkPath, renameBookmark, Bookmark } from "../manager/BookmarkManager";
import { copyAndToast, copiedMessage, renameWithPrompt } from "../manager/utils";
import { FileListItem } from "./FileListItem";
import { GeneralBrowser } from "./GeneralBrowser";
import { SettingsPage } from "./SettingsPage";
import { saveSettings, readSettings, AppSettings } from '../manager/Settings'
import { FileNavigationDest } from "./MediaViewer";
import { DROP_ACCEPTED_TYPES, handleDropToDirectory } from "../manager/dropHandler";
import { showToast } from "../manager/ToastManager";
import { ToastOverlay } from "./ToastOverlay";

interface MountDirectoriesPageProps {
  bookmarks: Bookmark[];
  showFolderItemCounts: boolean;
  onRefresh: () => void;
  onFullscreen: () => void;
  parentFullscreen?: boolean;
  onSettingsChange?: (settings: AppSettings) => void;
}

function getAccessiblePath(bookmark: Bookmark): string | null {
  if (bookmark.bookmarkId) {
    const resolved = resolveBookmarkPath(bookmark.bookmarkId);
    if (resolved) return resolved;
    return null;
  }
  return bookmark.path;
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
    <ZStack frame={{ maxWidth: 'infinity', maxHeight: 'infinity' }}>
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

export function MountDirectoriesPage({ bookmarks, showFolderItemCounts, onRefresh, onFullscreen, parentFullscreen, onSettingsChange }: MountDirectoriesPageProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<Bookmark[]>([])
  const [orderedBookmarks, setOrderedBookmarks] = useState<Bookmark[]>(() => [...bookmarks])
  const [selectMode, setSelectMode] = useState(false)
  const [selectedNames, setSelectedNames] = useState<Set<string>>(new Set())
  // 不可访问的目录路径集合
  const [inaccessiblePaths, setInaccessiblePaths] = useState<Set<string>>(new Set())
  // 每个书签目录内的文件个数
  const [folderCounts, setFolderCounts] = useState<Map<string, number>>(new Map())

  // 同步 orderedBookmarks 当 bookmarks prop 变化（增删操作）
  useEffect(() => {
    setOrderedBookmarks(bookmarks)
  }, [bookmarks])

  // 异步检查每个书签的目录是否存在 + 统计文件个数
  useEffect(() => {
    (async () => {
      const results = await Promise.all(
        bookmarks.map(async (bm) => {
          try {
            const exists = await FileManager.exists(bm.path)
            if (!exists) {
              return { path: bm.path, inaccessible: true, count: 0 }
            } else if (showFolderItemCounts !== false) {
              const items = await FileManager.readDirectory(bm.path)
              return { path: bm.path, inaccessible: false, count: items.length }
            }
            return { path: bm.path, inaccessible: false, count: 0 }
          } catch {
            return { path: bm.path, inaccessible: true, count: 0 }
          }
        })
      )
      const badPaths = new Set<string>()
      const counts = new Map<string, number>()
      for (const r of results) {
        if (r.inaccessible) badPaths.add(r.path)
        else if (r.count > 0) counts.set(r.path, r.count)
      }
      setInaccessiblePaths(badPaths)
      setFolderCounts(counts)
    })()
  }, [bookmarks])

  // 导航路径（用于文件夹侧滑进入）
  const navPath = useObservable<string[]>([])
  
  // 搜索栏是否活跃
  const [showSearch, setShowSearch] = useState(false)

  // 实时搜索
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([])
      return
    }
    const filtered = bookmarks.filter(b => b.name.toLowerCase().includes(searchQuery.toLowerCase()))
    setSearchResults(filtered)
  }, [searchQuery, bookmarks])

  const handleRemoveBookmark = (bookmark: Bookmark) => {
    withAnimation(Animation.smooth({ duration: 0.35 }), () => {
      removeBookmarkById(bookmark.bookmarkId);
      onRefresh();
    });
  };

  const handleAdd = async () => {
    const bookmark = await addDirectoryBookmark();
    if (bookmark) {
      onRefresh();
    }
  };

  // 搜索结果 — 使用 observable，添加目录后立即更新
  const displayBookmarks = useObservable<Array<Bookmark & {id: string}>>(bookmarks.map(b => ({ ...b, id: b.path })))

  useEffect(() => {
    const items = searchResults.length > 0 ? searchResults : (searchQuery.trim() ? [] : orderedBookmarks)
    displayBookmarks.setValue(items.map(b => ({ ...b, id: b.path })))
  }, [searchResults, searchQuery, orderedBookmarks])

  useEffect(() => {
    const items = searchResults.length > 0 ? searchResults : (searchQuery.trim() ? [] : bookmarks)
    displayBookmarks.setValue(items.map(b => ({ ...b, id: b.path })))
  }, [bookmarks])

  /** 选择模式 */
  const toggleSelect = (name: string) => {
    const next = new Set(selectedNames)
    if (next.has(name)) next.delete(name)
    else next.add(name)
    setSelectedNames(next)
  }

  const handleDeleteSelected = () => {
    withAnimation(Animation.smooth({ duration: 0.35 }), () => {
      for (const name of selectedNames) {
        const bm = bookmarks.find(b => b.name === name)
        if (bm) {
          removeBookmarkById(bm.bookmarkId)
        }
      }
      setSelectedNames(new Set())
      setSelectMode(false)
      onRefresh()
    })
  }

  const handleOpenSettings = () => {
    const currentSettings = readSettings()
    Navigation.present({
      element: <SettingsPage settings={currentSettings} onUpdateSettings={(updates) => {
        const newSettings = { ...currentSettings, ...updates }
        saveSettings(newSettings)
        onSettingsChange?.(newSettings)
        onRefresh()
      }} onToggleFullscreen={onFullscreen} />,
      modalPresentationStyle: 'pageSheet',
    })
  }

  // ── 系统目录缓存 ──
  const SYS_DIR_CACHE_KEY = 'FileStore_Dirs'
  const systemDirDefs = [
    { name: 'iPhone/Scripting', relativePath: '' } as const,
    { name: 'iPhone/Scripting/File Store', relativePath: 'File Store' } as const,
  ]
  function readSysDirCache(): Record<string, { cachedPath: string; displayName?: string }> {
    try {
      const st = (globalThis as any).Storage
      const raw = st.get?.(SYS_DIR_CACHE_KEY, { shared: true }) ?? st.getString?.(SYS_DIR_CACHE_KEY, { shared: true })
      if (raw) return JSON.parse(raw)
    } catch {}
    return {}
  }
  function saveSysDirCache(cache: Record<string, { cachedPath: string; displayName?: string }>) {
    try {
      const st = (globalThis as any).Storage
      st.set?.(SYS_DIR_CACHE_KEY, JSON.stringify(cache, null, 2), { shared: true })
    } catch {}
  }

  // 从缓存解析系统目录：有缓存路径就用缓存，否则动态重建
  function resolveSystemDirs() {
    const cache = readSysDirCache()
    return systemDirDefs.map(def => {
      const entry = cache[def.name]
      const path = entry?.cachedPath || (def.relativePath === '' ? FileManager.documentsDirectory : Path.join(FileManager.documentsDirectory, def.relativePath))
      return { name: def.name, path, displayName: entry?.displayName }
    })
  }

  const [systemDirs, setSystemDirs] = useState(() => resolveSystemDirs())
  const [systemDirCounts, setSystemDirCounts] = useState<Map<string, number>>(new Map())
  useEffect(() => {
    (async () => {
      const counts = new Map<string, number>()
      let cache = readSysDirCache()
      let cacheDirty = false
      const updatedDirs = [...systemDirs]
      for (let i = 0; i < updatedDirs.length; i++) {
        const sysDir = updatedDirs[i]
        try {
          const exists = await FileManager.exists(sysDir.path)
          if (!exists) {
            // 缓存路径失效（UUID变化），重新动态构建
            const def = systemDirDefs.find(d => d.name === sysDir.name)!
            const newPath = def.relativePath === '' ? FileManager.documentsDirectory : Path.join(FileManager.documentsDirectory, def.relativePath)
            updatedDirs[i] = { ...sysDir, path: newPath }
            cache[def.name] = { ...cache[def.name], cachedPath: newPath }
            cacheDirty = true
            const exists2 = await FileManager.exists(newPath)
            if (exists2 && showFolderItemCounts !== false) {
              const items = await FileManager.readDirectory(newPath)
              counts.set(sysDir.name, items.length)
            }
          } else if (showFolderItemCounts !== false) {
            const items = await FileManager.readDirectory(sysDir.path)
            counts.set(sysDir.name, items.length)
          }
        } catch {
          const def = systemDirDefs.find(d => d.name === sysDir.name)!
          const newPath = def.relativePath === '' ? FileManager.documentsDirectory : Path.join(FileManager.documentsDirectory, def.relativePath)
          if (newPath !== sysDir.path) {
            updatedDirs[i] = { ...sysDir, path: newPath }
            cache[def.name] = { ...cache[def.name], cachedPath: newPath }
            cacheDirty = true
          }
        }
      }
      if (cacheDirty) {
        saveSysDirCache(cache)
        setSystemDirs(updatedDirs)
      }
      setSystemDirCounts(counts)
    })()
  }, [showFolderItemCounts])

  // 本机目录重命名（持久化）
  const handleSystemRename = async (sysDirName: string) => {
    const currentSysDir = systemDirs.find(d => d.name === sysDirName)
    const currentName = currentSysDir?.displayName || sysDirName
    const trimmed = await renameWithPrompt(currentName)
    if (trimmed) {
      const cache = readSysDirCache()
      cache[sysDirName] = { ...cache[sysDirName], displayName: trimmed, cachedPath: cache[sysDirName]?.cachedPath || currentSysDir?.path || '' }
      saveSysDirCache(cache)
      setSystemDirs(prev => prev.map(d => d.name === sysDirName ? { ...d, displayName: trimmed } : d))
    }
  }

  // ── 从外部拖入文件到挂载目录 ──
  const handleDropToBookmark = async (info: DropInfo) => {
    // 获取所有可访问的书签（有有效路径且未被标记为不可访问）
    const accessibleBookmarks = bookmarks
      .map(b => ({
        bookmark: b,
        path: getAccessiblePath(b),
      }))
      .filter(item => item.path != null && !inaccessiblePaths.has(item.bookmark.path))

    if (accessibleBookmarks.length === 0) {
      console.log('无可用挂载目录，无法导入拖入文件')
      return
    }

    // 通过落点 y 坐标估算目标书签的行号
    // iOS List 行高约 56pt，Section header 约 40pt
    const rowHeight = 56
    const sectionHeaderHeight = 40
    const headerOffset = sectionHeaderHeight + (systemDirs.length * rowHeight) + sectionHeaderHeight
    const relativeY = info.location.y - headerOffset
    let targetIndex = 0
    if (relativeY >= 0) {
      targetIndex = Math.floor(relativeY / rowHeight)
    }
    targetIndex = Math.max(0, Math.min(targetIndex, accessibleBookmarks.length - 1))

    const target = accessibleBookmarks[targetIndex]
    console.log(`拖拽导入到挂载目录「${target.bookmark.name}」(${target.path})`)
    await handleDropToDirectory(info, target.path!, onRefresh)
  }

    return (
    <ZStack
      frame={{ maxWidth: 'infinity', maxHeight: 'infinity' }}
      onDrop={{
        types: DROP_ACCEPTED_TYPES,
        validateDrop: (info) => {
          const ok = info.hasItemsConforming(DROP_ACCEPTED_TYPES);
          console.log('MountDir ZStack validateDrop:', ok, 'location:', info.location);
          return ok;
        },
        dropEntered: (info) => {
          console.log('MountDir ZStack dropEntered at', info.location);
        },
        dropUpdated: (info) => {
          console.log('MountDir ZStack dropUpdated at', info.location);
          return "copy";
        },
        dropExited: (info) => {
          console.log('MountDir ZStack dropExited at', info.location);
        },
        performDrop: (info) => {
          console.log('MountDir ZStack performDrop at', info.location);
          try {
            handleDropToBookmark(info)
          } catch (e) {
            console.log('拖拽导入到挂载目录失败:', e)
          }
          return true
        },
      }}
    >
      <NavigationStack path={navPath}>
      <VStack frame={{ maxWidth: 'infinity', maxHeight: 'infinity' }}>
      <List
        listStyle="plain"
        navigationTitle="挂载目录"
        navigationBarTitleDisplayMode="inline"
        searchable={{
          value: searchQuery,
          onChanged: setSearchQuery,
          placement: 'navigationBarDrawer',
          prompt: '搜索目录...',
          presented: {
            value: showSearch,
            onChanged: (v) => {
              setShowSearch(v)
              if (!v) {
                setSearchQuery('')
                setSearchResults([])
              }
            },
          },
        }}
        navigationDestination={
          <NavigationDestination>
            {(page) => {
              if (page.startsWith('browser:')) {
                let dirPath = page.slice(8)
                let highlightFile: string | undefined
                const sepIdx = dirPath.indexOf('::')
                if (sepIdx !== -1) {
                  highlightFile = decodeURIComponent(dirPath.slice(sepIdx + 2))
                  dirPath = dirPath.slice(0, sepIdx)
                }
                return <GeneralBrowser dirPath={dirPath} dirName={Path.basename(dirPath)} rootPath={dirPath} navPath={navPath} highlightFile={highlightFile} showFolderItemCounts={showFolderItemCounts} onOpenSettings={handleOpenSettings} />
              }
              return <FileNavigationDest page={page} />
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
                    setSelectMode(false)
                    setSelectedNames(new Set())
                  } else {
                    setSelectMode(true)
                  }
                }}
              />
              {selectMode && selectedNames.size > 0 ? (
                <>
                  <Divider />
                  <Button title="取消挂载选中" systemImage="trash" role="destructive" action={handleDeleteSelected} />
                </>
              ) : null}
              <Divider />
              <Button title="添加目录" systemImage="folder.badge.plus" action={handleAdd} />
              <Divider />
              <Button title="设置" systemImage="gearshape" action={handleOpenSettings} />
            </Menu>,
          ],
        }}
      >
        {/* ── 本机目录（写死，不可删除） ── */}
        <Section>
          {systemDirs.map((sysDir, idx) => {
            const count = systemDirCounts.get(sysDir.name)
            const sysFile = {
              name: sysDir.name,
              path: sysDir.path,
              isDirectory: true,
              size: 0,
              modificationDate: Date.now(),
              extension: '',
              icon: 'folder.fill',
              iconColor: 'systemGray',
              category: 'folder',
            } as any
            return (
              <FileListItem
                key={sysDir.name}
                file={{
                  ...sysFile,
                  name: sysDir.displayName || sysDir.name,
                }}
                destination={<GeneralBrowser dirPath={sysDir.path} dirName={sysDir.displayName || sysDir.name} rootPath={sysDir.path} parentFullscreen={parentFullscreen} />}
                subtitle={showFolderItemCounts !== false && count != null ? `${count} 项` : '本机'}
                subtitleForegroundStyle="tertiaryLabel"
                hideTopSeparator={idx === 0}
                navPath={navPath}
                navPageId={'browser:' + sysDir.path}
                trailingActions={[
                  { title: '简介', systemImage: 'info.circle', action: () => {
                    const fakeBm: Bookmark = { name: sysDir.displayName || sysDir.name, path: sysDir.path, bookmarkId: '' }
                    Navigation.present({ element: <BookmarkInfoDialog bookmark={fakeBm} />, modalPresentationStyle: 'pageSheet' })
                  }},
                ]}
                leadingActions={[
                  { title: '重命名', systemImage: 'pencil', action: () => handleSystemRename(sysDir.name) },
                ]}
                contextMenuItems={[
                  { title: '简介', systemImage: 'info.circle', action: () => {
                    const fakeBm: Bookmark = { name: sysDir.displayName || sysDir.name, path: sysDir.path, bookmarkId: '' }
                    Navigation.present({ element: <BookmarkInfoDialog bookmark={fakeBm} />, modalPresentationStyle: 'pageSheet' })
                  }},
                  { title: '重命名', systemImage: 'pencil', action: () => handleSystemRename(sysDir.name) },
                ]}
              />
            )
          })}
        </Section>

        {/* ── 已挂载目录 ── */}
        {displayBookmarks.value.length > 0 ? (
          <Section>
            {displayBookmarks.value.map((bookmark: Bookmark, index: number) => {
                const dirPath = getAccessiblePath(bookmark);
                const bookmarkAsFile = {
                  name: bookmark.name,
                  path: bookmark.path,
                  isDirectory: true,
                  size: 0,
                  modificationDate: Date.now(),
                  extension: '',
                  icon: 'folder.fill',
                  iconColor: 'systemBlue',
                  category: 'folder',
                } as any
                const isAccessible = dirPath != null && !inaccessiblePaths.has(bookmark.path)
                const isSelected = selectedNames.has(bookmark.name)
                if (selectMode) {
                  return (
                    <FileListItem
                      file={bookmarkAsFile}
                      hideTopSeparator={index === 0}
                      selectMode={{
                        isSelected,
                        onToggle: () => toggleSelect(bookmark.name),
                      }}
                    />
                  )
                }
                return (
                  <FileListItem
                    file={bookmarkAsFile}
                    destination={isAccessible ? <GeneralBrowser dirPath={dirPath} dirName={bookmark.name} rootPath={dirPath} parentFullscreen={parentFullscreen} /> : undefined}
                    subtitle={isAccessible
                      ? (showFolderItemCounts !== false && folderCounts.has(bookmark.path) ? `${folderCounts.get(bookmark.path)} 项` : '文件夹')
                      : '⚠ 软件更新导致路径变化，无法访问，请重新挂载'}
                    subtitleForegroundStyle={isAccessible ? undefined : 'red'}
                    hideTopSeparator={index === 0}
                    navPath={isAccessible ? navPath : undefined}
                    navPageId={isAccessible ? 'browser:' + bookmark.path : undefined}
                    trailingActions={[
                      { title: '取消挂载', systemImage: 'trash', role: 'destructive', action: () => handleRemoveBookmark(bookmark) },
                      { title: '简介', systemImage: 'info.circle', action: () => {
                        Navigation.present({ element: <BookmarkInfoDialog bookmark={bookmark} />, modalPresentationStyle: 'pageSheet' });
                      }},
                    ]}
                    leadingActions={[
                      { title: '重命名', systemImage: 'pencil', action: () => handleRename(bookmark, onRefresh) },
                    ]}
                    contextMenuItems={[
                      { title: '简介', systemImage: 'info.circle', action: () => {
                        Navigation.present({ element: <BookmarkInfoDialog bookmark={bookmark} />, modalPresentationStyle: 'pageSheet' });
                      }},
                      { title: '重命名', systemImage: 'pencil', action: () => handleRename(bookmark, onRefresh) },
                      { title: '取消挂载', systemImage: 'trash', role: 'destructive', action: () => handleRemoveBookmark(bookmark) },
                    ]}
                  />
                );
              })}
            </Section>
        ) : null}
      </List>
      </VStack>
    </NavigationStack>
    </ZStack>
  );
}


