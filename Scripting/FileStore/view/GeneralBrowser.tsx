// 目录浏览器组件

import {
  Navigation,
  NavigationStack,
  List,
  Section,
  VStack,
  HStack,
  ZStack,
  Rectangle,
  Text,
  Button,
  ScrollViewReader,
  useState,
  useEffect,
  useMemo,
  useRef,
  useCallback,
  Path,
  useObservable,
  Group,
  ControlGroup,
  Spacer,
  Toolbar,
  ToolbarItem,
  Divider,
  Menu,
  NavigationDestination,
  EmptyView,
} from "scripting";
import {
  fmtSize,
  getFileCategory,
  getFileInfo,
  FileInfo,
  listDirectory,
  countDirectoryItems,
  countDirectoryItemsBatch,
  searchFiles,
  getCachedDirectoryListing,
  readClipboardPath,
  writeClipboardPath,
  renameWithPrompt,
  invalidateDirectoryCache,
  getMimeType,
  uniquePath,
  sanitizeExtractDirName,
  safeUnzip,
  extractArchiveSmartToNewDir,
  createSevenZArchive,
  createZipArchive,
  shareFilePath,
  buildSystemDirDefs,
} from "../manager/utils";
import { FileRowContent } from "./FileRowContent";
import { FileRowContextMenu } from "./FileRowContextMenu";
import { FolderCountStore } from "./FolderCountLabel";
import { DeepSearchResult } from "./SearchPanel";
import { SearchPanel } from "./SearchPanel";
import { onSearchStateChange } from "../manager/SearchState";
import { ArchiveBrowserPage, FileNavigationDest } from "./MediaViewer";
import { ToolbarMenu } from "./ToolbarMenu";
import { FileListItem, FileInfoDialog } from "./FileListItem";
import { filterFiles, sortFilesByOrder, normalizeSortOrder, DEFAULT_SORT_ORDER, DEFAULT_FILTER_TYPE } from "../manager/sortFilter";
import { isLivePhotoFile, unpackLivePhoto } from "../manager/LivePhotoPacker";
import { resolveOpenerForFile } from "./DefaultOpenerPicker";
import { getDefaultOpener, setDefaultOpener, OPENER_OPTIONS } from "../manager/DefaultOpener";
import { AppSettings, saveSettings, readSettings } from "../manager/Settings";
import { SettingsPage } from "./SettingsPage";
import { MountDirectoriesPage } from "./MountDirectoriesPage";
import { Bookmark, getAllBookmarks, addDirectoryBookmark, removeBookmark, resolveBookmarkPath, onBookmarksChanged } from "../manager/BookmarkManager";
import { ensureDir, makeTimestamp, importSinglePhotoResult } from "../manager/importHelpers";
import { DROP_ACCEPTED_TYPES, handleDropToDirectory } from "../manager/dropHandler";
import { makeDragConfig } from "./FileListItem";
import { showToast, showRemountWarning } from "../manager/ToastManager";
import { startLocalHttpServer, getActiveServers, stopServer, subscribe } from "../manager/LocalHttpServer";
import { WebPreviewPage } from "./WebPreviewPage";


// 剪贴板路径文件（用文件持久化，跨 tab/子目录保留）
const _readClipPath = readClipboardPath;
const _writeClipPath = writeClipboardPath;

const DIRECTORY_POLL_MIN_INTERVAL_MS = 999;
const DIRECTORY_POLL_MAX_INTERVAL_MS = 60000;
const DIRECTORY_POLL_FORCE_FULL_EVERY = 10;

function ManagedBookmarksSheet({
  showFolderItemCounts,
  onBookmarksChanged,
  onSettingsChange,
}: {
  showFolderItemCounts?: boolean;
  onBookmarksChanged: () => void;
  onSettingsChange?: (settings: AppSettings) => void;
}) {
  const [sheetBookmarks, setSheetBookmarks] = useState<Bookmark[]>(() => getAllBookmarks());

  const handleRefresh = () => {
    setSheetBookmarks(getAllBookmarks());
    onBookmarksChanged();
  };

  return <MountDirectoriesPage bookmarks={sheetBookmarks} showFolderItemCounts={showFolderItemCounts ?? true} onRefresh={handleRefresh} onSettingsChange={onSettingsChange} />;
}

async function getDirectoryPollToken(dirPath: string): Promise<string | null> {
  try {
    const stat = await FileManager.stat(dirPath);
    return `${stat.modificationDate || 0}:${stat.size || 0}`;
  } catch {
    return null;
  }
}

function tailDisplayPath(pathText: string, maxChars: number = 28): string {
  if (pathText.length <= maxChars) return pathText;
  const parts = pathText.split("/").filter(Boolean);
  if (parts.length === 0) return "..." + pathText.slice(-(maxChars - 3));
  const limit = Math.max(6, maxChars - 4);
  let tail = parts[parts.length - 1];
  for (let i = parts.length - 2; i >= 0; i--) {
    const next = `${parts[i]}/${tail}`;
    if (next.length > limit) break;
    tail = next;
  }
  if (tail.length > limit) tail = tail.slice(-limit);
  return `.../${tail}`;
}

/* ───── 文件行组件 ───── */
function FileRowLink({
  file,
  onRefresh,
  onDeleteFile,
  onRequestDelete,
  selectMode,
  isSelected,
  onToggleSelect,
  navPath,
  hideTopSeparator,
  folderCountStore,
  onCopyPath,
  isHighlighted,
  copyToDirTitle,
  onCopyToDir,
  dirPath,
  onDropCompleted,
  onFolderCountChanged,
  isHomeScreenHost,
}: {
  file: FileInfo;
  onRefresh: () => void;
  onDeleteFile?: (path: string) => void;
  onRequestDelete?: (file: FileInfo, afterSwipe?: boolean) => void;
  selectMode?: boolean;
  isSelected?: boolean;
  onToggleSelect?: (path: string) => void;
  rootPath?: string;
  rootName?: string;
  navPath?: any;
  hideTopSeparator?: boolean;
  folderCountStore: FolderCountStore;
  onCopyPath?: (path: string) => void;
  isHighlighted?: boolean;
  copyToDirTitle?: string;
  onCopyToDir?: (path: string) => void;
  dirPath?: string;
  onDropCompleted?: () => void;
  onFolderCountChanged?: (folderPath: string, count: number) => void;
  isHomeScreenHost?: boolean;
}) {
  const handleRename = async () => {
    const trimmed = await renameWithPrompt(file.name);
    if (trimmed) {
      try {
        const newPath = Path.join(Path.dirname(file.path), trimmed);
        await FileManager.rename(file.path, newPath);
        onRefresh();
      } catch (e) {
        console.log("重命名失败:", e);
      }
    }
  };

  const handleShowInfo = () => {
    Navigation.present({ element: <FileInfoDialog file={file} />, modalPresentationStyle: "pageSheet" });
  };

  const handleDelete = () => {
    onRequestDelete?.(file, false);
  };

  const handleSwipeDelete = () => {
    onRequestDelete?.(file, true);
  };

  const handleShare = async () => {
    await shareFilePath(file.path, file.name);
  };

  const openEditor = async (scrollToLine?: number) => {
    /*     if (isHomeScreenHost) {
          await Navigation.present({
            element: <EditorPage path={file.path} mode="present" scrollToLine={scrollToLine} />,
            modalPresentationStyle: "pageSheet",
          });
          return;
        } */
    if (navPath) {
      navPath.setValue([...navPath.value, "editor:" + file.path + (scrollToLine ? "::L" + scrollToLine : "")]);
    }
  };

  // ─ 7z 加密压缩（AES-256）：先弹居中的密码输入框，再二次确认 ─
  const handleSevenZCompress = async () => {
    try {
      const parent = dirPath || Path.dirname(file.path);
      const destPath = await uniquePath(Path.join(parent, file.name + ".7z"));
      const ok = await createSevenZArchive(file.path, destPath);
      if (!ok) return; // 用户取消或密码无效
      invalidateDirectoryCache(parent);
      onRefresh();
      showToast("7z 加密压缩完成");
    } catch (e) {
      console.log("7z 压缩失败:", e);
      showToast("7z 压缩失败");
    }
  };

  // ─ ZIP 加密压缩（AES-256）：先弹居中的密码输入框，再二次确认 ─
  const handleZipCompress = async () => {
    try {
      const parent = dirPath || Path.dirname(file.path);
      const destPath = await uniquePath(Path.join(parent, file.name + ".zip"));
      const ok = await createZipArchive(file.path, destPath);
      if (!ok) return;
      invalidateDirectoryCache(parent);
      onRefresh();
      showToast("ZIP 加密压缩完成");
    } catch (e) {
      console.log("ZIP 加密压缩失败:", e);
      showToast("ZIP 加密压缩失败");
    }
  };

  const handlePlainZipCompress = async () => {
    try {
      const parent = dirPath || Path.dirname(file.path);
      const destPath = await uniquePath(Path.join(parent, file.name + ".zip"));
      await FileManager.zip(file.path, destPath);
      invalidateDirectoryCache(parent);
      onRefresh();
      showToast("压缩完成");
    } catch (e) {
      console.log("压缩失败:", e);
      showToast("压缩失败");
    }
  };

  // ─ 统一智能解压到文件名子文件夹：真实识别 ZIP/7z，支持有密码和无密码 ─
  const handleExtractToFolder = async () => {
    try {
      const archiveName = sanitizeExtractDirName(file.name);
      const parentDir = dirPath || Path.dirname(file.path);
      let extractDir = Path.join(parentDir, archiveName);
      if (await FileManager.exists(extractDir)) {
        let counter = 1;
        while (await FileManager.exists(Path.join(parentDir, `${archiveName}_${String(counter).padStart(2, "0")}`))) {
          counter++;
        }
        extractDir = Path.join(parentDir, `${archiveName}_${String(counter).padStart(2, "0")}`);
      }
      const ok = await extractArchiveSmartToNewDir(file.path, extractDir)
      if (!ok) return; // 用户取消输入密码
      invalidateDirectoryCache(parentDir);
      onRefresh();
      showToast(`已解压到 ${Path.basename(extractDir)}`);
    } catch (e) {
      console.log("解压失败:", e);
      showToast("解压失败");
    }
  };

  // ─ 选择模式 ─
  if (selectMode) {
    return (
      <FileListItem
        file={file}
        hideTopSeparator={hideTopSeparator}
        selectMode={{
          isSelected: isSelected || false,
          onToggle: onToggleSelect ? () => onToggleSelect(file.path) : () => { },
        }}
      />
    );
  }

  // ─ 普通模式：使用 FileListItem 实现 ─
  const cat = getFileCategory(file.extension);
  const defaultOpener = file.isDirectory ? null : getDefaultOpener(Path.extname(file.path));
  const isDir = file.isDirectory;
  const isLivePhoto = isLivePhotoFile(file.name);
  const extension = file.extension.toLowerCase();
  const isImage = !isLivePhoto && cat === "image";
  const isVideo = !isLivePhoto && cat === "video";
  const isPreviewableText = !isDir && (extension === ".html" || extension === ".htm" || extension === ".md");
  const isMarkdown = extension === ".md";
  const extractFolderName = !isDir ? sanitizeExtractDirName(file.name) : "";

  return (
    <Button
      tag={file.path}
      action={async () => {
        if (navPath) {
          if (isDir) {
            navPath.setValue([...navPath.value, "browser:" + file.path]);
          } else {
            const prefix = await resolveOpenerForFile(file.path, cat);
            if (prefix) {
              if (prefix === "extract:") {
                // 直接解压到当前目录，不导航
                try {
                  const destDir = dirPath || Path.dirname(file.path);
                  await safeUnzip(file.path, destDir);
                  invalidateDirectoryCache(destDir);
                  onRefresh();
                  showToast("解压完成");
                } catch (e) {
                  console.log("解压失败:", e);
                  showToast("解压失败");
                }
              } else if (prefix === "extractfolder:" || prefix === "extract7z:") {
                // 统一智能解压：自动识别 ZIP/7z，支持有密码和无密码；兼容旧版已保存的 7z 默认方式
                await handleExtractToFolder();
              } else if (prefix === "archive:") {
                await Navigation.present({
                  element: <ArchiveBrowserPage filePath={file.path} />,
                  modalPresentationStyle: "pageSheet",
                });
              } else if (prefix === "share:") {
                await handleShare();
              } else if (prefix === "pdf:") {
                await QuickLook.previewURLs([file.path], true);
              } else if (prefix === "webpage:") {
                const wv = new WebViewController();
                await wv.loadFile(file.path);
                await wv.present({ fullscreen: true, navigationTitle: file.name });
                wv.dispose();
              } else if (prefix === "editor:") {
                await openEditor();
              } else {
                navPath.setValue([...navPath.value, prefix + file.path]);
              }
            }
          }
        }
      }}
      listRowSeparator={hideTopSeparator ? { visibility: "hidden", edges: "top" } : undefined}
      listRowBackground={isHighlighted ? <Rectangle fill="systemGray" opacity={0.15} /> : undefined}
      trailingSwipeActions={{
        // 不设 destructive role：该角色会让 SwiftUI 将滑动动作按“立即删除”处理，
        // 即使随后弹出确认框，取消后再次滑动也会触发原生状态崩溃。
        actions: [<Button title="删除" action={handleSwipeDelete} />, <Button title="简介" action={handleShowInfo} />],
      }}
      leadingSwipeActions={{
        actions: [<Button title="重命名" action={handleRename} />],
      }}
      contextMenu={{
        menuItems: (
          <>
          <FileRowContextMenu
            file={file}
            defaultOpener={defaultOpener}
            isLivePhoto={isLivePhoto}
            isImage={isImage}
            isVideo={isVideo}
            isPreviewableText={isPreviewableText}
            isMarkdown={isMarkdown}
            extractFolderName={extractFolderName}
            copyToDirTitle={copyToDirTitle}
            onCopyPath={onCopyPath}
            onCopyToDir={onCopyToDir}
            onRefresh={onRefresh}
            onRename={handleRename}
            onDelete={handleDelete}
            onShare={handleShare}
            onOpenEditor={() => openEditor()}
            onExtractToFolder={handleExtractToFolder}
            onPlainZipCompress={handlePlainZipCompress}
            onZipCompress={handleZipCompress}
            onSevenZCompress={handleSevenZCompress}
            navPath={navPath}
            dirPath={dirPath}
          />
          {false && (
          <Group>
            <ControlGroup>
              <Button title="拷贝" systemImage="doc.on.doc" action={async () => { await onCopyPath?.(file.path); }} />
              <Button title="重命名" systemImage="pencil" action={handleRename} />
              <Button title="分享" systemImage="square.and.arrow.up" action={handleShare} />
            </ControlGroup>
            {isLivePhoto ? (
              <Button
                title="保存到相册"
                systemImage="square.and.arrow.down"
                action={async () => {
                  let tmpImg: string | null = null;
                  let tmpVid: string | null = null;
                  try {
                    const data = await FileManager.readAsData(file.path);
                    if (!data) {
                      showToast("读取文件失败");
                      return;
                    }
                    const unpacked = unpackLivePhoto(data);
                    if (!unpacked) {
                      showToast("Live Photo 格式无效");
                      return;
                    }
                    const tmpDir = FileManager.temporaryDirectory;
                    tmpImg = tmpDir + `/_lp_save_${Date.now()}.${unpacked.imageExt}`;
                    tmpVid = tmpDir + `/_lp_save_${Date.now()}.mov`;
                    await FileManager.writeAsData(tmpImg, unpacked.imageData);
                    await FileManager.writeAsData(tmpVid, unpacked.videoData);
                    await Photos.saveLivePhoto({
                      imagePath: tmpImg,
                      videoPath: tmpVid,
                    });
                    showToast("已保存到相册");
                  } catch (e) {
                    console.log("保存到相册失败:", e);
                    showToast("保存失败");
                  } finally {
                    if (tmpImg) {
                      try { await FileManager.remove(tmpImg); } catch { }
                    }
                    if (tmpVid) {
                      try { await FileManager.remove(tmpVid); } catch { }
                    }
                  }
                }}
              />
            ) : (
              <EmptyView />
            )}
            {isImage ? (
              <Button
                title="保存到相册"
                systemImage="square.and.arrow.down"
                action={async () => {
                  try {
                    await Photos.savePhoto(file.path);
                    showToast("已保存到相册");
                  } catch (e) {
                    console.log("保存图片失败:", e);
                    showToast("保存失败");
                  }
                }}
              />
            ) : (
              <EmptyView />
            )}
            {isVideo ? (
              <Button
                title="导出到相册"
                systemImage="square.and.arrow.down"
                action={async () => {
                  try {
                    await Photos.saveVideo(file.path);
                    showToast("已导出到相册");
                  } catch (e) {
                    console.log("导出视频失败:", e);
                    showToast("导出失败");
                  }
                }}
              />
            ) : (
              <EmptyView />
            )}
            {isPreviewableText ? (
              <>
                {isMarkdown ? (
                  <Button
                    title="预览 Markdown"
                    systemImage="doc.text.magnifyingglass"
                    action={async () => {
                      if (navPath) {
                        navPath.setValue([...navPath.value, 'markdown:' + file.path]);
                      }
                    }}
                  />
                ) : (
                  <Button
                    title="预览网页"
                    systemImage="safari"
                    action={async () => {
                      const wv = new WebViewController();
                      await wv.loadFile(file.path);
                      await wv.present({ fullscreen: true, navigationTitle: file.name });
                      wv.dispose();
                    }}
                  />
                )}
                <Button
                  title="编辑"
                  systemImage="chevron.left.forwardslash.chevron.right"
                  action={() => openEditor()}
                />
                <Divider />
              </>
            ) : (
              <EmptyView />
            )}
            {copyToDirTitle && onCopyToDir ? (
              <Button
                title={copyToDirTitle!}
                systemImage="arrow.right.doc.on.clipboard"
                action={async () => {
                  await onCopyToDir!(file.path);
                }}
              />
            ) : (
              <EmptyView />
            )}
            {/* 压缩/解压 — 所有文件都有压缩选项，归档文件额外有解压选项 */}
            {getFileCategory(file.extension) === "archive" ? (
              <>
                <Button
                  title="查看压缩文件"
                  systemImage="archivebox.fill"
                  action={() => {
                    Navigation.present({
                      element: <ArchiveBrowserPage filePath={file.path} />,
                      modalPresentationStyle: "pageSheet",
                    });
                  }}
                />
                <Divider />
              </>
            ) : (
              <EmptyView />
            )}
            {!file.isDirectory ? (
              <Button
                title={`解压到（${extractFolderName}）`}
                systemImage="lock.open"
                action={() => handleExtractToFolder()}
              />
            ) : (
              <EmptyView />
            )}
            <Button
              title="压缩"
              systemImage="shippingbox"
              action={async () => {
                try {
                  const destPath = await uniquePath(Path.join(dirPath || Path.dirname(file.path), file.name + ".zip"));
                  await FileManager.zip(file.path, destPath);
                  invalidateDirectoryCache(dirPath || Path.dirname(file.path));
                  onRefresh();
                  showToast("压缩完成");
                } catch (e) {
                  console.log("压缩失败:", e);
                  showToast("压缩失败");
                }
              }}
            />
            <Button
              title="ZIP 加密压缩 (AES-256)"
              systemImage="lock.doc"
              action={handleZipCompress}
            />
            <Button
              title="7z 加密压缩 (AES-256)"
              systemImage="lock.doc"
              action={handleSevenZCompress}
            />
            <Divider />
            {!file.isDirectory ? (
              <Menu title="默认打开方式" systemImage="gear">
                {OPENER_OPTIONS.map((opt) => (
                  <Button
                    title={opt.label}
                    systemImage={defaultOpener === opt.prefix ? "checkmark" : undefined}
                    action={async () => {
                      setDefaultOpener(Path.extname(file.path), opt.prefix);
                      onRefresh();
                    }}
                  />
                ))}
              </Menu>
            ) : (
              <EmptyView />
            )}
            <Button title="简介" systemImage="info.circle" action={handleShowInfo} />
            <Button title="删除" systemImage="trash" role="destructive" action={handleDelete} />
          </Group>
          )}
          </>
        ),
      }}
      onDrag={file.isDirectory ? undefined : makeDragConfig(file.path)}
      onDrop={{
        types: DROP_ACCEPTED_TYPES,
        validateDrop: (info) => {
          const ok = info.hasItemsConforming(DROP_ACCEPTED_TYPES);
          return ok;
        },
        dropEntered: () => { },
        performDrop: (info) => {
          const destDir = file.isDirectory ? file.path : dirPath;
          if (!destDir) return false;
          if (file.isDirectory) invalidateDirectoryCache(destDir);
          handleDropToDirectory(info, destDir, () => { })
            .then(async () => {
              if (file.isDirectory) {
                try {
                  const children = await countDirectoryItems(destDir);
                  onFolderCountChanged?.(destDir, children);
                } catch { }
              }
              try {
                await onRefresh();
              } catch { }
              onDropCompleted?.();
            })
            .catch(async () => {
              try {
                await onRefresh();
              } catch { }
              onDropCompleted?.();
            });
          return true;
        },
      }}
    >
      <HStack spacing={12} alignment="center">
        <FileRowContent file={file} folderCountStore={folderCountStore} />
      </HStack>
    </Button>
  );
}

/* ───── 目录浏览器主组件 ───── */

function GeneralBrowser({
  dirPath = "",
  dirName,
  rootPath,
  rootName,
  navPath: outerNavPath,
  navigationDestination,
  items,
  onItemsChange,
  toolbarOtherItems,
  toolbarLeadingItems,
  toolbarTrailingItems,
  showFolderItemCounts,
  onOpenSettings,
  initialSortOrder,
  initialFilterType,
  onSortFilterChange,
  refreshKey,
  highlightFile,
  isHomePage,
  settings,
  onSettingsChange,
  bookmarks,
  externalCopiedPath,
  onExternalCopy,
  oppositeDirName,
  onCopyToOppositeDir,
  onDirChange,
  initialLoadDelay,
  clipboardSyncTrigger,
  addFilesRef,
  onFilesAdded,
  onDropCompleted,
  onFolderCountChanged,
  folderCountUpdateRef,
  isHomeScreenHost,
  isFocused = true,
}: {
  dirPath?: string;
  dirName?: string;
  rootPath?: string;
  rootName?: string;
  navPath?: any;
  navigationDestination?: any;
  items?: FileInfo[];
  onItemsChange?: (items: FileInfo[]) => void;
  toolbarOtherItems?: any;
  toolbarLeadingItems?: any;
  toolbarTrailingItems?: any;
  showFolderItemCounts?: boolean;
  onOpenSettings?: () => void;
  initialSortOrder?: import("../manager/sortFilter").SortOrder;
  initialFilterType?: string;
  onSortFilterChange?: (sortOrder: import("../manager/sortFilter").SortOrder, filterType: string) => void;
  refreshKey?: number;
  highlightFile?: string;
  isHomePage?: boolean;
  settings?: AppSettings;
  onSettingsChange?: (settings: AppSettings) => void;
  bookmarks?: Bookmark[];
  externalCopiedPath?: string | null;
  onExternalCopy?: (path: string) => void;
  oppositeDirName?: string;
  onCopyToOppositeDir?: (path: string) => void;
  onDirChange?: (dir: string) => void;
  initialLoadDelay?: number;
  clipboardSyncTrigger?: number;
  addFilesRef?: { current?: (files: FileInfo[]) => void };
  onFilesAdded?: (files: FileInfo[]) => void;
  onDropCompleted?: () => void;
  onFolderCountChanged?: (folderPath: string, count: number) => void;
  isHomeScreenHost?: boolean;
  folderCountUpdateRef?: { current?: (folderPath: string, count: number) => void };
  isFocused?: boolean;
}) {
  const cachedFiles = !items && dirPath ? getCachedDirectoryListing(dirPath) : null;
  const [files, setFiles] = useState<FileInfo[]>(cachedFiles || []);
  const [isLoading, setIsLoading] = useState(!items && !cachedFiles);

  // 暴露 addFiles 给父组件（双栏跨栏复制时乐观更新）
  if (addFilesRef) {
    addFilesRef.current = (newFiles: FileInfo[]) => {
      setFiles((prev) => {
        const existing = new Set(prev.map((f) => f.path));
        const unique = newFiles.filter((f) => !existing.has(f.path));
        if (unique.length === 0) return prev;
        return [...prev, ...unique];
      });
    };
  }

  let sourceFiles = items ?? files;
  /* ── 防止 displayFiles 变化时重复滚动到高亮文件 ── */
  const [searchQuery, setSearchQuery] = useState("");
  const [showSearch, setShowSearch] = useState(false);

  // 从 settings 或 props 读取排序/筛选初始值
  const [sortOrder, setSortOrder] = useState<import("../manager/sortFilter").SortOrder>(
    () => normalizeSortOrder(settings?.defaultSortOrder || readSettings().defaultSortOrder || initialSortOrder || DEFAULT_SORT_ORDER),
  );
  const [filterType, setFilterType] = useState<string>(() => (isHomePage && settings?.defaultFilterType ? settings.defaultFilterType : initialFilterType || DEFAULT_FILTER_TYPE));

  // 选择模式
  const [selectMode, setSelectMode] = useState(false);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const handleDeleteFile = useCallback((filePath: string) => {
    setFiles((current) => current.filter((entry) => entry.path !== filePath));
  }, []);

  // 搜索栏是否活跃
  const [copiedFilePath, setCopiedFilePath] = useState<string | null>(null);
  // 跳转到目录时高亮的文件路径
  const [highlightedPath, setHighlightedPath] = useState<string | null>(null);
  const handledRouteHighlightRef = useRef<string | null>(null);
  const routeHighlightTimerRef = useRef<number | null>(null);
  const scrollProxy = useRef<any>(null);
  // 标记：首次加载不带动画，避免初次滑动卡顿
  const firstLoadRef = useRef(true);
  const loadSeqRef = useRef(0);
  useEffect(() => {
    return () => {
      if (routeHighlightTimerRef.current) clearTimeout(routeHighlightTimerRef.current);
    };
  }, []);

  // 启动时和刷新时从文件恢复剪贴板路径
  // 当 externalCopiedPath 由父组件管理（双栏模式）时，以外部来源为准，不读取文件
  useEffect(() => {
    if (externalCopiedPath !== undefined) return;
    (async () => {
      const p = await _readClipPath();
      if (p != null) setCopiedFilePath(p);
    })();
  }, [refreshKey, externalCopiedPath]);

  // 仅同步剪贴板路径（不触发目录加载），由 clipboardSyncTrigger 驱动
  // 当 externalCopiedPath 由父组件管理时，以外部来源为准，不读取文件
  useEffect(() => {
    if (clipboardSyncTrigger == null) return;
    if (externalCopiedPath !== undefined) return;
    (async () => {
      const p = await _readClipPath();
      if (p != null) setCopiedFilePath(p);
    })();
  }, [clipboardSyncTrigger, externalCopiedPath]);

  // 组件挂载时立即显示 spinner，消除空内容闪屏
  // 第二次及以后的 isLoading 变化仍由上方 100ms 延迟控制，防闪烁
  const updateCopiedPath = useCallback(async (path: string | null) => {
    // 先更新 UI 状态，再异步写入文件（粘贴按钮立即出现）
    setCopiedFilePath(path);
    await _writeClipPath(path);
    // 如果有外部剪贴板回调，同步通知（跨栏共享）
    if (onExternalCopy) {
      onExternalCopy(path ?? "");
    }
  }, [onExternalCopy]);
  const handleRowCopyPath = useCallback((path: string) => {
    updateCopiedPath(path);
  }, [updateCopiedPath]);

  // 同步外部剪贴板路径到本地状态（覆盖脏数据，避免粘贴旧内容）
  useEffect(() => {
    if (externalCopiedPath !== undefined) {
      setCopiedFilePath(externalCopiedPath || null);
    }
  }, [externalCopiedPath]);

  // 优先使用外部传入的剪贴板路径（DualBrowserPage 跨栏共享）
  // 有共享路径时优先用它（最新），没有时用本地状态
  const effectiveCopiedPath = externalCopiedPath !== undefined ? externalCopiedPath || copiedFilePath : copiedFilePath;

  // 深度搜索结果
  const [deepSearchResults, setDeepSearchResults] = useState<DeepSearchResult[]>([]);

  // 每个子文件夹内的项目数。使用订阅 store，避免计数更新触发整个列表重渲染。
  const folderCountsRef = useRef<Map<string, number>>(new Map());
  const folderCountListenersRef = useRef<Map<string, Set<(count: number) => void>>>(new Map());
  const folderCountStore = useMemo<FolderCountStore>(() => ({
    get: (path) => folderCountsRef.current.get(path),
    subscribe: (path, listener) => {
      let listeners = folderCountListenersRef.current.get(path);
      if (!listeners) {
        listeners = new Set();
        folderCountListenersRef.current.set(path, listeners);
      }
      listeners.add(listener);
      return () => {
        listeners?.delete(listener);
        if (listeners && listeners.size === 0) folderCountListenersRef.current.delete(path);
      };
    },
  }), []);
  const publishFolderCount = (path: string, count: number) => {
    if (folderCountsRef.current.get(path) === count) return;
    folderCountsRef.current.set(path, count);
    folderCountListenersRef.current.get(path)?.forEach((listener) => listener(count));
  };
  const mergeFolderCountUpdates = (counts: { path: string; count: number }[]) => {
    counts.forEach(({ path, count }) => publishFolderCount(path, count));
  };
  const mergeFolderCountUpdatesRef = useRef(mergeFolderCountUpdates);
  mergeFolderCountUpdatesRef.current = mergeFolderCountUpdates;
  const applyFolderCountUpdate = useCallback((folderPath: string, count: number, notifyPeer: boolean = true) => {
    publishFolderCount(folderPath, count);
    if (notifyPeer) onFolderCountChanged?.(folderPath, count);
  }, [onFolderCountChanged]);
  if (folderCountUpdateRef) {
    folderCountUpdateRef.current = (folderPath: string, count: number) => {
      applyFolderCountUpdate(folderPath, count, false);
    };
  }

  const [serverTick, setServerTick] = useState(0);
  const deleteConfirmingRef = useRef(false);
  // 删除确认弹窗的延迟定时器：滑删后快速返回上一页时在卸载 effect 里清除，
  // 避免 Dialog.confirm 在已 pop 的页面上呈现。
  const deleteDialogTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // 所有目录浏览器订阅同一服务状态；任一侧启停服务时双列都会刷新。
  useEffect(() => subscribe(() => setServerTick((t) => t + 1)), []);

  // ── 首页专用状态 ──
  const defaultDir = Path.join(FileManager.documentsDirectory, "File Store");
  const [homeCurrentDir, setHomeCurrentDir] = useState(isHomePage ? settings?.homeCurrentPath || defaultDir : dirPath || "");
  const [navGen, setNavGen] = useState(0);
  const prevNavLenRef = useRef(0);
  const homeNavPath = useObservable<string[]>([]);
  const activeHomeNavPath = isHomePage && outerNavPath ? outerNavPath : homeNavPath;
  const homeNavLength = isHomePage ? activeHomeNavPath.value.length : 0;

  // 首页模式使用内部状态管理目录路径和导航，非首页直接使用 prop
  // const 声明避免函数参数可变性带来的不可预测行为
  const activeDirPath = isHomePage ? homeCurrentDir || defaultDir : dirPath || "";
  const activeNavPath = isHomePage ? activeHomeNavPath : outerNavPath;

  // Refs for stale-closure-safe access in effects（避免陈旧闭包）
  const activeDirPathRef = useRef(activeDirPath);
  activeDirPathRef.current = activeDirPath;
  const itemsRef = useRef(items);
  itemsRef.current = items;
  const onItemsChangeRef = useRef(onItemsChange);
  onItemsChangeRef.current = onItemsChange;
  const showFolderItemCountsRef = useRef(showFolderItemCounts);
  showFolderItemCountsRef.current = showFolderItemCounts;

  useEffect(() => {
    if (!isHomePage) return;
    if (homeNavLength > prevNavLenRef.current) {
      setNavGen((g) => g + 1);
    }
    prevNavLenRef.current = homeNavLength;
  }, [isHomePage, homeNavLength]);

  useEffect(() => {
    if (isHomePage) {
      let resolvedPath = settings?.homeCurrentPath;
      if (settings?.homeDirectoryBookmarkName) {
        try {
          const bp = FileManager.bookmarkedPath(settings.homeDirectoryBookmarkName);
          if (bp) resolvedPath = bp;
        } catch (e) {
          console.log("解析首页书签失败:", e);
        }
      }
      setHomeCurrentDir(resolvedPath || defaultDir);
    }
  }, [settings?.homeCurrentPath, settings?.homeDirectoryBookmarkName]);

  const currentDirInternal = activeDirPath || "";

  // 向父级报告当前目录路径（双栏浏览需知道对方目录）
  useEffect(() => {
    onDirChange?.(currentDirInternal);
  }, [currentDirInternal]);

  useEffect(() => {
    if (!items) {
      if (initialLoadDelay && initialLoadDelay > 0) {
        const timer = setTimeout(() => {
          loadDirectory(true);
        }, initialLoadDelay);
        return () => clearTimeout(timer);
      } else {
        loadDirectory(true);
      }
    }
  }, [activeDirPath, items, initialLoadDelay]);

  useEffect(() => {
    if (refreshKey != null && refreshKey > 0) {
      const _items = itemsRef.current;
      const _activeDirPath = activeDirPathRef.current;
      const _onItemsChange = onItemsChangeRef.current;
      const _showFolderItemCounts = showFolderItemCountsRef.current;
      if (_activeDirPath) invalidateDirectoryCache(_activeDirPath);
      const doRefresh = async () => {
        if (_items && _onItemsChange) {
          if (_activeDirPath) {
            try {
              const refreshed = await listDirectory(_activeDirPath);
              _onItemsChange(refreshed);
            } catch { }
          }
        } else {
          await loadDirectoryRef.current(true);
        }
        // 目录刷新完成后，直接从 listDirectory（命中刚填充的缓存）获取子目录列表并计数。
        // 不依赖当前渲染切片，避免刷新后 React 尚未提交新列表时拿到旧数据。
        if (_showFolderItemCounts !== false && _activeDirPath) {
          try {
            const freshItems = await listDirectory(_activeDirPath);
            const dirs = freshItems.filter((f) => f.isDirectory);
            if (dirs.length === 0) return;
            // 有界并发读取，避免大量子目录计数串行阻塞刷新，同时不使磁盘 I/O 突增。
            const counts = (await countDirectoryItemsBatch(dirs.map((dir) => dir.path), true))
              .filter((entry): entry is { path: string; count: number } => entry.count !== null);
            if (counts.length > 0) mergeFolderCountUpdatesRef.current(counts);
          } catch { }
        }
      };
      doRefresh();
    }
  }, [refreshKey]);

  const loadDirectory = async (silent = false, retryCount = 0) => {
    if (items || !activeDirPath) return;
    const loadSeq = ++loadSeqRef.current;
    const loadingDir = activeDirPath;
    if (!silent) setIsLoading(true);
    const isLatestLoad = () => loadSeq === loadSeqRef.current && loadingDir === activeDirPath;
    try {
      const itemsList = await listDirectory(loadingDir);
      if (!isLatestLoad()) return;
      // 加载后立即查找要高亮的文件
      if (highlightFile && handledRouteHighlightRef.current !== highlightFile) {
        const matched = itemsList.find((f) => f.name === highlightFile);
        if (matched) {
          handledRouteHighlightRef.current = highlightFile;
          withAnimation(Animation.smooth({ duration: 0.4 }), () => {
            setFiles(itemsList);
            setHighlightedPath(matched.path);
          });
          setTimeout(() => scrollProxy.current?.scrollTo(matched.path, "center"), 450);
          if (routeHighlightTimerRef.current) clearTimeout(routeHighlightTimerRef.current);
          routeHighlightTimerRef.current = setTimeout(() => {
            setHighlightedPath((current) => (current === matched.path ? null : current));
            routeHighlightTimerRef.current = null;
          }, 2000);
          setIsLoading(false);
          return;
        }
      }
      // 文件夹计数懒加载：仅计算可见文件夹
      if (firstLoadRef.current) {
        // 首次加载：直接设置不带动画，避免初次滑动卡顿
        setFiles(itemsList);
        firstLoadRef.current = false;
      } else {
        withAnimation(Animation.smooth({ duration: 0.4 }), () => {
          setFiles(itemsList);
        });
      }
      setIsLoading(false);
    } catch (e) {
      console.log("加载目录失败:", e);
      // iCloud 未下载的目录：readDirectory 可能抛错。触发一次目录级下载后自动重试，
      // 避免点进 iCloud 目录“点不进去”且列表永远为空。
      if (retryCount < 1 && loadingDir) {
        try {
          if (typeof FileManager.isFileStoredIniCloud === "function" && FileManager.isFileStoredIniCloud(loadingDir)) {
            console.log("目录在 iCloud 中，尝试触发下载后重试:", loadingDir);
            await FileManager.downloadFileFromiCloud(loadingDir).catch(() => false);
            if (isLatestLoad()) {
              invalidateDirectoryCache(loadingDir);
              return await loadDirectory(silent, retryCount + 1);
            }
          }
        } catch { }
      }
      // 首页根目录不存在或不可读取（如残留书签指向无权限的缓存目录）时，回退到默认目录并修正存档
      if (isHomePage && loadingDir) {
        try {
          // 计算首页配置的根目录（与挂载时的解析逻辑一致）
          let homeRoot = settings?.homeCurrentPath || defaultDir;
          if (settings?.homeDirectoryBookmarkName) {
            try {
              const bp = FileManager.bookmarkedPath(settings.homeDirectoryBookmarkName);
              if (bp) homeRoot = bp;
            } catch { }
          }
          const norm = (p: string) => p.replace(/\/+$/, "");
          // 加载的就是首页根目录、且它不是默认目录本身时才回退（进入此 catch 说明目录已不可读/不存在）
          const isRoot = norm(loadingDir) === norm(homeRoot);
          if (isRoot && norm(loadingDir) !== norm(defaultDir)) {
            console.log("首页目录不存在或不可访问，回退到默认目录:", defaultDir);
            // 软件更新后首页书签失效（无权限/路径变化）：用 ToastOverlay 提醒重新挂载
            showRemountWarning(settings?.homeDirectoryBookmarkName ? "首页目录" : undefined);
            setHomeCurrentDir(defaultDir);
            if (settings && onSettingsChange) {
              const restored = { ...settings, homeCurrentPath: defaultDir, homeDirectoryBookmarkName: null };
              saveSettings(restored);
              onSettingsChange(restored);
            }
            // 确保默认目录存在
            if (!(await FileManager.exists(defaultDir))) {
              try {
                await FileManager.createDirectory(defaultDir, true);
              } catch (e2) {
                console.log("创建默认目录失败:", e2);
              }
            }
            // 重新加载默认目录
            const itemsList = await listDirectory(defaultDir);
            if (!isLatestLoad()) return;
            setFiles(itemsList);
          }
        } catch { }
      }
      if (isLatestLoad()) setIsLoading(false);
    }
  };
  const loadDirectoryRef = useRef(loadDirectory);
  loadDirectoryRef.current = loadDirectory;

  const refreshDirectory = useCallback(async () => {
    // 强制清除缓存，确保从磁盘读取最新内容（拖拽/删除/重命名等操作依赖此行为）
    if (activeDirPath) invalidateDirectoryCache(activeDirPath);
    // 用户主动刷新时恢复短轮询，之后无变化再逐步退避。
    pollResetRef.current += 1;
    if (items && onItemsChange) {
      // items mode: reload from disk to get refreshed items
      if (activeDirPath) {
        try {
          const refreshed = await listDirectory(activeDirPath);
          onItemsChange(refreshed);
        } catch { }
      }
    } else {
      await loadDirectory(true);
    }
  }, [activeDirPath, items, onItemsChange]);


  // 999ms 轮询检测目录内容变化 + 新增文件高亮（非 items 模式）
  // 每次先 stat 当前目录；目录未变化时跳过昂贵的 readDirectory + getFileInfo 全量扫描。
  // isFocused 为 false 时停止轮询以节省 CPU
  const filesRef = useRef<FileInfo[]>(files);
  filesRef.current = files;
  const prevPollRef = useRef<FileInfo[] | null>(null);
  const prevPollTokenRef = useRef<string | null>(null);
  const pollCountRef = useRef(0);
  const pollSeqRef = useRef(0);
  const pollResetRef = useRef(0);
  useEffect(() => {
    // 自增序列号：新目录的轮询启动时，旧目录正在进行的异步操作可检测到序号不匹配并自动中止
    pollSeqRef.current += 1;
    const seq = pollSeqRef.current;
    if (items || !activeDirPath || !isFocused) return;
    // 切换目录时重置轮询快照，避免用旧目录的文件列表与新目录比较而误高亮
    prevPollRef.current = null;
    prevPollTokenRef.current = null;
    pollCountRef.current = 0;
    let pollTimer: number | null = null;
    let pollIntervalMs = DIRECTORY_POLL_MIN_INTERVAL_MS;
    let seenPollReset = pollResetRef.current;
    const isLatestPoll = () => seq === pollSeqRef.current;
    const scheduleNextPoll = () => {
      if (isLatestPoll()) {
        pollTimer = setTimeout(poll, pollIntervalMs);
      }
    };
    const poll = async () => {
      if (!isLatestPoll()) return;
      if (seenPollReset !== pollResetRef.current) {
        seenPollReset = pollResetRef.current;
        pollIntervalMs = DIRECTORY_POLL_MIN_INTERVAL_MS;
      }
      try {
        pollCountRef.current += 1;
        const token = await getDirectoryPollToken(activeDirPath);
        if (!isLatestPoll()) return;
        const forceFullScan = pollCountRef.current % DIRECTORY_POLL_FORCE_FULL_EVERY === 0;
        const tokenChanged = token == null || prevPollTokenRef.current == null || token !== prevPollTokenRef.current;
        if (!tokenChanged && !forceFullScan) {
          // 稳定目录指数退避，最高 60 秒；任何 token 变化或周期性全量检查都会恢复短间隔。
          pollIntervalMs = Math.min(DIRECTORY_POLL_MAX_INTERVAL_MS, pollIntervalMs * 2);
          scheduleNextPoll();
          return;
        }
        // 目录有变化或到达兜底全量检查：恢复快速轮询，及时捕获后续外部变更。
        pollIntervalMs = DIRECTORY_POLL_MIN_INTERVAL_MS;
        // 需要全量扫描时必须清除缓存，否则 listDirectory 返回缓存数据（30秒有效期），发现不了外部变化
        invalidateDirectoryCache(activeDirPath);
        const newList = await listDirectory(activeDirPath);
        if (!isLatestPoll()) return;
        const prev = prevPollRef.current;
        if (prev !== null) {
          // 后续轮询：检测变化 + 新文件高亮
          const newFiles: FileInfo[] = [];
          let changed = prev.length !== newList.length;
          const prevPaths = new Set(prev.map((f) => f.path));
          for (let i = 0; i < newList.length; i++) {
            const nextFile = newList[i];
            if (!prevPaths.has(nextFile.path)) newFiles.push(nextFile);
            const prevFile = prev[i];
            if (!changed && (!prevFile || prevFile.path !== nextFile.path || prevFile.size !== nextFile.size)) {
              changed = true;
            }
          }
          if (changed) {
            setFiles(newList);
            if (newFiles.length > 0) {
              setHighlightedPath(newFiles[0].path);
              setTimeout(() => scrollProxy.current?.scrollTo(newFiles[0].path, "center"), 100);
              setTimeout(() => setHighlightedPath(null), 2000);
            }
          }
        } else {
          // 首次轮询：只更新文件列表，不触发高亮
          const current = filesRef.current;
          const changed = current.length !== newList.length || current.some((f, i) => f.path !== newList[i].path || f.size !== newList[i].size);
          if (changed) {
            setFiles(newList);
          }
        }
        prevPollRef.current = newList;
        prevPollTokenRef.current = token;
      } catch (e) {
        // 读取失败时不要高频重试；退避后继续保持可恢复的轮询。
        pollIntervalMs = Math.min(DIRECTORY_POLL_MAX_INTERVAL_MS, pollIntervalMs * 2);
      }
      if (isLatestPoll()) {
        scheduleNextPoll();
      }
    };
    const initialTimer = setTimeout(poll, initialLoadDelay || 0);
    return () => {
      clearTimeout(initialTimer);
      if (pollTimer) clearTimeout(pollTimer);
    };
  }, [items, activeDirPath, initialLoadDelay, isFocused]);

  // serverTick 由所有浏览器实例共同订阅的 HTTP 服务事件更新，
  // 因此双列中的两侧菜单都会重新读取服务列表。
  const hasHttpServerEntry = sourceFiles.some(
    (file) => !file.isDirectory && (file.name.toLowerCase() === "index.html" || file.name.toLowerCase() === "index.htm"),
  );
  const activeServers = getActiveServers();

  const requestFileDelete = useCallback((file: FileInfo, afterSwipe = false) => {
    // 右滑菜单关闭的原生动画比普通菜单长；结束前弹出 Dialog.confirm 会在下一次取消时触发系统崩溃。
    // 长按菜单没有此问题，仍立即使用原来的确认弹窗。
    if (deleteConfirmingRef.current) return;
    deleteConfirmingRef.current = true;
    const dialogDelay = afterSwipe ? 350 : 0;
    if (deleteDialogTimerRef.current) clearTimeout(deleteDialogTimerRef.current);
    deleteDialogTimerRef.current = setTimeout(async () => {
      deleteDialogTimerRef.current = null;
      try {
        const confirmed = await Dialog.confirm({
          title: "删除文件",
          message: `确定要删除“${file.name}”吗？此操作不可撤销。`,
          cancelLabel: "取消",
          confirmLabel: "删除",
        });
        if (!confirmed) return;

        await FileManager.remove(file.path);
        // 双栏 items 模式下 setFiles 对显示无效果（sourceFiles = items ?? files），
        // 必须经 refreshDirectory 通知父组件刷新，否则磁盘已删但行仍留在列表。
        await refreshDirectory();
        if (!items) {
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => prev.filter((entry) => entry.path !== file.path));
          });
        }
      } catch (e) {
        console.log("删除失败:", e);
        showToast("删除失败");
      } finally {
        // 右滑路径额外保留一个完整的原生动画周期，避免紧接着再左滑复用旧 presentation 状态。
        const unlockDelay = afterSwipe ? 350 : 0;
        const unlockTimer = setTimeout(() => {
          deleteConfirmingRef.current = false;
        }, unlockDelay);
        // 若组件已卸载，无需再保留解锁定时器
        if (deleteDialogTimerRef.current === null && unlockDelay > 0) {
          deleteDialogTimerRef.current = unlockTimer;
        }
      }
    }, dialogDelay);
  }, [items]);

  // 卸载时清除待弹出的删除确认弹窗，防止在已销毁页面上呈现原生弹窗
  useEffect(() => {
    return () => {
      if (deleteDialogTimerRef.current) {
        clearTimeout(deleteDialogTimerRef.current);
        deleteDialogTimerRef.current = null;
      }
    };
  }, []);

  const displayFiles = useMemo(() => {
    let result = sourceFiles;
    if (searchQuery.trim()) {
      result = searchFiles(sourceFiles, searchQuery);
    }
    result = filterFiles(result, filterType);
    return sortFilesByOrder(result, sortOrder);
  }, [sourceFiles, searchQuery, sortOrder, filterType]);

  // 路由携带的高亮文件只消费一次，避免目录轮询或列表更新持续重置高亮计时器。
  useEffect(() => {
    if (!highlightFile || handledRouteHighlightRef.current === highlightFile) return;
    console.log("highlightFile changed, search for:", highlightFile, "total files:", displayFiles.length);
    const match = displayFiles.find((f) => f.name === highlightFile);
    if (match) {
      handledRouteHighlightRef.current = highlightFile;
      console.log("highlightFile match via displayFiles:", match.path);
      setHighlightedPath(match.path);
      setTimeout(() => scrollProxy.current?.scrollTo(match.path, "center"), 100);
      if (routeHighlightTimerRef.current) clearTimeout(routeHighlightTimerRef.current);
      routeHighlightTimerRef.current = setTimeout(() => {
        setHighlightedPath((current) => (current === match.path ? null : current));
        routeHighlightTimerRef.current = null;
      }, 2000);
    } else {
      console.log(
        "no match found for:",
        highlightFile,
        "first few files:",
        displayFiles.slice(0, 3).map((f) => f.name),
      );
    }
  }, [highlightFile, displayFiles, refreshKey]);

  // ─ 分页：大数据量时只渲染可见部分 ─
  const [visibleCount, setVisibleCount] = useState(100);
  // 目录切换或搜索变化时重置分页，防止跨目录/搜索后首帧按上次累积行数渲染
  useEffect(() => {
    setVisibleCount(100);
  }, [activeDirPath, searchQuery]);
  const visibleFiles = useMemo(() => displayFiles.slice(0, visibleCount), [displayFiles, visibleCount]);
  const hasMore = displayFiles.length > visibleCount;
  const preloadNextPage = (expectedVisibleCount: number) => {
    setVisibleCount((current) => (current === expectedVisibleCount ? Math.min(current + 100, displayFiles.length) : current));
  };

  // 懒加载文件夹计数：仅对可见文件夹计算（滚动时防抖）
  // refreshKey 驱动的计数由 refreshKey effect 在 loadDirectory 完成后直接处理
  const folderCountTimerRef = useRef<number | null>(null);
  useEffect(() => {
    if (showFolderItemCounts === false) return;
    if (!activeDirPath) return;
    const dirs = visibleFiles.filter((f) => f.isDirectory);
    if (dirs.length === 0) return;
    // 防抖 666ms：只在 visibleFiles 变化（滚动）时触发，避免滚动时频繁 I/O
    if (folderCountTimerRef.current) clearTimeout(folderCountTimerRef.current);
    let cancelled = false;
    folderCountTimerRef.current = setTimeout(() => {
      folderCountTimerRef.current = null;
      (async () => {
        const batch = await countDirectoryItemsBatch(dirs.map((dir) => dir.path));
        if (cancelled) return;
        // 保持原有失败显示为 0 的行为。
        mergeFolderCountUpdates(batch.map(({ path, count }) => ({ path, count: count ?? 0 })));
      })();
    }, 666);
    return () => {
      cancelled = true;
      if (folderCountTimerRef.current) {
        clearTimeout(folderCountTimerRef.current);
        folderCountTimerRef.current = null;
      }
    };
  }, [visibleFiles]);

  const fileStats = useMemo(() => {
    let folderCount = 0;
    let fileCount = 0;
    let totalSize = 0;
    for (const f of displayFiles) {
      if (f.isDirectory) {
        folderCount++;
      } else {
        fileCount++;
        totalSize += f.size;
      }
    }
    return { folderCount, fileCount, totalSize };
  }, [displayFiles]);
  const { folderCount, fileCount, totalSize } = fileStats;

  // ─ 选择操作 ─
  const toggleSelect = useCallback((path: string) => {
    setSelectedPaths((current) => {
      const next = new Set(current);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }, []);

  const selectAll = () => {
    setSelectedPaths(new Set(displayFiles.map((f) => f.path)));
  };

  const deselectAll = () => {
    setSelectedPaths(new Set());
  };

  const deleteSelected = async () => {
    const count = selectedPaths.size;
    if (count === 0) return;
    const confirmed = await Dialog.confirm({
      title: "删除文件",
      message: `确定要删除选中的 ${count} 个项目吗？此操作不可撤销。`,
      cancelLabel: "取消",
      confirmLabel: "删除",
    });
    if (!confirmed) return;
    const deletedPaths = new Set<string>();
    const failedPaths = new Set<string>();
    for (const p of selectedPaths) {
      try {
        await FileManager.remove(p);
        deletedPaths.add(p);
      } catch (e) {
        failedPaths.add(p);
        console.log("删除失败:", e);
      }
    }
    if (deletedPaths.size > 0 && activeDirPath) invalidateDirectoryCache(activeDirPath);
    withAnimation(Animation.smooth({ duration: 0.35 }), () => {
      setSelectedPaths(failedPaths);
      setSelectMode(failedPaths.size > 0);
      setFiles((prev) => prev.filter((f) => !deletedPaths.has(f.path)));
    });
    refreshDirectory();
    if (failedPaths.size > 0) showToast(`${failedPaths.size} 个项目删除失败`);
  };

  const compressSelected = async () => {
    const paths = Array.from(selectedPaths);
    if (paths.length === 0) return;
    // 自动生成压缩包名称，不弹窗输入
    const defaultName = (paths.length === 1 ? Path.basename(paths[0], Path.extname(paths[0])) : "archive") + "_" + String(Date.now()).slice(-6);
    const zipName = defaultName.endsWith(".zip") ? defaultName : `${defaultName}.zip`;
    const destPath = await uniquePath(Path.join(activeDirPath || "", zipName));
    try {
      if (paths.length === 1) {
        await FileManager.zip(paths[0], destPath);
      } else {
        // 多文件：复制到临时目录 → 压缩 → 删除临时目录
        const tmpDir = Path.join(FileManager.temporaryDirectory, `fs_compress_${Date.now()}`);
        await FileManager.createDirectory(tmpDir);
        try {
          for (const p of paths) {
            await FileManager.copyFile(p, Path.join(tmpDir, Path.basename(p)));
          }
          await FileManager.zip(tmpDir, destPath);
        } finally {
          try {
            await FileManager.remove(tmpDir);
          } catch { }
        }
      }
      invalidateDirectoryCache(activeDirPath || "");
      setSelectMode(false);
      setSelectedPaths(new Set());
      refreshDirectory();
      showToast("压缩完成");
    } catch (e) {
      console.log("压缩失败:", e);
      showToast("压缩失败");
    }
  };

  const hasAllSelected = selectedPaths.size > 0 && selectedPaths.size === displayFiles.length;

  // ─ 批量操作 ─
  const copySelectedPaths = async () => {
    const paths = Array.from(selectedPaths);
    const text = paths.join("\n");
    await Pasteboard.setString(text);
    showToast(paths.length === 1 ? "已复制文件路径" : `已复制 ${paths.length} 个文件路径`);
    setSelectMode(false);
    deselectAll();
  };

  const moveSelectedToBookmark = async () => {
    const count = selectedPaths.size;
    if (count === 0) return;
    const dest = await Dialog.prompt({
      title: "移动文件",
      message: `将 ${count} 项移动到:`,
      defaultValue: activeDirPath,
      placeholder: "目标路径",
      cancelLabel: "取消",
      confirmLabel: "移动",
    });
    if (dest == null || !dest.trim()) return;
    const destDir = dest.trim();
    const failedNames: string[] = [];
    for (const p of selectedPaths) {
      const name = Path.basename(p);
      try {
        const targetPath = Path.join(destDir, name);
        try {
          await FileManager.rename(p, targetPath);
        } catch {
          // rename 跨卷（如 iCloud→本地）会整体失败：回退 copyFile + remove
          await FileManager.copyFile(p, targetPath);
          await FileManager.remove(p);
        }
      } catch (e) {
        console.log("移动失败:", p, e);
        failedNames.push(name);
      }
    }
    setSelectedPaths(new Set());
    setSelectMode(false);
    if (activeDirPath) invalidateDirectoryCache(activeDirPath);
    // 目标目录可能是另一栏正在显示的目录，同时失效目标缓存
    invalidateDirectoryCache(destDir);
    loadDirectory(true);
    if (failedNames.length > 0) {
      showToast(`移动失败 ${failedNames.length} 项: ${failedNames.slice(0, 3).join("、")}${failedNames.length > 3 ? " …" : ""}`);
    }
  };

  // ─ 多选导出到相册 ─
  const exportSelectedPhotos = async () => {
    const paths = Array.from(selectedPaths);
    if (paths.length === 0) return;
    for (const p of paths) {
      try {
        const cat = getFileCategory(Path.extname(p));
        if (cat === "image") {
          await Photos.savePhoto(p);
        } else if (cat === "video") {
          await Photos.saveVideo(p);
        } else if (isLivePhotoFile(Path.basename(p))) {
          const data = await FileManager.readAsData(p);
          if (data) {
            const unpacked = unpackLivePhoto(data);
            if (unpacked) {
              const stamp = String(Date.now());
              const imgTmp = Path.join(FileManager.temporaryDirectory, "lp_" + stamp + "." + unpacked.imageExt);
              const vidTmp = Path.join(FileManager.temporaryDirectory, "lp_" + stamp + ".mov");
              await FileManager.writeAsData(imgTmp, unpacked.imageData);
              await FileManager.writeAsData(vidTmp, unpacked.videoData);
              await Photos.saveLivePhoto({ imagePath: imgTmp, videoPath: vidTmp });
              try {
                FileManager.remove(imgTmp);
              } catch { }
              try {
                FileManager.remove(vidTmp);
              } catch { }
            }
          }
        }
      } catch (e) {
        console.log("导出失败:", p, e);
      }
    }
    setSelectMode(false);
    deselectAll();
    console.log("已导出 " + paths.length + " 个文件到相册");
  };

  // ─ 多选拷贝到剪贴板 ─
  const copySelectedToClipboard = async () => {
    const paths = Array.from(selectedPaths);
    if (paths.length === 0) return;
    await updateCopiedPath(paths[0]);
    setSelectMode(false);
    deselectAll();
  };

  // ─ 新建文件 ─
  const handleCreateFile = async (type: "folder" | "js" | "txt" | "json" | "md", quick?: boolean) => {
    if (!activeDirPath) return;
    const baseDir = activeDirPath;
    const typeNames = { folder: "文件夹", js: "JavaScript文件", txt: "文本文件", json: "JSON文件", md: "Markdown文件" };
    const extensions = { folder: "", js: ".js", txt: ".txt", json: ".json", md: ".md" };

    // 快速模式：直接创建，不弹窗
    let name: string;
    if (quick) {
      name = type === "folder" ? "新建文件夹" : "新建文件";
    } else {
      const result = await Dialog.prompt({
        title: `新建${typeNames[type]}`,
        message: `输入${type === "folder" ? "文件夹" : "文件"}名称`,
        defaultValue: type === "folder" ? "新建文件夹" : "新建文件",
        placeholder: "名称",
        confirmLabel: "创建",
        cancelLabel: "取消",
      });
      if (result == null || !result.trim()) return;
      name = result.trim();
    }

    const ext = extensions[type];
    let targetPath = type === "folder" ? Path.join(baseDir, name) : Path.join(baseDir, name + ext);

    // 同名自动加 _01, _02 ...
    if (await FileManager.exists(targetPath)) {
      let counter = 1;
      while (true) {
        const newName = `${name}_${String(counter).padStart(2, "0")}`;
        targetPath = type === "folder" ? Path.join(baseDir, newName) : Path.join(baseDir, newName + ext);
        if (!(await FileManager.exists(targetPath))) break;
        counter++;
      }
    }

    try {
      if (type === "folder") {
        await FileManager.createDirectory(targetPath, false);
      } else {
        await FileManager.writeAsString(targetPath, "", "utf8");
      }
      // 乐观更新：立即在 UI 中显示新项目
      const newItem: FileInfo = {
        name: Path.basename(targetPath),
        path: targetPath,
        isDirectory: type === "folder",
        isLink: false,
        size: 0,
        creationDate: Date.now(),
        modificationDate: Date.now(),
        extension: type === "folder" ? "" : extensions[type],
        category: type === "folder" ? ("unknown" as any) : getFileCategory(extensions[type]),
        mimeType: "",
        icon: type === "folder" ? "folder.fill" : "doc.text",
        iconColor: type === "folder" ? "systemBlue" : "systemGray",
      };
      withAnimation(Animation.smooth({ duration: 0.35 }), () => {
        setFiles((prev) => [...prev, newItem]);
      });
      onFilesAdded?.([newItem]);
      setHighlightedPath(targetPath);
      setTimeout(() => scrollProxy.current?.scrollTo(targetPath, "center"), 300);
      setTimeout(() => setHighlightedPath(null), 2500);
      // 后台静默刷新，确保数据与磁盘一致
      invalidateDirectoryCache(activeDirPath);
      loadDirectory(true);
    } catch (e) {
      console.log("创建失败:", e);
      // 默认目录不存在时自动创建并重试
      if (baseDir === defaultDir && !(await FileManager.exists(baseDir))) {
        try {
          await FileManager.createDirectory(baseDir, true);
          if (type === "folder") {
            await FileManager.createDirectory(targetPath, false);
          } else {
            await FileManager.writeAsString(targetPath, "", "utf8");
          }
          // 重试成功：同样乐观更新 + 后台刷新
          const retryItem: FileInfo = {
            name: Path.basename(targetPath),
            path: targetPath,
            isDirectory: type === "folder",
            isLink: false,
            size: 0,
            creationDate: Date.now(),
            modificationDate: Date.now(),
            extension: type === "folder" ? "" : extensions[type],
            category: type === "folder" ? ("unknown" as any) : getFileCategory(extensions[type]),
            mimeType: "",
            icon: type === "folder" ? "folder.fill" : "doc.text",
            iconColor: type === "folder" ? "systemBlue" : "systemGray",
          };
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => [...prev, retryItem]);
          });
          onFilesAdded?.([retryItem]);
          setHighlightedPath(targetPath);
          setTimeout(() => scrollProxy.current?.scrollTo(targetPath, "center"), 300);
          setTimeout(() => setHighlightedPath(null), 2500);
          invalidateDirectoryCache(activeDirPath);
          loadDirectory(true);
          return;
        } catch (e2) { }
      }
      await Dialog.alert({
        title: "创建失败",
        message: String(e),
        buttonLabel: "确定",
      });
    }
  };

  /** 新建文件 - 通用：弹窗让用户输入文件名（含扩展名） */
  const handleCreateNewFile = async () => {
    if (!activeDirPath) return;
    const baseDir = activeDirPath;
    const result = await Dialog.prompt({
      title: "新建文件",
      message: "输入文件名（含扩展名，如 hello.js）",
      defaultValue: "新建文件.txt",
      placeholder: "文件名",
      confirmLabel: "创建",
      cancelLabel: "取消",
    });
    if (result == null || !result.trim()) return;
    const name = result.trim();
    let targetPath = Path.join(baseDir, name);
    if (await FileManager.exists(targetPath)) {
      const ext = Path.extname(name);
      const nameBody = Path.basename(name, ext);
      let counter = 1;
      while (true) {
        const newName = `${nameBody}_${String(counter).padStart(2, "0")}${ext}`;
        targetPath = Path.join(baseDir, newName);
        if (!(await FileManager.exists(targetPath))) break;
        counter++;
      }
    }
    try {
      await FileManager.writeAsString(targetPath, "", "utf8");
      // 乐观更新：立即在 UI 中显示新文件
      const ext = Path.extname(targetPath);
      const newItem: FileInfo = {
        name: Path.basename(targetPath),
        path: targetPath,
        isDirectory: false,
        isLink: false,
        size: 0,
        creationDate: Date.now(),
        modificationDate: Date.now(),
        extension: ext,
        category: getFileCategory(ext),
        mimeType: "",
        icon: "doc.text",
        iconColor: "systemGray",
      };
      withAnimation(Animation.smooth({ duration: 0.35 }), () => {
        setFiles((prev) => [...prev, newItem]);
      });
      onFilesAdded?.([newItem]);
      setHighlightedPath(targetPath);
      setTimeout(() => scrollProxy.current?.scrollTo(targetPath, "center"), 300);
      setTimeout(() => setHighlightedPath(null), 2500);
      // 后台静默刷新
      if (activeDirPath) invalidateDirectoryCache(activeDirPath);
      loadDirectory(true);
    } catch (e) {
      console.log("创建失败:", e);
      // 默认目录不存在时自动创建并重试
      if (baseDir === defaultDir && !(await FileManager.exists(baseDir))) {
        try {
          await FileManager.createDirectory(baseDir, true);
          await FileManager.writeAsString(targetPath, "", "utf8");
          // 重试成功：同样乐观更新 + 后台刷新
          const retryExt = Path.extname(targetPath);
          const retryItem: FileInfo = {
            name: Path.basename(targetPath),
            path: targetPath,
            isDirectory: false,
            isLink: false,
            size: 0,
            creationDate: Date.now(),
            modificationDate: Date.now(),
            extension: retryExt,
            category: getFileCategory(retryExt),
            mimeType: "",
            icon: "doc.text",
            iconColor: "systemGray",
          };
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => [...prev, retryItem]);
          });
          onFilesAdded?.([retryItem]);
          setHighlightedPath(targetPath);
          setTimeout(() => scrollProxy.current?.scrollTo(targetPath, "center"), 300);
          setTimeout(() => setHighlightedPath(null), 2500);
          if (activeDirPath) invalidateDirectoryCache(activeDirPath);
          loadDirectory(true);
          return;
        } catch (e2) { }
      }
      await Dialog.alert({ title: "创建失败", message: String(e), buttonLabel: "确定" });
    }
  };

  // ─ 排序助手 ─
  const handleSort = (order: import("../manager/sortFilter").SortOrder) => {
    setSortOrder(order);
    if (isHomePage && settings && onSettingsChange) {
      onSettingsChange({ ...settings, defaultSortOrder: order });
    }
    // 同时持久化到 storage（所有页面生效）
    const stored = readSettings();
    stored.defaultSortOrder = order;
    saveSettings(stored);
    onSortFilterChange?.(order, filterType);
  };

  // ─ 筛选助手 ─
  const handleFilterChange = (type: string) => {
    setFilterType(type);
    if (isHomePage && settings && onSettingsChange) {
      onSettingsChange({ ...settings, defaultFilterType: type });
    }
    const stored = readSettings();
    stored.defaultFilterType = type;
    saveSettings(stored);
    onSortFilterChange?.(sortOrder, type);
  };

  // 搜索栏始终显示

  // ── 导入/相机/实况照片（所有页面可用）──
  let handleOpenSettingsInternal: () => void = () => { };
  let homeNavigationDest = null as any;

  const handleImportFromFiles = async () => {
    try {
      const files = await DocumentPicker.pickFiles({ shouldShowFileExtensions: true });
      if (files && files.length > 0) {
        await ensureDir(activeDirPath);
        const _newPaths: string[] = [];
        for (const filePath of files) {
          const name = Path.basename(filePath);
          const dest = await uniquePath(Path.join(activeDirPath, name));
          await FileManager.copyFile(filePath, dest);
          _newPaths.push(dest);
        }
        // 乐观更新：立即显示导入的文件
        if (_newPaths.length > 0) {
          const _newItems: FileInfo[] = await Promise.all(
            _newPaths.map(async (p) => {
              try {
                return await getFileInfo(p);
              } catch {
                const ext = Path.extname(p);
                return {
                  name: Path.basename(p),
                  path: p,
                  isDirectory: false,
                  isLink: false,
                  size: 0,
                  creationDate: Date.now(),
                  modificationDate: Date.now(),
                  extension: ext,
                  category: getFileCategory(ext),
                  mimeType: getMimeType(ext),
                  icon: "doc.text",
                  iconColor: "systemGray",
                } as FileInfo;
              }
            }),
          );
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => [...prev, ..._newItems]);
          });
          onFilesAdded?.(_newItems);
          setHighlightedPath(_newPaths[0]);
          setTimeout(() => scrollProxy.current?.scrollTo(_newPaths[0], "center"), 300);
          setTimeout(() => setHighlightedPath(null), 2500);
        }
        if (activeDirPath) invalidateDirectoryCache(activeDirPath);
        loadDirectory(true);
      }
    } catch (e) {
      console.log("导入失败:", e);
    }
  };

  const handleImportImages = async () => {
    try {
      const results = await Photos.pick({ filter: PHPickerFilter.images(), limit: 0 });
      if (results && results.length > 0) {
        await ensureDir(activeDirPath);
        const _newPaths: string[] = [];
        for (const result of results) {
          const _p = await importSinglePhotoResult(result, activeDirPath);
          if (_p) _newPaths.push(_p);
        }
        if (_newPaths.length > 0) {
          const _newItems: FileInfo[] = _newPaths.map((_p) => ({
            name: Path.basename(_p),
            path: _p,
            isDirectory: false,
            isLink: false,
            size: 0,
            creationDate: Date.now(),
            modificationDate: Date.now(),
            extension: Path.extname(_p),
            category: getFileCategory(Path.extname(_p)),
            mimeType: "",
            icon: "doc.text",
            iconColor: "systemGray",
          }));
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => [...prev, ..._newItems]);
          });
          onFilesAdded?.(_newItems);
          setHighlightedPath(_newPaths[0]);
          setTimeout(() => scrollProxy.current?.scrollTo(_newPaths[0], "center"), 300);
          setTimeout(() => setHighlightedPath(null), 2500);
        }
        if (activeDirPath) invalidateDirectoryCache(activeDirPath);
        loadDirectory(true);
      }
    } catch (e) {
      console.log("图片导入失败:", e);
    }
  };

  const handleImportLivePhotosOnly = async () => {
    try {
      const results = await Photos.pick({ filter: PHPickerFilter.livePhotos(), limit: 0 });
      if (results && results.length > 0) {
        await ensureDir(activeDirPath);
        const _newPaths: string[] = [];
        for (const result of results) {
          const _p = await importSinglePhotoResult(result, activeDirPath);
          if (_p) _newPaths.push(_p);
        }
        if (_newPaths.length > 0) {
          const _newItems: FileInfo[] = _newPaths.map((_p) => ({
            name: Path.basename(_p),
            path: _p,
            isDirectory: false,
            isLink: false,
            size: 0,
            creationDate: Date.now(),
            modificationDate: Date.now(),
            extension: Path.extname(_p),
            category: getFileCategory(Path.extname(_p)),
            mimeType: "",
            icon: "doc.text",
            iconColor: "systemGray",
          }));
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => [...prev, ..._newItems]);
          });
          onFilesAdded?.(_newItems);
          setHighlightedPath(_newPaths[0]);
          setTimeout(() => scrollProxy.current?.scrollTo(_newPaths[0], "center"), 300);
          setTimeout(() => setHighlightedPath(null), 2500);
        }
        if (activeDirPath) invalidateDirectoryCache(activeDirPath);
        loadDirectory(true);
      }
    } catch (e) {
      console.log("实况照片导入失败:", e);
    }
  };

  const handleImportVideos = async () => {
    try {
      const results = await Photos.pick({ filter: PHPickerFilter.videos(), limit: 0 });
      if (results && results.length > 0) {
        await ensureDir(activeDirPath);
        const _newPaths: string[] = [];
        for (const result of results) {
          const _p = await importSinglePhotoResult(result, activeDirPath);
          if (_p) _newPaths.push(_p);
        }
        if (_newPaths.length > 0) {
          const _newItems: FileInfo[] = _newPaths.map((_p) => ({
            name: Path.basename(_p),
            path: _p,
            isDirectory: false,
            isLink: false,
            size: 0,
            creationDate: Date.now(),
            modificationDate: Date.now(),
            extension: Path.extname(_p),
            category: getFileCategory(Path.extname(_p)),
            mimeType: "",
            icon: "doc.text",
            iconColor: "systemGray",
          }));
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => [...prev, ..._newItems]);
          });
          onFilesAdded?.(_newItems);
          setHighlightedPath(_newPaths[0]);
          setTimeout(() => scrollProxy.current?.scrollTo(_newPaths[0], "center"), 300);
          setTimeout(() => setHighlightedPath(null), 2500);
        }
        if (activeDirPath) invalidateDirectoryCache(activeDirPath);
        loadDirectory(true);
      }
    } catch (e) {
      console.log("视频导入失败:", e);
    }
  };

  const handleTakePhoto = async () => {
    try {
      await ensureDir(activeDirPath);
      const result = await Photos.capture({ mode: "photo", mediaTypes: ["public.image"], allowsEditing: false });
      if (result?.imagePath) {
        const ts = makeTimestamp();
        const ext = Path.extname(result.imagePath).toLowerCase() || ".jpg";
        const dest = await uniquePath(Path.join(activeDirPath, `IMG_${ts}${ext}`));
        await FileManager.copyFile(result.imagePath, dest);
        try {
          await FileManager.remove(result.imagePath);
        } catch { }
        // 乐观更新：立即在 UI 中显示新照片
        const photoExt = ext;
        const photoItem: FileInfo = {
          name: Path.basename(dest),
          path: dest,
          isDirectory: false,
          isLink: false,
          size: 0,
          creationDate: Date.now(),
          modificationDate: Date.now(),
          extension: photoExt,
          category: getFileCategory(photoExt),
          mimeType: "",
          icon: "photo",
          iconColor: "systemGreen",
        };
        withAnimation(Animation.smooth({ duration: 0.35 }), () => {
          setFiles((prev) => [...prev, photoItem]);
        });
        onFilesAdded?.([photoItem]);
        setHighlightedPath(dest);
        setTimeout(() => scrollProxy.current?.scrollTo(dest, "center"), 300);
        setTimeout(() => setHighlightedPath(null), 2500);
        if (activeDirPath) invalidateDirectoryCache(activeDirPath);
        loadDirectory(true);
      }
    } catch (e) {
      console.log("拍照失败:", e);
    }
  };

  const handleRecordVideo = async () => {
    try {
      await ensureDir(activeDirPath);
      const result = await Photos.capture({ mode: "video", mediaTypes: ["public.movie"], allowsEditing: false, videoQuality: "high", videoMaximumDuration: 600 });
      if (result?.mediaPath) {
        const ts = makeTimestamp();
        const ext = Path.extname(result.mediaPath).toLowerCase() || ".mov";
        const dest = await uniquePath(Path.join(activeDirPath, `VID_${ts}${ext}`));
        await FileManager.copyFile(result.mediaPath, dest);
        try {
          await FileManager.remove(result.mediaPath);
        } catch { }
        // 乐观更新：立即在 UI 中显示新视频
        const videoItem: FileInfo = {
          name: Path.basename(dest),
          path: dest,
          isDirectory: false,
          isLink: false,
          size: 0,
          creationDate: Date.now(),
          modificationDate: Date.now(),
          extension: ext,
          category: getFileCategory(ext),
          mimeType: "",
          icon: "video",
          iconColor: "systemPink",
        };
        withAnimation(Animation.smooth({ duration: 0.35 }), () => {
          setFiles((prev) => [...prev, videoItem]);
        });
        onFilesAdded?.([videoItem]);
        setHighlightedPath(dest);
        setTimeout(() => scrollProxy.current?.scrollTo(dest, "center"), 300);
        setTimeout(() => setHighlightedPath(null), 2500);
        if (activeDirPath) invalidateDirectoryCache(activeDirPath);
        loadDirectory(true);
      }
    } catch (e) {
      console.log("录像失败:", e);
    }
  };

  const handleImportFromPhotos = async () => {
    try {
      const results = await Photos.pick({ filter: PHPickerFilter.any([PHPickerFilter.images(), PHPickerFilter.livePhotos(), PHPickerFilter.videos()]), limit: 0 });
      if (results && results.length > 0) {
        await ensureDir(activeDirPath);
        const _newPaths: string[] = [];
        for (const result of results) {
          const _p = await importSinglePhotoResult(result, activeDirPath);
          if (_p) _newPaths.push(_p);
        }
        if (_newPaths.length > 0) {
          const _newItems: FileInfo[] = _newPaths.map((_p) => ({
            name: Path.basename(_p),
            path: _p,
            isDirectory: false,
            isLink: false,
            size: 0,
            creationDate: Date.now(),
            modificationDate: Date.now(),
            extension: Path.extname(_p),
            category: getFileCategory(Path.extname(_p)),
            mimeType: "",
            icon: "doc.text",
            iconColor: "systemGray",
          }));
          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
            setFiles((prev) => [...prev, ..._newItems]);
          });
          onFilesAdded?.(_newItems);
          setHighlightedPath(_newPaths[0]);
          setTimeout(() => scrollProxy.current?.scrollTo(_newPaths[0], "center"), 300);
          setTimeout(() => setHighlightedPath(null), 2500);
        }
        if (activeDirPath) invalidateDirectoryCache(activeDirPath);
        loadDirectory(true);
      }
    } catch (e) {
      console.log("照片导入失败:", e);
    }
  };

  if (isHomePage) {
    handleOpenSettingsInternal = () => {
      Navigation.present({
        element: (
          <SettingsPage
            settings={settings!}
            onUpdateSettings={(updates) => {
              const newSettings = { ...settings, ...updates } as AppSettings;
              saveSettings(newSettings);
              onSettingsChange?.(newSettings);
            }}
          />
        ),
        modalPresentationStyle: "pageSheet",
      });
    };
  }

  const importToolbarItems = (
    <Group>
      <Divider />
      <Button title="从相册导入" systemImage="photo.on.rectangle" action={handleImportFromPhotos} />
      {/*     <Button title="实况照片" systemImage="livephoto" action={handleImportLivePhotosOnly} /> */}
      <Button title="从文件导入" systemImage="doc.badge.plus" action={handleImportFromFiles} />
      <Divider />
      {/* <Menu title="更多导入" systemImage="ellipsis">
        <Button title="图片" systemImage="photo" action={handleImportImages} />
        <Button title="视频" systemImage="video" action={handleImportVideos} />
        <Button title="实况照片" systemImage="livephoto" action={handleImportLivePhotosOnly} />
        <Divider />
        <Button title="拍照" systemImage="camera.viewfinder" action={handleTakePhoto} />
        <Button title="录像" systemImage="video.circle" action={handleRecordVideo} />
      </Menu> */}
    </Group>
  );

  if (isHomePage) {
    homeNavigationDest = (
      <NavigationDestination>
        {(page) => {
          if (page.startsWith("browser:")) {
            return (
              <BrowserRouteView
                key={page + "@navGen" + navGen}
                page={page}
                navigationPath={activeNavPath}
                isHomeScreenHost={isHomeScreenHost}
                onDirChange={onDirChange}
                oppositeDirName={oppositeDirName}
                onCopyToOppositeDir={onCopyToOppositeDir}
                externalCopiedPath={externalCopiedPath}
                onExternalCopy={onExternalCopy}
                onDropCompleted={onDropCompleted}
                onFolderCountChanged={onFolderCountChanged}
                folderCountUpdateRef={folderCountUpdateRef}
                refreshKey={refreshKey}
              />
            );
          }
          return <FileNavigationDest page={page} />;
        }}
      </NavigationDestination>
    );
  }

  // ─ 收藏夹状态 ─
  const [bookmarkRefreshKey, setBookmarkRefreshKey] = useState(0);
  const allBookmarks = useMemo(() => getAllBookmarks(), [bookmarkRefreshKey, bookmarks]);

  // 订阅全局书签变更：任意分栏/页面添加删除收藏后，这里都实时刷新
  useEffect(() => {
    return onBookmarksChanged(() => {
      setBookmarkRefreshKey((k) => k + 1);
    });
  }, []);
  const handleManageBookmarks = async () => {
    await Navigation.present({
      element: (
        <ManagedBookmarksSheet
          showFolderItemCounts={showFolderItemCounts}
          onBookmarksChanged={() => {
            setBookmarkRefreshKey((key) => key + 1);
            void refreshDirectory();
          }}
          onSettingsChange={onSettingsChange}
        />
      ),
      modalPresentationStyle: "pageSheet",
    });
    setBookmarkRefreshKey((key) => key + 1);
  };

  // ─ 系统目录 ─
  interface SystemDirEntry {
    name: string;
    path: string;
    icon: string;
    tag: string;
  }
  const [systemDirEntries, setSystemDirEntries] = useState<SystemDirEntry[]>([]);
  useEffect(() => {
    (async () => {
      const defs = buildSystemDirDefs();
      const entries: SystemDirEntry[] = [];
      for (const def of defs) {
        try {
          const path = def.getPath();
          if (path) {
            entries.push({ name: def.name, path, icon: def.icon, tag: def.tag });
          }
        } catch { }
      }
      setSystemDirEntries(entries);
    })();
  }, []);
  // 路径显示：根目录自定义名称 + 相对路径
  const displayPath = useMemo(() => {
    if (!activeDirPath) return "文件列表";
    const root = rootPath || activeDirPath;
    // 首页模式优先使用书签名称（支持重命名后显示实际名称）
    const bookmarkName =
      isHomePage && settings?.homeDirectoryBookmarkName
        ? allBookmarks.find((b) => b.bookmarkId === settings.homeDirectoryBookmarkName || b.name === settings.homeDirectoryBookmarkName)?.name || settings.homeDirectoryBookmarkName
        : null;
    const effectiveRootName = bookmarkName || rootName || dirName || Path.basename(activeDirPath);
    if (activeDirPath === root) {
      return effectiveRootName;
    }
    // 严格前缀匹配后剥离；replace(root, "") 会替换第一个出现位置，
    // root="/a/b"、active="/a/bc/d" 时会错误地得到 "c/d"。
    const relativePath = activeDirPath.startsWith(root)
      ? activeDirPath.slice(root.length).replace(/^\//, "")
      : "";
    return relativePath ? `${effectiveRootName}/${relativePath}` : effectiveRootName;
  }, [activeDirPath, dirName, rootPath, rootName, settings?.homeDirectoryBookmarkName, isHomePage, allBookmarks]);
  const titleDisplayPath = useMemo(() => tailDisplayPath(displayPath), [displayPath]);

  // ─ 首页标题点击：修改首页路径（仅在首页可用） ─
  const handlePickDirectory = async () => {
    const bookmark = await addDirectoryBookmark();
    if (bookmark) {
      if (isHomePage && settings && onSettingsChange) {
        const newSettings = { ...settings, homeDirectoryBookmarkName: bookmark.bookmarkId || bookmark.name, homeCurrentPath: bookmark.path };
        saveSettings(newSettings);
        onSettingsChange(newSettings);
      } else if (activeNavPath) {
        activeNavPath.setValue([...activeNavPath.value, "browser:" + bookmark.path]);
      }
    }
  };

  const handleInputPath = async () => {
    const input = await Dialog.prompt({
      title: "输入文件路径",
      message: "请输入要跳转的目录路径",
      defaultValue: activeDirPath || defaultDir,
      placeholder: "/var/mobile/...",
      cancelLabel: "取消",
      confirmLabel: "确定",
    });
    if (input != null && input.trim()) {
      const trimmed = input.trim();
      const exists = await FileManager.exists(trimmed);
      if (!exists) {
        const create = await Dialog.confirm({
          title: "路径不存在",
          message: "该路径不存在，是否创建？",
          cancelLabel: "取消",
          confirmLabel: "创建",
        });
        if (!create) return;
        try {
          await FileManager.createDirectory(trimmed, true);
        } catch (e) {
          await Dialog.alert({ title: "创建失败", message: String(e), buttonLabel: "确定" });
          return;
        }
      }
      if (isHomePage && settings && onSettingsChange) {
        const newSettings = { ...settings, homeCurrentPath: trimmed, homeDirectoryBookmarkName: null };
        saveSettings(newSettings);
        onSettingsChange(newSettings);
      } else if (activeNavPath) {
        activeNavPath.setValue([...activeNavPath.value, "browser:" + trimmed]);
      }
    }
  };


  const handleCopyPath = async () => {
    if (!activeDirPath) return;
    await Pasteboard.setString(activeDirPath);
    showToast("已复制路径");
  };


  // ─ 收藏夹操作 ─
  const handleAddBookmark = async () => {
    const bookmark = await addDirectoryBookmark();
    if (bookmark) {
      setBookmarkRefreshKey((k) => k + 1);
      showToast("已添加收藏");
    }
  };

  const handleNavigateToBookmark = async (bookmark: Bookmark) => {
    // 优先通过持久书签解析当前可访问路径（软件更新/容器 UUID 变化后 bookmarkId 仍可能可解析）
    let path = bookmark.path;
    if (bookmark.bookmarkId) {
      const resolved = resolveBookmarkPath(bookmark.bookmarkId);
      if (resolved) path = resolved;
    }
    // 仅 exists 不够：路径存在但失去访问权限（如软件更新后书签失效）时 exists 仍可能返回 true，
    // 必须真正读一次目录才能确认可访问。
    let accessible = false;
    try {
      accessible = (await FileManager.exists(path)) && (await FileManager.readDirectory(path)) !== null;
    } catch {
      accessible = false;
    }
    if (!accessible) {
      // 书签失效（软件更新导致）→ 用 ToastOverlay 弹窗提醒重新挂载
      showRemountWarning(bookmark.name);
      removeBookmark(bookmark.name);
      setBookmarkRefreshKey((k) => k + 1);
      return;
    }
    if (isHomePage && settings && onSettingsChange) {
      const newSettings = {
        ...settings,
        homeCurrentPath: path,
        homeDirectoryBookmarkName: bookmark.bookmarkId || bookmark.name,
      };
      saveSettings(newSettings);
      onSettingsChange(newSettings);
    } else if (activeNavPath) {
      activeNavPath.setValue([...activeNavPath.value, "browser:" + path]);
    }
  };



  // 监听全局搜索关闭事件
  useEffect(() => {
    return onSearchStateChange((show) => {
      if (!show) {
        withAnimation(Animation.smooth({ duration: 0.35 }), () => {
          setSearchQuery("");
          setDeepSearchResults([]);
        });
      }
    });
  }, []);

  const finishDroppedPaths = async (createdPaths: string[]) => {
    // 乐观更新：立即显示新增文件，不等 refreshDirectory 慢加载
    if (createdPaths.length > 0 && addFilesRef?.current) {
      const newFiles = createdPaths.map(
        (p) =>
          ({
            name: Path.basename(p),
            path: p,
            isDirectory: false,
            isLink: false,
            size: 0,
            creationDate: Date.now(),
            modificationDate: Date.now(),
            extension: Path.extname(Path.basename(p)),
            category: getFileCategory(Path.extname(Path.basename(p))),
            mimeType: "",
            icon: "doc.text",
            iconColor: "systemGray",
          }) as FileInfo,
      );
      addFilesRef.current(newFiles);
      onFilesAdded?.(newFiles);
    }
    refreshDirectory();
    try {
      const children = await countDirectoryItems(effectiveDropDir);
      applyFolderCountUpdate(effectiveDropDir, children);
    } catch { }
    onDropCompleted?.();
  };

  const handleDropToCurrentDirectory = (info: DropInfo) => {
    if (!effectiveDropDir) return false;
    handleDropToDirectory(info, effectiveDropDir, () => { })
      .then(finishDroppedPaths)
      .catch(() => {
        refreshDirectory();
        onDropCompleted?.();
      });
    return true;
  };

  const currentDirectoryDrop = {
    types: DROP_ACCEPTED_TYPES,
    validateDrop: (info: DropInfo) => info.hasItemsConforming(DROP_ACCEPTED_TYPES),
    performDrop: handleDropToCurrentDirectory,
  };

  const directoryBlankDropZone = (
    <Button action={() => { }} listRowSeparator={{ visibility: "hidden", edges: "all" }} listRowBackground={<Rectangle fill="clear" />} onDrop={currentDirectoryDrop}>
      <VStack frame={{ maxWidth: "infinity", minHeight: 1 }} contentShape="rect">
        <Spacer minLength={1} />
      </VStack>
    </Button>
  );

  const titleMenuActionsRef = useRef<{
    handleInputPath: () => void;
    handleAddBookmark: () => void;
    handleManageBookmarks: () => void;
    handleCopyPath: () => void;
    handleNavigateToBookmark: (bm: Bookmark) => void;
    handleSystemDirSelect: (entry: SystemDirEntry) => void;
  } | null>(null);
  titleMenuActionsRef.current = {
    handleInputPath,
    handleAddBookmark,
    handleManageBookmarks,
    handleCopyPath,
    handleNavigateToBookmark,
    handleSystemDirSelect: async (entry: SystemDirEntry) => {
      const exists = await FileManager.exists(entry.path);
      if (!exists) {
        await Dialog.alert({ title: "提示", message: "目录不存在：" + entry.path, buttonLabel: "确定" });
        return;
      }
      if (isHomePage && settings && onSettingsChange) {
        const newSettings = { ...settings, homeCurrentPath: entry.path, homeDirectoryBookmarkName: null };
        saveSettings(newSettings);
        onSettingsChange(newSettings);
      } else if (activeNavPath) {
        activeNavPath.setValue([...activeNavPath.value, "browser:" + entry.path]);
      }
    },
  };
  const titleMenu = useMemo(
    () => (
      <Menu
        label={
          <Text font="headline" lineLimit={1}>
            {titleDisplayPath}
          </Text>
        }
      >
        <ControlGroup>
          <Button title="前往目录" systemImage="pencil.and.outline" action={() => titleMenuActionsRef.current?.handleInputPath()} />
          <Button title="添加收藏" systemImage="star" action={() => titleMenuActionsRef.current?.handleAddBookmark()} />
          <Button title="管理收藏" systemImage="folder.badge.gearshape" action={() => titleMenuActionsRef.current?.handleManageBookmarks()} />
        </ControlGroup>
        <Button title="复制当前路径" systemImage="doc.on.clipboard" action={() => titleMenuActionsRef.current?.handleCopyPath()} />
        <Divider />
        {systemDirEntries.length > 0 ? (
          <>
            <Divider />
            {systemDirEntries.map((entry) => (
              <Button
                key={entry.name}
                title={entry.name}
                systemImage={entry.icon}
                action={() => titleMenuActionsRef.current?.handleSystemDirSelect(entry)}
              />
            ))}
          </>
        ) : (
          <EmptyView />
        )}
        {allBookmarks.length > 0 ? (
          <>
            <Divider />
            {allBookmarks.map((bm) => (
              <Button key={bm.bookmarkId || bm.path} title={bm.name} systemImage="folder" action={() => titleMenuActionsRef.current?.handleNavigateToBookmark(bm)} />
            ))}
          </>
        ) : (
          <EmptyView />
        )}
      </Menu>
    ),
    [titleDisplayPath, systemDirEntries, allBookmarks],
  );

  const mainContent = (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }} onDrop={currentDirectoryDrop}>
      <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
        <ScrollViewReader>
          {(proxy) => {
            scrollProxy.current = proxy;
            return (
              <List
                listStyle="plain"
                navigationTitle={titleDisplayPath}
                navigationBarTitleDisplayMode="inline"
                navigationDestination={isHomePage ? homeNavigationDest : navigationDestination}
                onDrop={currentDirectoryDrop}
                searchable={{
                  value: searchQuery,
                  onChanged: setSearchQuery,
                  placement: "navigationBarDrawer",
                  prompt: "搜索当前目录...",
                  presented: {
                    value: showSearch,
                    onChanged: (v: boolean) => {
                      setShowSearch(v);
                      if (!v) {
                        setSearchQuery("");
                        setDeepSearchResults([]);
                      }
                    },
                  },
                }}
                toolbar={
                  <Toolbar>
                    <ToolbarItem placement="principal">{titleMenu}</ToolbarItem>
                    {toolbarLeadingItems ?? <EmptyView />}
                    {toolbarTrailingItems ?? <EmptyView />}
                    <ToolbarItem placement="topBarTrailing">
                      <ToolbarMenu
                        key={"tm-" + (effectiveCopiedPath ? "1" : "0")}
                        selectMode={{
                          enabled: true,
                          isSelectMode: selectMode,
                          onToggleSelectMode: () => {
                            if (selectMode) {
                              setSelectMode(false);
                              deselectAll();
                            } else setSelectMode(true);
                          },
                          onSelectAll: selectAll,
                          onDeselectAll: deselectAll,
                          selectedCount: selectedPaths.size,
                          onDeleteSelected: deleteSelected,
                          onMoveSelected: moveSelectedToBookmark,
                          onCopyPaths: copySelectedPaths,
                          onExportPhotos: exportSelectedPhotos,
                          onCopyToClipboard: copySelectedToClipboard,
                          onCompressSelected: compressSelected,
                        }}
                        sort={{
                          sortOrder: sortOrder,
                          onSortChange: handleSort,
                        }}
                        filter={{
                          filterType: filterType,
                          onFilterChange: handleFilterChange,
                        }}
                        extraItems={
                          <Group key={"extra-" + (effectiveCopiedPath ? "1" : "0") + "-s" + serverTick}>
                            {hasHttpServerEntry ? (
                              <>
                                <Button
                                  title="启动 HTTP Server"
                                  systemImage="network"
                                  action={async () => {
                                    if (!activeDirPath) return;
                                    const hasEntry = (await FileManager.exists(Path.join(activeDirPath, "index.html"))) || (await FileManager.exists(Path.join(activeDirPath, "index.htm")));
                                    if (!hasEntry) {
                                      showToast("当前目录没有 index.html 入口");
                                      return;
                                    }
                                    try {
                                      const actualUrl = await startLocalHttpServer(activeDirPath);
                                      setServerTick((t) => t + 1);
                                      console.log("[HTTP Preview] 预览:", actualUrl);
                                      await Pasteboard.setString(actualUrl);
                                      await Navigation.present({
                                        element: <WebPreviewPage url={actualUrl} />,
                                        modalPresentationStyle: "pageSheet",
                                      });
                                    } catch (e) {
                                      console.log("启动 HTTP Server 或打开预览失败:", e);
                                      showToast("HTTP Server 启动或预览打开失败");
                                    }
                                  }}
                                />
                                <Divider />
                              </>
                            ) : (
                              <EmptyView />
                            )}
                            {activeServers.length > 0 ? (
                              <>
                                <Divider />
                                {activeServers.map((srv) => (
                                  <Button
                                    key={srv.directory}
                                    title={`关闭 ${srv.url} · ${Path.basename(srv.directory)}`}
                                    systemImage="xmark.circle"
                                    role="destructive"
                                    action={async () => {
                                      await stopServer(srv.directory);
                                      setServerTick((t) => t + 1);
                                      showToast(`已停止 ${Path.basename(srv.directory)}`);
                                    }}
                                  />
                                ))}
                              </>
                            ) : (
                              <EmptyView />
                            )}
                            {effectiveCopiedPath ? (
                              <>
                                <Divider />
                                <Button
                                  title="粘贴到当前目录"
                                  systemImage="arrow.right.doc.on.clipboard"
                                  action={async () => {
                                    try {
                                      if (!effectiveCopiedPath) return;
                                      const baseName = Path.basename(effectiveCopiedPath);
                                      const ext = Path.extname(baseName);
                                      const nameBody = Path.basename(baseName, ext);
                                      let destPath = Path.join(activeDirPath || "", baseName);
                                      // 如果目标已存在则加数字后缀
                                      let counter = 1;
                                      while (await FileManager.exists(destPath)) {
                                        destPath = Path.join(activeDirPath || "", `${nameBody}_${counter}${ext}`);
                                        counter++;
                                      }
                                      await FileManager.copyFile(effectiveCopiedPath, destPath);
                                      await updateCopiedPath(null);

                                      // 乐观更新：立即在 UI 中显示粘贴的项目
                                      (async () => {
                                        if (await FileManager.exists(destPath)) {
                                          const isDir = await FileManager.isDirectory(destPath);
                                          const destExt = Path.extname(destPath);
                                          const newFile: FileInfo = {
                                            name: Path.basename(destPath),
                                            path: destPath,
                                            isDirectory: isDir,
                                            isLink: false,
                                            size: 0,
                                            creationDate: Date.now(),
                                            modificationDate: Date.now(),
                                            extension: isDir ? "" : destExt,
                                            category: isDir ? ("unknown" as any) : getFileCategory(destExt),
                                            mimeType: "",
                                            icon: isDir ? "folder.fill" : "doc.text",
                                            iconColor: isDir ? "systemBlue" : "systemGray",
                                          };
                                          withAnimation(Animation.smooth({ duration: 0.35 }), () => {
                                            setFiles((prev) => [...prev, newFile]);
                                          });
                                          onFilesAdded?.([newFile]);
                                          setHighlightedPath(destPath);
                                          setTimeout(() => scrollProxy.current?.scrollTo(destPath, "center"), 300);
                                          setTimeout(() => setHighlightedPath(null), 2500);
                                          // 如果是文件夹，立即更新文件夹计数
                                          if (isDir) {
                                            try {
                                              const children = await countDirectoryItems(destPath);
                                              applyFolderCountUpdate(destPath, children);
                                            } catch (e) {
                                              console.log("更新文件夹计数失败:", e);
                                            }
                                          }
                                        }
                                      })();
                                      // 后台静默刷新，确保数据与磁盘一致
                                      if (activeDirPath) invalidateDirectoryCache(activeDirPath);
                                      refreshDirectory();
                                    } catch (e) {
                                      console.log("粘贴失败:", e);
                                      // 不清除复制来源，用户可在权限/iCloud 等问题解决后直接重试。
                                      showToast("粘贴失败，请重试");
                                    }
                                  }}
                                />
                                <Button
                                  title="取消复制"
                                  systemImage="xmark"
                                  action={async () => {
                                    await updateCopiedPath(null);
                                  }}
                                />
                                <Divider />
                              </>
                            ) : (
                              <EmptyView />
                            )}
                          </Group>
                        }
                        otherItems={
                          <Group>

                            {/* Menu 内使用 Group 保留各项独立点击区域；ControlGroup 会将相邻按钮合并，可能误触发首项动作。 */}
                            <Group>
                              <Button title="新建文件" systemImage="doc.text" action={handleCreateNewFile} />
                              <Button title="新建文件夹" systemImage="folder.badge.plus" action={() => handleCreateFile("folder")} />
                              <Button title="新建 JS" systemImage="chevron.left.forwardslash.chevron.right" action={() => handleCreateFile("js", true)} />
                              {isHomePage ? (
                                importToolbarItems
                              ) : (
                                <>
                                  {importToolbarItems}
                                  {toolbarOtherItems ?? <EmptyView />}
                                </>
                              )}

                            </Group>
                          </Group>
                        }
                        bottomItem={
                          <Button
                            title="设置"
                            systemImage="gearshape"
                            action={
                              isHomePage
                                ? handleOpenSettingsInternal
                                : settings && onSettingsChange
                                  ? () => {
                                    Navigation.present({
                                      element: (
                                        <SettingsPage
                                          settings={settings!}
                                          onUpdateSettings={(updates) => {
                                            const newSettings = { ...settings, ...updates } as AppSettings;
                                            saveSettings(newSettings);
                                            onSettingsChange(newSettings);
                                          }}
                                        />
                                      ),
                                      modalPresentationStyle: "pageSheet",
                                    });
                                  }
                                  : onOpenSettings || (() => { })
                            }
                          />
                        }
                      />
                    </ToolbarItem>
                  </Toolbar>
                }
              >
                {showSearch && activeDirPath ? (
                  <SearchPanel
                    searchQuery={searchQuery}
                    dirPath={activeDirPath}
                    onResultsChange={setDeepSearchResults}
                    navPath={activeNavPath}
                    resultTrailingActions={(result) => [
                      {
                        title: "简介",
                        systemImage: "info.circle",
                        action: () => {
                          const fileInfo: FileInfo = {
                            path: result.path,
                            name: result.name,
                            size: result.size,
                            modificationDate: result.modificationDate,
                            isDirectory: result.isDirectory,
                            extension: Path.extname(result.name),
                            category: result.category as FileInfo["category"],
                            isLink: false,
                            mimeType: "",
                            icon: result.icon,
                            iconColor: result.iconColor as FileInfo["iconColor"],
                            creationDate: 0,
                          };
                          Navigation.present({ element: <FileInfoDialog file={fileInfo} />, modalPresentationStyle: "pageSheet" });
                        },
                      },
                    ]}
                    resultContextMenuItems={(result) => [
                      {
                        title: "重命名",
                        systemImage: "pencil",
                        action: async () => {
                          const newName = await renameWithPrompt(result.name);
                          if (newName) {
                            try {
                              const newPath = Path.join(Path.dirname(result.path), newName);
                              await FileManager.rename(result.path, newPath);
                              refreshDirectory();
                            } catch (e) {
                              console.log("重命名失败:", e);
                            }
                          }
                        },
                      },
                      {
                        title: "复制",
                        systemImage: "doc.on.doc",
                        action: async () => {
                          await updateCopiedPath(result.path);
                          showToast("已复制文件，前往目标目录后可粘贴");
                        },
                      },
                      {
                        title: "简介",
                        systemImage: "info.circle",
                        action: () => {
                          const fileInfo = {
                            path: result.path,
                            name: result.name,
                            size: result.size,
                            modificationDate: result.modificationDate,
                            isDirectory: result.isDirectory,
                            extension: Path.extname(result.name),
                            category: result.category,
                            isLink: false,
                            mimeType: "",
                            icon: result.icon,
                            iconColor: result.iconColor,
                            creationDate: 0,
                          };
                          Navigation.present({ element: <FileInfoDialog file={fileInfo as FileInfo} />, modalPresentationStyle: "pageSheet" });
                        },
                      },
                      {
                        title: "删除",
                        systemImage: "trash",
                        role: "destructive",
                        action: async () => {
                          try {
                            await FileManager.remove(result.path);
                            refreshDirectory();
                          } catch (e) {
                            console.log("删除失败:", e);
                          }
                        },
                      },
                    ]}
                    onResultTap={async (result) => {
                      // 检查文件是否存在
                      const exists = await FileManager.exists(result.path);
                      if (!exists) {
                        showToast("文件已不存在");
                        return;
                      }
                      // 非目录文件：检查是否已被更新（修改时间不同说明索引已过期）
                      if (!result.isDirectory) {
                        try {
                          const stat = await FileManager.stat(result.path);
                          if (stat.modificationDate !== result.modificationDate) {
                            showToast("文件已更新，请重新索引");
                            return;
                          }
                        } catch {
                          showToast("文件不存在");
                          return;
                        }
                      }
                      if (result.isDirectory && activeNavPath) {
                        activeNavPath.setValue([...activeNavPath.value, "browser:" + result.path]);
                      } else if (!result.isDirectory) {
                        const prefix = await resolveOpenerForFile(result.path, result.category);
                        if (prefix) {
                          // editor 类型且有匹配行：直接 present 编辑器并跳转行号
                          if (prefix === "editor:") {
                            const line = result.matchedLine || (result.allMatches && result.allMatches.length > 0 ? result.allMatches[0].line : undefined);
                            /* if (isHomeScreenHost) {
                              await Navigation.present({
                                element: <EditorPage path={result.path} mode="present" scrollToLine={line} />,
                                modalPresentationStyle: "pageSheet",
                              });
                            } else */ if (activeNavPath) {
                              activeNavPath.setValue([...activeNavPath.value, prefix + result.path + (line ? "::L" + line : "")]);
                            }
                          } else if (prefix === "archive:") {
                            // 深度搜索打开压缩包始终使用 pageSheet；不走 NavigationStack 路由，
                            // 以保持与目录列表中“查看压缩文件”一致的弹窗体验。
                            await Navigation.present({
                              element: <ArchiveBrowserPage filePath={result.path} />,
                              modalPresentationStyle: "pageSheet",
                            });
                          } else if (prefix === "share:") {
                            await shareFilePath(result.path, result.name);
                          } else if (prefix === "pdf:") {
                            await QuickLook.previewURLs([result.path], true);
                          } else if (prefix === "webpage:") {
                            const wv = new WebViewController();
                            await wv.loadFile(result.path);
                            await wv.present({ fullscreen: true, navigationTitle: result.name });
                            wv.dispose();
                          } else if (activeNavPath) {
                            activeNavPath.setValue([...activeNavPath.value, prefix + result.path]);
                          }
                        }
                      }
                    }}
                  />
                ) : (
                  <EmptyView />
                )}

                {/* 文件列表 - 深度搜索结果显示时隐藏 */}
                {deepSearchResults.length === 0 ? (
                  visibleFiles.length === 0 ? (
                    <Section>{directoryBlankDropZone}</Section>
                  ) : (
                    <Section>
                      {visibleFiles.map((file, fileIdx) => (
                        <Group key={file.path}>
                          <FileRowLink
                            key={file.path}
                            file={file}
                            onRefresh={refreshDirectory}
                            onDeleteFile={handleDeleteFile}
                            onRequestDelete={requestFileDelete}
                            selectMode={selectMode}
                            isSelected={selectedPaths.has(file.path)}
                            onToggleSelect={toggleSelect}
                            rootPath={rootPath || activeDirPath}
                            rootName={rootName || dirName}
                            navPath={activeNavPath}
                            hideTopSeparator={fileIdx === 0}
                            folderCountStore={folderCountStore}
                            onCopyPath={handleRowCopyPath}
                            isHighlighted={file.path === highlightedPath}
                            copyToDirTitle={oppositeDirName}
                            onCopyToDir={onCopyToOppositeDir}
                            dirPath={effectiveDropDir}
                            onDropCompleted={onDropCompleted}
                            onFolderCountChanged={applyFolderCountUpdate}
                            isHomeScreenHost={isHomeScreenHost}
                          />
                          {hasMore && fileIdx === Math.max(0, visibleFiles.length - 26) ? (
                            <HStack
                              frame={{ maxWidth: "infinity", height: 1 }}
                              listRowBackground={<Rectangle fill="clear" />}
                              listRowSeparator={{ visibility: "hidden", edges: "all" }}
                              onAppear={() => preloadNextPage(visibleFiles.length)}
                            >
                              <EmptyView />
                            </HStack>
                          ) : (
                            <EmptyView />
                          )}
                        </Group>
                      ))}
                      {hasMore ? <Button title="加载更多" action={() => preloadNextPage(visibleFiles.length)} /> : <EmptyView />}
                    </Section>
                  )
                ) : (
                  <EmptyView />
                )}

                {deepSearchResults.length === 0 ? (
                  <Section>
                    <HStack spacing={12} alignment="center" listRowBackground={<></>} listRowSeparator={{ visibility: "hidden", edges: "all" }} padding={{ top: 20, bottom: 20 }}>
                      <Spacer />
                      <Text foregroundStyle="tertiaryLabel" font={10} monospaced>
                        文件夹 {folderCount} 文件 {fileCount} 大小 {fmtSize(totalSize)}
                      </Text>
                      <Spacer />
                    </HStack>
                  </Section>
                ) : (
                  <EmptyView />
                )}
              </List>
            );
          }}
        </ScrollViewReader>
      </VStack>
      <EmptyView />
    </ZStack>
  );

  // 计算当前目录路径（处理子文件夹导航：取导航栈中最新的 browser: 路径）
  let effectiveDropDir = activeDirPath || "";
  if (isHomePage && activeHomeNavPath.value.length > 0) {
    for (let i = activeHomeNavPath.value.length - 1; i >= 0; i--) {
      const p = activeHomeNavPath.value[i];
      if (p.startsWith("browser:")) {
        effectiveDropDir = p.slice(8);
        break;
      }
    }
  }

  return isHomePage && !outerNavPath ? (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <NavigationStack
        path={activeHomeNavPath}
        onDrop={{
          types: DROP_ACCEPTED_TYPES,
          validateDrop: (info) => {
            const ok = info.hasItemsConforming(DROP_ACCEPTED_TYPES);
            console.log("NavStack validateDrop:", ok, "dir:", effectiveDropDir);
            return ok;
          },
          dropEntered: () => {
            console.log("NavStack dropEntered, dir:", effectiveDropDir);
          },
          performDrop: (info) => {
            // 从 NavigationStack 路径中获取当前真实目录
            const pathArray = Array.isArray(activeHomeNavPath?.value) ? activeHomeNavPath.value : activeHomeNavPath?.value ? [activeHomeNavPath.value] : [];
            let destDir = effectiveDropDir;
            for (let i = pathArray.length - 1; i >= 0; i--) {
              const p = typeof pathArray[i] === "string" ? pathArray[i] : "";
              if (p.startsWith("browser:")) {
                const extracted = p.slice(8);
                const sepIdx = extracted.indexOf("::");
                destDir = sepIdx !== -1 ? extracted.slice(0, sepIdx) : extracted;
                break;
              }
            }
            console.log("NavStack performDrop, dir:", destDir);
            if (!destDir) return false;
            handleDropToDirectory(info, destDir, () => { })
              .then(async (createdPaths) => {
                invalidateDirectoryCache(destDir);
                // 乐观更新：立即显示新增文件
                if (createdPaths.length > 0 && addFilesRef?.current) {
                  const newFiles = createdPaths.map(
                    (p) =>
                      ({
                        name: Path.basename(p),
                        path: p,
                        isDirectory: false,
                        isLink: false,
                        size: 0,
                        creationDate: Date.now(),
                        modificationDate: Date.now(),
                        extension: Path.extname(Path.basename(p)),
                        category: getFileCategory(Path.extname(Path.basename(p))),
                        mimeType: "",
                        icon: "doc.text",
                        iconColor: "systemGray",
                      }) as FileInfo,
                  );
                  addFilesRef.current(newFiles);
                  onFilesAdded?.(newFiles);
                }
                // 如果导航到了子目录，强制 remount 子视图刷新
                if (pathArray.length > 1) {
                  setNavGen((g) => g + 1);
                }
                refreshDirectory();
                try {
                  const children = await countDirectoryItems(destDir);
                  applyFolderCountUpdate(destDir, children);
                } catch { }
                onDropCompleted?.();
              })
              .catch(() => {
                refreshDirectory();
                onDropCompleted?.();
              });
            return true;
          },
        }}
      >
        {mainContent}
      </NavigationStack>
    </ZStack>
  ) : (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>{mainContent}</ZStack>
    </ZStack>
  );
}

function BrowserRouteView({
  page,
  navigationPath,
  isHomeScreenHost,
  ...browserProps
}: {
  page: string;
  navigationPath: any;
  isHomeScreenHost?: boolean;
  [key: string]: any;
}) {
  let dirPath = page.slice(8);
  let highlightFile: string | undefined;
  const separatorIndex = dirPath.indexOf("::");
  if (separatorIndex !== -1) {
    highlightFile = decodeURIComponent(dirPath.slice(separatorIndex + 2));
    dirPath = dirPath.slice(0, separatorIndex);
  }

  // 判断当前实例是否是导航栈中最后一项（即当前显示的）
  // 只有最后一项应该轮询，其他项应该停止轮询以节省 CPU
  const navArray = navigationPath?.value && Array.isArray(navigationPath.value) ? navigationPath.value : [];
  const isFocused = navArray.length > 0 && navArray[navArray.length - 1] === page;

  return (
    <GeneralBrowser
      key={page}
      {...browserProps}
      dirPath={dirPath}
      dirName={Path.basename(dirPath)}
      rootPath={dirPath}
      navPath={navigationPath}
      highlightFile={highlightFile}
      isHomePage={false}
      isHomeScreenHost={isHomeScreenHost}
      isFocused={isFocused}
    />
  );
}

export { GeneralBrowser, BrowserRouteView };
