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
  Image,
  ScrollViewReader,
  useState,
  useEffect,
  useMemo,
  useRef,
  Path,
  useObservable,
  Group,
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
  fmtDate,
  getFileCategory,
  getFileInfo,
  FileInfo,
  listDirectory,
  countDirectoryItems,
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
  shareFilePath,
  buildSystemDirDefs,
} from "../manager/utils";
import { FileRowContent } from "./FileRowContent";
import { DeepSearchResult } from "./SearchPanel";
import { SearchPanel } from "./SearchPanel";
import { onSearchStateChange } from "../manager/SearchState";
import { FileNavigationDest } from "./MediaViewer";
import { ToolbarMenu } from "./ToolbarMenu";
import { FileListItem, FileInfoDialog } from "./FileListItem";
import { filterFiles, sortFilesByOrder, DEFAULT_SORT_ORDER, DEFAULT_FILTER_TYPE } from "../manager/sortFilter";
import { isLivePhotoFile, unpackLivePhoto } from "../manager/LivePhotoPacker";
import { resolveOpenerForFile } from "./DefaultOpenerPicker";
import { getDefaultOpener, setDefaultOpener, OPENER_OPTIONS } from "../manager/DefaultOpener";
import { AppSettings, saveSettings, readSettings } from "../manager/Settings";
import { SettingsPage } from "./SettingsPage";
import { Bookmark, getAllBookmarks, addDirectoryBookmark, removeBookmark, renameBookmark } from "../manager/BookmarkManager";
import { ensureDir, makeTimestamp, importSinglePhotoResult } from "../manager/importHelpers";
import { DROP_ACCEPTED_TYPES, handleDropToDirectory } from "../manager/dropHandler";
import { makeDragConfig } from "./FileListItem";
import { showToast } from "../manager/ToastManager";

// 剪贴板路径文件（用文件持久化，跨 tab/子目录保留）
const _readClipPath = readClipboardPath;
const _writeClipPath = writeClipboardPath;

const DIRECTORY_POLL_INTERVAL_MS = 999;
const DIRECTORY_POLL_FORCE_FULL_EVERY = 10;

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
  selectMode,
  isSelected,
  onToggleSelect,
  navPath,
  hideTopSeparator,
  folderCounts,
  onCopyPath,
  isHighlighted,
  copyToDirTitle,
  onCopyToDir,
  dirPath,
  onDropCompleted,
  onFolderCountChanged,
}: {
  file: FileInfo;
  onRefresh: () => void;
  onDeleteFile?: (path: string) => void;
  selectMode?: boolean;
  isSelected?: boolean;
  onToggleSelect?: () => void;
  rootPath?: string;
  rootName?: string;
  navPath?: any;
  hideTopSeparator?: boolean;
  folderCounts?: Map<string, number>;
  onCopyPath?: (path: string) => void;
  isHighlighted?: boolean;
  copyToDirTitle?: string;
  onCopyToDir?: (path: string) => void;
  dirPath?: string;
  onDropCompleted?: () => void;
  onFolderCountChanged?: (folderPath: string, count: number) => void;
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

  const handleDelete = async () => {
    try {
      await FileManager.remove(file.path);
      withAnimation(Animation.smooth({ duration: 0.35 }), () => {
        if (onDeleteFile) {
          onDeleteFile(file.path);
        } else {
          onRefresh();
        }
      });
    } catch (e) {
      console.log("删除失败:", e);
    }
  };

  const handleShare = async () => {
    await shareFilePath(file.path, file.name);
  };

  // ─ 选择模式 ─
  if (selectMode) {
    return (
      <FileListItem
        file={file}
        hideTopSeparator={hideTopSeparator}
        selectMode={{
          isSelected: isSelected || false,
          onToggle: onToggleSelect || (() => {}),
        }}
      />
    );
  }

  // ─ 普通模式：使用 FileListItem 实现 ─
  const cat = getFileCategory(file.extension);
  const defaultOpener = file.isDirectory ? null : getDefaultOpener(Path.extname(file.path));
  const isTextFile = !file.isDirectory && (cat === "text" || cat === "code" || cat === "data");

  if (isTextFile) {
    return (
      <Button
        tag={file.path}
        action={async () => {
          if (navPath) {
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
              } else if (prefix === "extractfolder:") {
                // 解压到以文件名命名的子文件夹
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
                  await FileManager.createDirectory(extractDir, true);
                  await safeUnzip(file.path, extractDir);
                  invalidateDirectoryCache(parentDir);
                  onRefresh();
                  showToast(`已解压到 ${Path.basename(extractDir)}`);
                } catch (e) {
                  console.log("解压失败:", e);
                  showToast("解压失败");
                }
              } else if (prefix === "share:") {
                await handleShare();
              } else if (prefix === "pdf:") {
                await QuickLook.previewURLs([file.path], true);
              } else if (prefix === "webpage:") {
                const wv = new WebViewController();
                await wv.loadFile(file.path);
                await wv.present({ fullscreen: true, navigationTitle: file.name });
                wv.dispose();
              } else {
                navPath.setValue([...navPath.value, prefix + file.path]);
              }
            }
          }
        }}
        listRowSeparator={hideTopSeparator ? { visibility: "hidden", edges: "top" } : undefined}
        listRowBackground={isHighlighted ? <Rectangle fill="systemGray" opacity={0.15} /> : undefined}
        trailingSwipeActions={{
          actions: [<Button title="删除" role="destructive" action={handleDelete} />, <Button title="简介" action={handleShowInfo} />],
        }}
        leadingSwipeActions={{
          actions: [<Button title="重命名" action={handleRename} />],
        }}
        contextMenu={{
          menuItems: (
            <Group>
              {!file.isDirectory && (file.extension.toLowerCase() === '.html' || file.extension.toLowerCase() === '.htm' || file.extension.toLowerCase() === '.md') ? (
                <>
                  {file.extension.toLowerCase() === '.md' ? (
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
                    action={async () => {
                      if (navPath) {
                        navPath.setValue([...navPath.value, 'editor:' + file.path]);
                      }
                    }}
                  />
                  <Divider />
                </>
              ) : (
                <EmptyView />
              )}
              <Button title="重命名" systemImage="pencil" action={handleRename} />
              <Button
                title="拷贝"
                systemImage="doc.on.doc"
                action={async () => {
                  await onCopyPath?.(file.path);
                }}
              />
              <Button title="分享" systemImage="square.and.arrow.up" action={handleShare} />
              {copyToDirTitle && onCopyToDir ? (
                <Button
                  title={copyToDirTitle}
                  systemImage="arrow.right.doc.on.clipboard"
                  action={async () => {
                    await onCopyToDir(file.path);
                  }}
                />
              ) : (
                <EmptyView />
              )}
              {/* 压缩/解压 — 所有文件都有压缩选项，归档文件额外有解压选项 */}
              {getFileCategory(file.extension) === "archive" ? (
                <>
                  <Button
                    title="解压到当前目录"
                    systemImage="archivebox"
                    action={async () => {
                      try {
                        const targetDir = dirPath || Path.dirname(file.path);
                        await safeUnzip(file.path, targetDir);
                        invalidateDirectoryCache(targetDir);
                        onRefresh();
                        showToast("解压完成");
                      } catch (e) {
                        console.log("解压失败:", e);
                        showToast("解压失败");
                      }
                    }}
                  />
                  <Button
                    title={`解压到${sanitizeExtractDirName(file.name)}`}
                    systemImage="folder.badge.gearshape"
                    action={async () => {
                      try {
                        const archiveName = sanitizeExtractDirName(file.name);
                        let extractDir = Path.join(dirPath || Path.dirname(file.path), archiveName);
                        if (await FileManager.exists(extractDir)) {
                          let counter = 1;
                          while (await FileManager.exists(Path.join(dirPath || Path.dirname(file.path), `${archiveName}_${String(counter).padStart(2, "0")}`))) {
                            counter++;
                          }
                          extractDir = Path.join(dirPath || Path.dirname(file.path), `${archiveName}_${String(counter).padStart(2, "0")}`);
                        }
                        await FileManager.createDirectory(extractDir, true);
                        await safeUnzip(file.path, extractDir);
                        invalidateDirectoryCache(dirPath || Path.dirname(file.path));
                        onRefresh();
                        showToast(`已解压到 ${Path.basename(extractDir)}`);
                      } catch (e) {
                        console.log("解压失败:", e);
                        showToast("解压失败");
                      }
                    }}
                  />
                  <Divider />
                </>
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
          ),
        }}
        onDrag={file.isDirectory ? undefined : makeDragConfig(file.path)}
        onDrop={{
          types: DROP_ACCEPTED_TYPES,
          validateDrop: (info) => {
            const ok = info.hasItemsConforming(DROP_ACCEPTED_TYPES);
            return ok;
          },
          dropEntered: () => {},
          performDrop: (info) => {
            const destDir = file.isDirectory ? file.path : dirPath;
            if (!destDir) return false;
            if (file.isDirectory) invalidateDirectoryCache(destDir);
            handleDropToDirectory(info, destDir, () => {})
              .then(async () => {
                if (file.isDirectory) {
                  try {
                    const children = await countDirectoryItems(destDir);
                    onFolderCountChanged?.(destDir, children);
                  } catch {}
                }
                try {
                  await onRefresh();
                } catch {}
                onDropCompleted?.();
              })
              .catch(async () => {
                try {
                  await onRefresh();
                } catch {}
                onDropCompleted?.();
              });
            return true;
          },
        }}
      >
        <HStack spacing={12} alignment="center">
          <FileRowContent file={file} />
        </HStack>
      </Button>
    );
  }

  const isDir = file.isDirectory;

  return (
    <Button
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
              } else if (prefix === "extractfolder:") {
                // 解压到以文件名命名的子文件夹
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
                  await FileManager.createDirectory(extractDir, true);
                  await safeUnzip(file.path, extractDir);
                  invalidateDirectoryCache(parentDir);
                  onRefresh();
                  showToast(`已解压到 ${Path.basename(extractDir)}`);
                } catch (e) {
                  console.log("解压失败:", e);
                  showToast("解压失败");
                }
              } else if (prefix === "share:") {
                await handleShare();
              } else if (prefix === "pdf:") {
                await QuickLook.previewURLs([file.path], true);
              } else if (prefix === "webpage:") {
                const wv = new WebViewController();
                await wv.loadFile(file.path);
                await wv.present({ fullscreen: true, navigationTitle: file.name });
                wv.dispose();
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
        actions: [<Button title="删除" role="destructive" action={handleDelete} />, <Button title="简介" action={handleShowInfo} />],
      }}
      leadingSwipeActions={{
        actions: [<Button title="重命名" action={handleRename} />],
      }}
      contextMenu={{
        menuItems: (
          <Group>
            {isLivePhotoFile(file.name) ? (
              <>
                <Button
                  title="提取视频"
                  systemImage="video"
                  action={async () => {
                    try {
                      const data = await FileManager.readAsData(file.path);
                      if (data) {
                        const unpacked = unpackLivePhoto(data);
                        if (unpacked) {
                          const vidPath = Path.join(Path.dirname(file.path), Path.basename(file.name, ".live") + ".mov");
                          await FileManager.writeAsData(vidPath, unpacked.videoData);
                          onRefresh();
                        }
                      }
                    } catch (e) {
                      console.log("提取视频失败:", e);
                    }
                  }}
                />
                <Button
                  title="导出到相册"
                  systemImage="square.and.arrow.down"
                  action={async () => {
                    try {
                      const data = await FileManager.readAsData(file.path);
                      if (data) {
                        const unpacked = unpackLivePhoto(data);
                        if (unpacked) {
                          const baseName = Path.basename(file.name, ".live");
                          const stamp = String(Date.now());
                          const imgTmp = Path.join(FileManager.temporaryDirectory, baseName + "_" + stamp + "." + unpacked.imageExt);
                          const vidTmp = Path.join(FileManager.temporaryDirectory, baseName + "_" + stamp + ".mov");
                          await FileManager.writeAsData(imgTmp, unpacked.imageData);
                          await FileManager.writeAsData(vidTmp, unpacked.videoData);
                          await Photos.saveLivePhoto({ imagePath: imgTmp, videoPath: vidTmp });
                          try {
                            FileManager.remove(imgTmp);
                          } catch {}
                          try {
                            FileManager.remove(vidTmp);
                          } catch {}
                        }
                      }
                    } catch (e) {
                      console.log("导出到相册失败:", e);
                    }
                  }}
                />
              </>
            ) : (
              <EmptyView />
            )}
            {/* 普通图片/视频导出到相册 */}
            {!isLivePhotoFile(file.name) && getFileCategory(file.extension) === "image" ? (
              <Button
                title="导出到相册"
                systemImage="square.and.arrow.down"
                action={async () => {
                  try {
                    await Photos.savePhoto(file.path);
                  } catch (e) {
                    console.log("导出图片失败:", e);
                  }
                }}
              />
            ) : (
              <EmptyView />
            )}
            {!isLivePhotoFile(file.name) && getFileCategory(file.extension) === "video" ? (
              <Button
                title="导出到相册"
                systemImage="square.and.arrow.down"
                action={async () => {
                  try {
                    await Photos.saveVideo(file.path);
                  } catch (e) {
                    console.log("导出视频失败:", e);
                  }
                }}
              />
            ) : (
              <EmptyView />
            )}
            {/* 压缩/解压 — 所有非目录文件都有压缩选项，归档文件额外有解压选项 */}
            {!file.isDirectory && getFileCategory(file.extension) === "archive" ? (
              <>
                <Button
                  title="解压到当前目录"
                  systemImage="archivebox"
                  action={async () => {
                    try {
                      const targetDir = dirPath || Path.dirname(file.path);
                      await safeUnzip(file.path, targetDir);
                      invalidateDirectoryCache(targetDir);
                      onRefresh();
                      showToast("解压完成");
                    } catch (e) {
                      console.log("解压失败:", e);
                      showToast("解压失败");
                    }
                  }}
                />
                <Button
                  title={`解压到${sanitizeExtractDirName(file.name)} 内`}
                  systemImage="folder.badge.gearshape"
                  action={async () => {
                    try {
                      const archiveName = sanitizeExtractDirName(file.name);
                      let extractDir = Path.join(dirPath || Path.dirname(file.path), archiveName);
                      // 避免覆盖已有目录，追加 _01 _02
                      if (await FileManager.exists(extractDir)) {
                        let counter = 1;
                        while (await FileManager.exists(Path.join(dirPath || Path.dirname(file.path), `${archiveName}_${String(counter).padStart(2, "0")}`))) {
                          counter++;
                        }
                        extractDir = Path.join(dirPath || Path.dirname(file.path), `${archiveName}_${String(counter).padStart(2, "0")}`);
                      }
                      await FileManager.createDirectory(extractDir, true);
                      await safeUnzip(file.path, extractDir);
                      invalidateDirectoryCache(dirPath || Path.dirname(file.path));
                      onRefresh();
                      showToast(`已解压到 ${Path.basename(extractDir)}`);
                    } catch (e) {
                      console.log("解压失败:", e);
                      showToast("解压失败");
                    }
                  }}
                />
                <Divider />
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
              </>
            ) : (
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
            )}
            {/* 复制文件路径到剪贴板 */}
            <Button
              title="拷贝"
              systemImage="doc.on.doc"
              action={async () => {
                await onCopyPath?.(file.path);
              }}
            />
            <Button title="分享" systemImage="square.and.arrow.up" action={handleShare} />
            {copyToDirTitle && onCopyToDir ? (
              <Button
                title={copyToDirTitle}
                systemImage="arrow.right.doc.on.clipboard"
                action={async () => {
                  await onCopyToDir(file.path);
                }}
              />
            ) : (
              <EmptyView />
            )}
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
            <Button title="重命名" systemImage="pencil" action={handleRename} />
            <Button title="简介" systemImage="info.circle" action={handleShowInfo} />
            <Button title="删除" systemImage="trash" role="destructive" action={handleDelete} />
          </Group>
        ),
      }}
      onDrag={file.isDirectory ? undefined : makeDragConfig(file.path)}
      onDrop={{
        types: DROP_ACCEPTED_TYPES,
        validateDrop: (info) => {
          const ok = info.hasItemsConforming(DROP_ACCEPTED_TYPES);
          return ok;
        },
        dropEntered: () => {},
        performDrop: (info) => {
          const destDir = file.isDirectory ? file.path : dirPath;
          if (!destDir) return false;
          if (file.isDirectory) invalidateDirectoryCache(destDir);
          handleDropToDirectory(info, destDir, () => {})
            .then(async () => {
              if (file.isDirectory) {
                try {
                  const children = await countDirectoryItems(destDir);
                  onFolderCountChanged?.(destDir, children);
                } catch {}
              }
              try {
                await onRefresh();
              } catch {}
              onDropCompleted?.();
            })
            .catch(async () => {
              try {
                await onRefresh();
              } catch {}
              onDropCompleted?.();
            });
          return true;
        },
      }}
    >
      <HStack spacing={12} alignment="center">
        <FileRowContent file={file} folderCounts={folderCounts} />
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
  folderCountUpdateRef?: { current?: (folderPath: string, count: number) => void };
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

  // 100ms 防闪烁 - 用 ref 避免 useEffect 延迟
  const spinnerReadyRef = useRef(false);
  const spinnerTimerRef = useRef<number | null>(null);
  const [tick, setTick] = useState(0);
  const spinTickRef = useRef(0);

  useEffect(() => {
    if (spinnerTimerRef.current) {
      clearTimeout(spinnerTimerRef.current);
      spinnerTimerRef.current = null;
    }
    if (isLoading) {
      spinnerReadyRef.current = false;
      spinTickRef.current = 0;
      let cancelled = false;
      const spin = () => {
        if (cancelled || !spinnerReadyRef.current) return;
        setTick((t) => t + 1);
        spinnerTimerRef.current = setTimeout(spin, 80);
      };
      spinnerTimerRef.current = setTimeout(() => {
        if (cancelled) return;
        spinnerReadyRef.current = true;
        setTick((t) => t + 1);
        spinnerTimerRef.current = setTimeout(spin, 80);
      }, 100);
      return () => {
        cancelled = true;
        if (spinnerTimerRef.current) {
          clearTimeout(spinnerTimerRef.current);
          spinnerTimerRef.current = null;
        }
        spinnerReadyRef.current = false;
        spinTickRef.current = 0;
      };
    } else {
      spinnerReadyRef.current = false;
      spinTickRef.current = 0;
    }
  }, [isLoading]);
  const showSpinner = isLoading && spinnerReadyRef.current;

  let sourceFiles = items ?? files;
  /* ── 防止 displayFiles 变化时重复滚动到高亮文件 ── */
  const [searchQuery, setSearchQuery] = useState("");
  const [showSearch, setShowSearch] = useState(false);

  // 从 settings 或 props 读取排序/筛选初始值
  const [sortOrder, setSortOrder] = useState<import("../manager/sortFilter").SortOrder>(
    () => (settings?.defaultSortOrder || readSettings().defaultSortOrder || initialSortOrder || DEFAULT_SORT_ORDER) as any,
  );
  const [filterType, setFilterType] = useState<string>(() => (isHomePage && settings?.defaultFilterType ? settings.defaultFilterType : initialFilterType || DEFAULT_FILTER_TYPE));

  // 选择模式
  const [selectMode, setSelectMode] = useState(false);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());

  // 搜索栏是否活跃
  const [copiedFilePath, setCopiedFilePath] = useState<string | null>(null);
  // 跳转到目录时高亮的文件路径
  const [highlightedPath, setHighlightedPath] = useState<string | null>(null);
  const selectedFile = useObservable<string | null>(null);
  const scrollProxy = useRef<any>(null);
  // 标记：首次加载不带动画，避免初次滑动卡顿
  const firstLoadRef = useRef(true);
  const loadSeqRef = useRef(0);
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
  useEffect(() => {
    if (isLoading) {
      spinnerReadyRef.current = true;
      setTick(1);
    }
  }, []);
  const updateCopiedPath = async (path: string | null) => {
    // 先更新 UI 状态，再异步写入文件（粘贴按钮立即出现）
    setCopiedFilePath(path);
    await _writeClipPath(path);
    // 如果有外部剪贴板回调，同步通知（跨栏共享）
    if (onExternalCopy) {
      onExternalCopy(path ?? "");
    }
  };

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

  // 每个子文件夹内的项目数
  const [folderCounts, setFolderCounts] = useState<Map<string, number>>(new Map());
  const mergeFolderCountUpdates = (counts: { path: string; count: number }[]) => {
    if (counts.length === 0) return;
    setFolderCounts((prev) => {
      let next: Map<string, number> | null = null;
      for (const c of counts) {
        if (prev.get(c.path) !== c.count) {
          if (!next) next = new Map(prev);
          next.set(c.path, c.count);
        }
      }
      return next ?? prev;
    });
  };
  const mergeFolderCountUpdatesRef = useRef(mergeFolderCountUpdates);
  mergeFolderCountUpdatesRef.current = mergeFolderCountUpdates;
  const applyFolderCountUpdate = (folderPath: string, count: number, notifyPeer: boolean = true) => {
    setFolderCounts((prev) => {
      if (prev.get(folderPath) === count) return prev;
      const next = new Map(prev);
      next.set(folderPath, count);
      return next;
    });
    if (notifyPeer) onFolderCountChanged?.(folderPath, count);
  };
  if (folderCountUpdateRef) {
    folderCountUpdateRef.current = (folderPath: string, count: number) => {
      applyFolderCountUpdate(folderPath, count, false);
    };
  }

  // ── 首页专用状态 ──
  const defaultDir = Path.join(FileManager.documentsDirectory, "File Store");
  const [homeCurrentDir, setHomeCurrentDir] = useState(isHomePage ? settings?.homeCurrentPath || defaultDir : dirPath || "");
  const [navGen, setNavGen] = useState(0);
  const prevNavLenRef = useRef(0);
  const homeNavPath = useObservable<string[]>([]);

  const homeNavLength = isHomePage ? homeNavPath.value.length : 0;

  // 首页模式使用内部状态管理目录路径和导航，非首页直接使用 prop
  // const 声明避免函数参数可变性带来的不可预测行为
  const activeDirPath = isHomePage ? homeCurrentDir || defaultDir : dirPath || "";
  const activeNavPath = isHomePage ? homeNavPath : outerNavPath;

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
            } catch {}
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
            const counts: { path: string; count: number }[] = [];
            for (const dir of dirs) {
              try {
                const children = await countDirectoryItems(dir.path);
                counts.push({ path: dir.path, count: children });
              } catch {}
            }
            if (counts.length > 0) {
              mergeFolderCountUpdatesRef.current(counts);
            }
          } catch {}
        }
      };
      doRefresh();
    }
  }, [refreshKey]);

  const loadDirectory = async (silent = false) => {
    if (items || !activeDirPath) return;
    const loadSeq = ++loadSeqRef.current;
    const loadingDir = activeDirPath;
    if (!silent) setIsLoading(true);
    const isLatestLoad = () => loadSeq === loadSeqRef.current && loadingDir === activeDirPath;
    try {
      const itemsList = await listDirectory(loadingDir);
      if (!isLatestLoad()) return;
      // 加载后立即查找要高亮的文件
      if (highlightFile) {
        const matched = itemsList.find((f) => f.name === highlightFile);
        if (matched) {
          withAnimation(Animation.smooth({ duration: 0.4 }), () => {
            setFiles(itemsList);
            setHighlightedPath(matched.path);
          });
          setTimeout(() => scrollProxy.current?.scrollTo(matched.path, "center"), 450);
          setTimeout(() => {
            setHighlightedPath(null);
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
      // 首页目录不存在时自动回退到默认目录
      if (isHomePage && loadingDir) {
        try {
          const exists = await FileManager.exists(loadingDir);
          if (!exists) {
            console.log("首页目录不存在，回退到默认目录:", defaultDir);
            setHomeCurrentDir(defaultDir);
            if (settings && onSettingsChange) {
              const restored = { ...settings, homeCurrentPath: defaultDir };
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
        } catch {}
      }
      if (isLatestLoad()) setIsLoading(false);
    }
  };
  const loadDirectoryRef = useRef(loadDirectory);
  loadDirectoryRef.current = loadDirectory;

  const refreshDirectory = async () => {
    // 强制清除缓存，确保从磁盘读取最新内容（拖拽/删除/重命名等操作依赖此行为）
    if (activeDirPath) invalidateDirectoryCache(activeDirPath);
    if (items && onItemsChange) {
      // items mode: reload from disk to get refreshed items
      if (activeDirPath) {
        try {
          const refreshed = await listDirectory(activeDirPath);
          onItemsChange(refreshed);
        } catch {}
      }
    } else {
      await loadDirectory(true);
    }
  };

  const refresh = async () => {
    if (!activeDirPath) return;
    invalidateDirectoryCache(activeDirPath);
    try {
      if (items && onItemsChange) {
        const refreshed = await listDirectory(activeDirPath);
        onItemsChange(refreshed);
      } else {
        await loadDirectory(true);
      }
    } catch (e) {
      console.error("Refresh failed:", e);
    }
  };

  // 999ms 轮询检测目录内容变化 + 新增文件高亮（非 items 模式）
  // 每次先 stat 当前目录；目录未变化时跳过昂贵的 readDirectory + getFileInfo 全量扫描。
  const filesRef = useRef<FileInfo[]>(files);
  filesRef.current = files;
  const prevPollRef = useRef<FileInfo[] | null>(null);
  const prevPollTokenRef = useRef<string | null>(null);
  const pollCountRef = useRef(0);
  const pollSeqRef = useRef(0);
  useEffect(() => {
    // 自增序列号：新目录的轮询启动时，旧目录正在进行的异步操作可检测到序号不匹配并自动中止
    pollSeqRef.current += 1;
    const seq = pollSeqRef.current;
    if (items || !activeDirPath) return;
    // 切换目录时重置轮询快照，避免用旧目录的文件列表与新目录比较而误高亮
    prevPollRef.current = null;
    prevPollTokenRef.current = null;
    pollCountRef.current = 0;
    let pollTimer: number | null = null;
    const isLatestPoll = () => seq === pollSeqRef.current;
    const scheduleNextPoll = () => {
      if (isLatestPoll()) {
        pollTimer = setTimeout(poll, DIRECTORY_POLL_INTERVAL_MS);
      }
    };
    const poll = async () => {
      if (!isLatestPoll()) return;
      try {
        pollCountRef.current += 1;
        const token = await getDirectoryPollToken(activeDirPath);
        if (!isLatestPoll()) return;
        const forceFullScan = pollCountRef.current % DIRECTORY_POLL_FORCE_FULL_EVERY === 0;
        const tokenChanged = token == null || prevPollTokenRef.current == null || token !== prevPollTokenRef.current;
        if (!tokenChanged && !forceFullScan) {
          scheduleNextPoll();
          return;
        }
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
      } catch (e) {}
      if (isLatestPoll()) {
        scheduleNextPoll();
      }
    };
    const initialTimer = setTimeout(poll, initialLoadDelay || 0);
    return () => {
      clearTimeout(initialTimer);
      if (pollTimer) clearTimeout(pollTimer);
    };
  }, [items, activeDirPath, initialLoadDelay]);

  const displayFiles = useMemo(() => {
    let result = sourceFiles;
    if (searchQuery.trim()) {
      result = searchFiles(sourceFiles, searchQuery);
    }
    result = filterFiles(result, filterType);
    return sortFilesByOrder(result, sortOrder);
  }, [sourceFiles, searchQuery, sortOrder, filterType]);

  // displayFiles 更新后重新匹配高亮
  useEffect(() => {
    if (!highlightFile) return;
    console.log("highlightFile changed, search for:", highlightFile, "total files:", displayFiles.length);
    const match = displayFiles.find((f) => f.name === highlightFile);
    if (match) {
      console.log("highlightFile match via displayFiles:", match.path);
      setHighlightedPath(match.path);
      setTimeout(() => scrollProxy.current?.scrollTo(match.path, "center"), 100);
      setTimeout(() => {
        setHighlightedPath(null);
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
  const [visibleCount, setVisibleCount] = useState(50);
  const visibleFiles = useMemo(() => displayFiles.slice(0, visibleCount), [displayFiles, visibleCount]);
  const hasMore = displayFiles.length > visibleCount;

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
        const counts: { path: string; count: number }[] = [];
        for (const dir of dirs) {
          if (cancelled) return;
          try {
            const children = await countDirectoryItems(dir.path);
            counts.push({ path: dir.path, count: children });
          } catch {
            counts.push({ path: dir.path, count: 0 });
          }
        }
        if (!cancelled) mergeFolderCountUpdates(counts);
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
  const toggleSelect = (path: string) => {
    const next = new Set(selectedPaths);
    if (next.has(path)) next.delete(path);
    else next.add(path);
    setSelectedPaths(next);
  };

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
    for (const p of selectedPaths) {
      try {
        await FileManager.remove(p);
      } catch (e) {
        console.log("删除失败:", e);
      }
    }
    const deletedPaths = new Set(selectedPaths);
    withAnimation(Animation.smooth({ duration: 0.35 }), () => {
      setSelectedPaths(new Set());
      setSelectMode(false);
      setFiles((prev) => prev.filter((f) => !deletedPaths.has(f.path)));
    });
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
          } catch {}
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
    for (const p of selectedPaths) {
      try {
        const name = Path.basename(p);
        await FileManager.rename(p, Path.join(dest.trim(), name));
      } catch (e) {
        console.log("移动失败:", e);
      }
    }
    setSelectedPaths(new Set());
    setSelectMode(false);
    if (activeDirPath) invalidateDirectoryCache(activeDirPath);
    loadDirectory(true);
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
              } catch {}
              try {
                FileManager.remove(vidTmp);
              } catch {}
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
        } catch (e2) {}
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
        } catch (e2) {}
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
    onSortFilterChange?.(sortOrder, type);
  };

  // 搜索栏始终显示

  // ── 导入/相机/实况照片（所有页面可用）──
  let handleOpenSettingsInternal: () => void = () => {};
  let homeNavigationDest = null as any;

  const handleImportFromFiles = async () => {
    try {
      const files = await DocumentPicker.pickFiles({ shouldShowFileExtensions: true });
      if (files && files.length > 0) {
        await ensureDir(activeDirPath);
        const _newPaths: string[] = [];
        for (const filePath of files) {
          const name = Path.basename(filePath);
          const dest = Path.join(activeDirPath, name);
          if (await FileManager.exists(dest)) await FileManager.remove(dest);
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
                  mimeType: getMimeType(ext, p),
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
        const dest = Path.join(activeDirPath, `IMG_${ts}${ext}`);
        if (await FileManager.exists(dest)) await FileManager.remove(dest);
        await FileManager.copyFile(result.imagePath, dest);
        try {
          await FileManager.remove(result.imagePath);
        } catch {}
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
        const dest = Path.join(activeDirPath, `VID_${ts}${ext}`);
        if (await FileManager.exists(dest)) await FileManager.remove(dest);
        await FileManager.copyFile(result.mediaPath, dest);
        try {
          await FileManager.remove(result.mediaPath);
        } catch {}
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
      <Button title="从文件导入" systemImage="doc.badge.plus" action={handleImportFromFiles} />
      <Divider />
      <Menu title="更多导入" systemImage="ellipsis.circle">
        <Button title="图片" systemImage="photo" action={handleImportImages} />
        <Button title="视频" systemImage="video" action={handleImportVideos} />
        <Button title="实况照片" systemImage="livephoto" action={handleImportLivePhotosOnly} />
        <Divider />
        <Button title="拍照" systemImage="camera.viewfinder" action={handleTakePhoto} />
        <Button title="录像" systemImage="video.circle" action={handleRecordVideo} />
      </Menu>
    </Group>
  );

  if (isHomePage) {
    homeNavigationDest = (
      <NavigationDestination>
        {(page) => {
          if (page.startsWith("browser:")) {
            let dPath = page.slice(8);
            let hFile: string | undefined;
            const sepIdx = dPath.indexOf("::");
            if (sepIdx !== -1) {
              hFile = decodeURIComponent(dPath.slice(sepIdx + 2));
              dPath = dPath.slice(0, sepIdx);
            }
            return (
              <GeneralBrowser
                key={page + "@navGen" + navGen}
                dirPath={dPath}
                dirName={Path.basename(dPath)}
                rootPath={dPath}
                navPath={activeNavPath}
                highlightFile={hFile}
                isHomePage={false}
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
        } catch {}
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
    const relativePath = activeDirPath.replace(root, "").replace(/^\//, "");
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

  const handleResetPath = async () => {
    if (isHomePage && settings && onSettingsChange) {
      const newSettings = { ...settings, homeCurrentPath: null, homeDirectoryBookmarkName: null };
      saveSettings(newSettings);
      onSettingsChange(newSettings);
    } else if (activeNavPath) {
      const target = rootPath || defaultDir;
      activeNavPath.setValue([...activeNavPath.value, "browser:" + target]);
    }
  };

  const handleCopyPath = async () => {
    if (!activeDirPath) return;
    await Pasteboard.setString(activeDirPath);
    showToast("已复制路径");
  };

  const handlePastePath = async () => {
    try {
      const text = await Pasteboard.getString();
      if (!text || !text.trim()) {
        await Dialog.alert({ title: "提示", message: "剪贴板为空", buttonLabel: "确定" });
        return;
      }
      const trimmed = text.trim();
      const exists = await FileManager.exists(trimmed);
      if (!exists) {
        await Dialog.alert({ title: "提示", message: "路径不存在：" + trimmed, buttonLabel: "确定" });
        return;
      }
      if (isHomePage && settings && onSettingsChange) {
        const newSettings = { ...settings, homeCurrentPath: trimmed, homeDirectoryBookmarkName: null };
        saveSettings(newSettings);
        onSettingsChange(newSettings);
      } else if (activeNavPath) {
        activeNavPath.setValue([...activeNavPath.value, "browser:" + trimmed]);
      }
    } catch (e) {
      console.log("粘贴路径失败:", e);
    }
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
    const path = bookmark.path;
    const exists = await FileManager.exists(path);
    if (!exists) {
      await Dialog.alert({ title: "提示", message: "目录不存在：" + path, buttonLabel: "确定" });
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

  const handleRenameBookmark = async (bookmark: Bookmark) => {
    const newName = await Dialog.prompt({
      title: "重命名收藏",
      defaultValue: bookmark.name,
      placeholder: "名称",
      cancelLabel: "取消",
      confirmLabel: "确定",
    });
    if (newName && newName.trim() && newName.trim() !== bookmark.name) {
      renameBookmark(bookmark.name, newName.trim());
      setBookmarkRefreshKey((k) => k + 1);
    }
  };

  const handleDeleteBookmark = async (bookmark: Bookmark) => {
    const confirmed = await Dialog.confirm({
      title: "删除收藏",
      message: `确定删除「${bookmark.name}」？`,
      cancelLabel: "取消",
      confirmLabel: "删除",
    });
    if (confirmed) {
      removeBookmark(bookmark.name);
      setBookmarkRefreshKey((k) => k + 1);
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
    } catch {}
    onDropCompleted?.();
  };

  const handleDropToCurrentDirectory = (info: DropInfo) => {
    if (!effectiveDropDir) return false;
    handleDropToDirectory(info, effectiveDropDir, () => {})
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
    <Button action={() => {}} listRowSeparator={{ visibility: "hidden", edges: "all" }} listRowBackground={<Rectangle fill="clear" />} onDrop={currentDirectoryDrop}>
      <VStack frame={{ maxWidth: "infinity", minHeight: 520 }} contentShape="rect">
        <Spacer minLength={520} />
      </VStack>
    </Button>
  );

  const mainContent = (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }} onDrop={currentDirectoryDrop}>
      <VStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
        <ScrollViewReader>
          {(proxy) => {
            scrollProxy.current = proxy;
            return (
              <List
                selection={selectedFile}
                listStyle="plain"
                navigationTitle={titleDisplayPath}
                navigationBarTitleDisplayMode="inline"
                navigationDestination={isHomePage ? homeNavigationDest : navigationDestination}
                refreshable={refresh}
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
                    <ToolbarItem placement="principal">
                      <Menu
                        label={
                          <Text font="headline" lineLimit={1}>
                            {titleDisplayPath}
                          </Text>
                        }
                      >
                        <Button title="访问 • 输入路径" systemImage="pencil.and.outline" action={handleInputPath} />
                        <Button title="访问 • 默认路径" systemImage="arrow.counterclockwise" action={handleResetPath} />
                        <Divider />
                        <Button title="复制当前路径" systemImage="doc.on.clipboard" action={handleCopyPath} />
                        <Divider />
                        <Button title="手动选择路径收藏" systemImage="star" action={handleAddBookmark} />
                        {allBookmarks.length > 0 ? (
                          <>
                            <Divider />
                            {allBookmarks.map((bm) => (
                              <Button title={bm.name} systemImage="folder" action={() => handleNavigateToBookmark(bm)} />
                            ))}
                          </>
                        ) : (
                          <EmptyView />
                        )}
                        {systemDirEntries.length > 0 ? (
                          <>
                            <Divider />
                            {systemDirEntries.map((entry) => (
                              <Button
                                key={entry.name}
                                title={entry.name}
                                systemImage={entry.icon}
                                action={async () => {
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
                                }}
                              />
                            ))}
                          </>
                        ) : (
                          <EmptyView />
                        )}
                      </Menu>
                    </ToolbarItem>
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
                          <Group key={"cp-" + (effectiveCopiedPath ? "1" : "0")}>
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
                            <Button title="新建文件" systemImage="doc.text" action={handleCreateNewFile} />
                            <Button title="新建文件夹" systemImage="folder.badge.plus" action={() => handleCreateFile("folder")} />
                            <Button title="快速新建JS" systemImage="chevron.left.forwardslash.chevron.right" action={() => handleCreateFile("js", true)} />
                            {isHomePage ? (
                              importToolbarItems
                            ) : (
                              <>
                                {importToolbarItems}
                                {toolbarOtherItems ?? <EmptyView />}
                              </>
                            )}
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
                                  : onOpenSettings || (() => {})
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
                    resultLeadingActions={(result) => [
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
                    ]}
                    resultTrailingActions={(result) => [
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
                          try {
                            const newPath = Path.join(Path.dirname(result.path), result.name);
                            await FileManager.copyFile(result.path, newPath);
                            refreshDirectory();
                          } catch (e) {
                            console.log("复制失败:", e);
                          }
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
                            if (line && activeNavPath) {
                              // 用 ::L 嵌入行号 = 导航栈方式（普通文件也用同一方式）
                              activeNavPath.setValue([...activeNavPath.value, prefix + result.path + "::L" + line]);
                            } else if (activeNavPath) {
                              activeNavPath.setValue([...activeNavPath.value, prefix + result.path]);
                            }
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
                        <FileRowLink
                          key={file.path}
                          file={file}
                          onRefresh={refreshDirectory}
                          onDeleteFile={(filePath) => setFiles((prev) => prev.filter((f) => f.path !== filePath))}
                          selectMode={selectMode}
                          isSelected={selectedPaths.has(file.path)}
                          onToggleSelect={() => toggleSelect(file.path)}
                          rootPath={rootPath || activeDirPath}
                          rootName={rootName || dirName}
                          navPath={activeNavPath}
                          hideTopSeparator={fileIdx === 0}
                          folderCounts={folderCounts}
                          onCopyPath={(path) => updateCopiedPath(path)}
                          isHighlighted={file.path === highlightedPath}
                          copyToDirTitle={oppositeDirName}
                          onCopyToDir={onCopyToOppositeDir}
                          dirPath={effectiveDropDir}
                          onDropCompleted={onDropCompleted}
                          onFolderCountChanged={applyFolderCountUpdate}
                        />
                      ))}
                      {hasMore ? <Button title="加载更多" onAppear={() => setVisibleCount((prev) => prev + 50)} action={() => setVisibleCount((prev) => prev + 50)} /> : <EmptyView />}
                    </Section>
                  )
                ) : (
                  <EmptyView />
                )}

                {displayFiles.length > 0 ? (
                  <Section>
                    <HStack spacing={12} alignment="center" listRowBackground={<></>} listRowSeparator={{ visibility: "hidden", edges: "all" }} padding={{ top: 20, bottom: 20 }}>
                      <Spacer />
                      <Text foregroundStyle="tertiaryLabel">
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
  if (isHomePage && homeNavPath.value.length > 0) {
    for (let i = homeNavPath.value.length - 1; i >= 0; i--) {
      const p = homeNavPath.value[i];
      if (p.startsWith("browser:")) {
        effectiveDropDir = p.slice(8);
        break;
      }
    }
  }

  return isHomePage ? (
    <ZStack frame={{ maxWidth: "infinity", maxHeight: "infinity" }}>
      <NavigationStack
        path={homeNavPath}
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
            const pathArray = Array.isArray(homeNavPath?.value) ? homeNavPath.value : homeNavPath?.value ? [homeNavPath.value] : [];
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
            handleDropToDirectory(info, destDir, () => {})
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
                } catch {}
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

export { GeneralBrowser };
