// 通用搜索面板组件 - 深度搜索功能
// 搜索栏由父组件的 List.searchable 提供
// 本组件仅处理深度搜索的开关、索引构建与结果展示

import { Section, HStack, VStack, Spacer, Text, Image, Button, useState, useEffect, useRef, useMemo, VirtualNode, Group, Menu, Path, StyledText, EmptyView } from "scripting";
import { buildIndex, searchFromIndex, DeepSearchResult, getIndexStats, IndexStats, cancelBuildIndex, closeDatabase } from "../manager/DeepSearch";
import { setDeepSearchPref, getDeepSearchPref } from "../manager/SearchState";
import { FileInfo, FileCategory, writeClipboardPath, shareFilePath } from "../manager/utils";
import { ContextMenuItem } from "./FileListItem";
import { resolveOpenerForFile } from "./DefaultOpenerPicker";
import { setDefaultOpener, OPENER_OPTIONS } from "../manager/DefaultOpener";
import { showToast } from "../manager/ToastManager";

interface SearchPanelProps {
  /** 当前搜索关键字 */
  searchQuery: string;
  /** 搜索 / 索引的根目录（即当前文件夹路径） */
  dirPath: string;
  /** 是否显示深度搜索开关与功能，默认 true */
  enableDeepSearch?: boolean;
  /**
   * 深度搜索结果行的目标页（Button + Navigation.present 模式）。
   * 与 onResultTap 二选一；提供后行将渲染为 Button + Navigation.present。
   */
  destinationForResult?: (result: DeepSearchResult) => VirtualNode;
  /**
   * 深度搜索结果行的点击回调（Button + Navigation.present 模式）。
   * 仅在未提供 destinationForResult 时生效。
   */
  onResultTap?: (result: DeepSearchResult) => void;
  /** 结果行第二行是否显示大小（默认根据是否文件夹自动） */
  showSize?: boolean;
  /** 深度搜索结果数量变化回调（供外部展示空状态等） */
  onResultsChange?: (results: DeepSearchResult[]) => void;
  /** 导航路径 Observable（文件夹结果用侧滑进入） */
  navPath?: any;
  /** 搜索结果行的左滑操作（每结果） */
  resultLeadingActions?: (result: DeepSearchResult) => ContextMenuItem[];
  /** 搜索结果行的右滑操作（每结果） */
  resultTrailingActions?: (result: DeepSearchResult) => ContextMenuItem[];
  /** 搜索结果行的上下文菜单（每结果） */
  resultContextMenuItems?: (result: DeepSearchResult) => ContextMenuItem[];
}

/* ───── 高亮文本组件 ───── */

/** 将文本中匹配 query 的部分高亮显示，可附带行号前缀 */
function HighlightedText({ text, query }: { text: string; query: string }) {
  if (!query.trim()) {
    return (
      <Text font={12} foregroundStyle="secondaryLabel" multilineTextAlignment="leading">
        {text}
      </Text>
    );
  }

  const lowerText = text.toLowerCase();
  const lowerQuery = query.toLowerCase();
  const segments: (string | StyledText)[] = [];

  let pos = 0;
  while (pos < text.length) {
    const idx = lowerText.indexOf(lowerQuery, pos);
    if (idx === -1) {
      segments.push({ content: text.slice(pos), foregroundColor: "secondaryLabel", font: 12 });
      break;
    }
    if (idx > pos) {
      segments.push({ content: text.slice(pos, idx), foregroundColor: "secondaryLabel", font: 12 });
    }
    segments.push({
      content: text.slice(idx, idx + query.length),
      foregroundColor: "systemPink",
      fontWeight: "bold",
      font: 12,
    });
    pos = idx + query.length;
  }

  if (segments.length === 0) {
    return (
      <Text font={12} foregroundStyle="secondaryLabel" multilineTextAlignment="leading">
        {text}
      </Text>
    );
  }

  return (
    <Text
      font={12}
      multilineTextAlignment="leading"
      styledText={{
        content: segments,
      }}
    />
  );
}

/* ───── DeepSearchResult → FileInfo ───── */
function resultToFileInfo(result: DeepSearchResult): FileInfo {
  return {
    path: result.path,
    name: result.name,
    size: result.size,
    modificationDate: result.modificationDate,
    isDirectory: result.isDirectory,
    isLink: false,
    extension: Path.extname(result.name),
    category: result.category as FileCategory,
    mimeType: "",
    icon: result.icon,
    iconColor: result.iconColor as FileInfo["iconColor"],
    creationDate: 0,
  };
}

/* ───── 主组件 ───── */

export function SearchPanel({ searchQuery, dirPath, enableDeepSearch = true, onResultTap, onResultsChange, navPath, resultLeadingActions, resultTrailingActions }: SearchPanelProps) {
  /* ── 内部状态 ── */
  const [deepSearchResults, setDeepSearchResults] = useState<DeepSearchResult[]>([]);
  const deepSearchResultsRef = useRef<DeepSearchResult[]>(deepSearchResults);
  deepSearchResultsRef.current = deepSearchResults;
  // 默认关闭，后续 useEffect 检查偏好后自动开启
  const [deepSearchEnabled, setDeepSearchEnabled] = useState(false);
  const [isBuildingIndex, setIsBuildingIndex] = useState(false);
  const [indexStats, setIndexStats] = useState<IndexStats | null>(null);
  const [indexingCount, setIndexingCount] = useState(0);
  const indexingCountRef = useRef(0);
  /* ── 分页状态 ── */
  const [searchOffset, setSearchOffset] = useState(0);
  const [hasMoreResults, setHasMoreResults] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const pageSize = 200;
  /* ── 已删除路径缓存，防止重新搜索后再次出现 ── */
  const deletedPathsRef = useRef(new Set<string>());

  /* ── 首次渲染时深度搜索已自动开启：构建索引（仅一次） ── */
  const deepSearchInitedRef = useRef(false);
  useEffect(() => {
    if (!deepSearchEnabled || deepSearchInitedRef.current || !dirPath) return;
    deepSearchInitedRef.current = true;
    (async () => {
      try {
        const stats = await getIndexStats(dirPath);
        setIndexStats(stats);
        if (stats.total === 0) {
          setIsBuildingIndex(true);
          await buildIndex(dirPath, (count) => {
            setIndexingCount(count);
          });
          setIsBuildingIndex(false);
          const freshStats = await getIndexStats(dirPath);
          setIndexStats(freshStats);
        }
      } catch {}
    })();
  }, [deepSearchEnabled]);

  /* ── 深度搜索：构建索引 ── */
  const buildDeepSearchIndex = async (forceRebuild: boolean = false) => {
    setIsBuildingIndex(true);
    setIndexingCount(0);
    indexingCountRef.current = 0;
    try {
      await buildIndex(
        dirPath,
        (count, _currentPath) => {
          indexingCountRef.current = count;
          setIndexingCount(count);
        },
        forceRebuild,
      );
      const stats = await getIndexStats(dirPath);
      setIndexStats(stats);
      // 索引重建完成后自动重新搜索当前查询，确保结果列表与最新索引一致
      if (searchQuery.trim()) {
        await performDeepSearch(searchQuery);
      }
    } catch (e) {
      console.log("构建索引失败:", e);
    } finally {
      setIsBuildingIndex(false);
    }
  };

  /* ── 深度搜索：执行搜索 ── */
  const performDeepSearch = async (query: string, append: boolean = false) => {
    const currentDirPath = dirPath;
    if (!query.trim()) {
      setSearchOffset(0);
      setHasMoreResults(false);
      notifyResults([]);
      return;
    }
    try {
      const offset = append ? searchOffset : 0;
      const results = await searchFromIndex(currentDirPath, query, pageSize, offset);
      if (append) {
        const updated = [...deepSearchResultsRef.current, ...results];
        setDeepSearchResults(updated);
        deepSearchResultsRef.current = updated;
        onResultsChange?.(updated);
      } else {
        notifyResults(results);
      }
      setSearchOffset(offset + results.length);
      setHasMoreResults(results.length >= pageSize);
    } catch (e) {
      console.log("深度搜索失败:", e);
    }
  };

  const loadMoreResults = async () => {
    if (isLoadingMore || !hasMoreResults) return;
    setIsLoadingMore(true);
    await performDeepSearch(searchQuery, true);
    setIsLoadingMore(false);
  };

  /* ── 通知外部结果变化（过滤已删除路径） ── */
  const notifyResults = (results: DeepSearchResult[]) => {
    const filtered = results.filter((r) => !deletedPathsRef.current.has(r.path));
    setDeepSearchResults(filtered);
    deepSearchResultsRef.current = filtered;
    onResultsChange?.(filtered);
  };

  /* ── 深度搜索：开关切换 ── */
  const toggleDeepSearch = async (enabled: boolean) => {
    setDeepSearchEnabled(enabled);
    // 手动切换后标记已初始化，避免 useEffect 重复构建索引
    if (enabled) deepSearchInitedRef.current = true;
    // 持久化偏好
    if (dirPath) {
      setDeepSearchPref(dirPath, enabled);
    }
    if (enabled) {
      if (!indexStats || indexStats.total === 0) {
        const stats = await getIndexStats(dirPath);
        setIndexStats(stats);
        if (stats.total === 0) {
          await buildDeepSearchIndex();
        }
      }
      if (searchQuery.trim()) {
        await performDeepSearch(searchQuery);
      }
    } else {
      notifyResults([]);
    }
  };

  /* ── 当用户输入搜索词时检查偏好并自动开启 ── */
  useEffect(() => {
    if (searchQuery.trim() && !deepSearchEnabled && dirPath && getDeepSearchPref(dirPath)) {
      setDeepSearchEnabled(true);
    }
  }, [searchQuery]);

  /* ── 输入变化时自动触发深度搜索（防抖） ── */
  useEffect(() => {
    if (deepSearchEnabled && searchQuery.trim()) {
      const timer = setTimeout(() => {
        performDeepSearch(searchQuery);
      }, 300);
      return () => clearTimeout(timer);
    } else if (deepSearchEnabled && !searchQuery.trim()) {
      notifyResults([]);
    }
  }, [searchQuery, deepSearchEnabled]);

  /* ── 退出搜索时重置深度搜索 ── */
  useEffect(() => {
    if (!searchQuery.trim()) {
      setDeepSearchResults([]);
      deepSearchResultsRef.current = [];
      setSearchOffset(0);
      setHasMoreResults(false);
      setIsBuildingIndex(false);
      setIndexingCount(0);
      cancelBuildIndex();
    }
  }, [searchQuery]);

  /* ── 取消索引 ── */
  const handleCancelIndexing = () => {
    cancelBuildIndex();
    setIsBuildingIndex(false);
    setIndexingCount(0);
  };

  /* ── 缓存导航回调和防重复导航 ── */
  const navPathRef = useRef(navPath);
  const onResultTapRef = useRef(onResultTap);
  navPathRef.current = navPath;
  onResultTapRef.current = onResultTap;
  const navigatingRef = useRef<string | null>(null);

  /* ── 自定义折叠状态（按文件路径）默认全部折叠 ── */
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const toggleExpanded = (path: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  /* ── 缓存结果渲染 ── */
  const resultsSection = useMemo(() => {
    if (!enableDeepSearch || deepSearchResults.length === 0) return <EmptyView />;

    const navigateToFile = (result: DeepSearchResult, specificLine?: number) => {
      // 防止重复导航
      const path_ = result.path;
      if (navigatingRef.current === path_) return;
      navigatingRef.current = path_;
      setTimeout(() => {
        navigatingRef.current = null;
      }, 500);

      const _onResultTap = onResultTapRef.current;
      const _navPath = navPathRef.current;
      if (_onResultTap) {
        if (specificLine) {
          // 覆盖 matchedLine 指向具体行
          _onResultTap({ ...result, matchedLine: specificLine });
        } else {
          _onResultTap(result);
        }
      } else if (_navPath) {
        (async () => {
          const prefix = await resolveOpenerForFile(result.path, result.category);
          if (prefix) {
            if (prefix === "share:") {
              await shareFilePath(result.path, result.name);
            } else if (prefix === "editor:" && specificLine) {
              _navPath.setValue([..._navPath.value, prefix + result.path + "::L" + specificLine]);
            } else {
              _navPath.setValue([..._navPath.value, prefix + result.path]);
            }
          }
        })();
      }
    };

    const deleteFile = async (result: DeepSearchResult) => {
      // 立即从列表移除（乐观更新），再异步删除文件
      deletedPathsRef.current.add(result.path);
      const updated = deepSearchResultsRef.current.filter((r) => r.path !== result.path);
      deepSearchResultsRef.current = updated;
      setDeepSearchResults(updated);
      onResultsChange?.(updated);
      try {
        await FileManager.remove(result.path);
      } catch (e) {
        console.log("删除失败:", e);
      }
    };

    const copyToStorage = async (result: DeepSearchResult) => {
      try {
        await writeClipboardPath(result.path);
        showToast("已复制路径");
      } catch (e) {
        console.log("拷贝失败:", e);
      }
    };

    const copyFilePath = (result: DeepSearchResult) => {
      Clipboard.copyText(result.path);
      showToast("已复制路径");
    };

    /* 包装左滑操作，仅文件真被删除后才更新搜索列表 */
    const wrapTrailingAction = (origAction: () => void | Promise<void>, path: string) => {
      return async () => {
        await origAction();
        // 检查文件是否已被删除（仅对删除操作生效，简介等操作跳过）
        let stillExists = true;
        try {
          stillExists = await FileManager.exists(path);
        } catch {
          // exists() 抛异常也视为已删除
          stillExists = false;
        }
        if (stillExists) return;
        // 文件已删除 → 从搜索列表移除
        deletedPathsRef.current.add(path);
        const updated = deepSearchResultsRef.current.filter((r) => r.path !== path);
        deepSearchResultsRef.current = updated;
        setDeepSearchResults(updated);
        onResultsChange?.(updated);
      };
    };

    const gotoParentDir = (result: DeepSearchResult) => {
      const _navPath = navPathRef.current;
      if (!_navPath) return;
      const parent = result.path.substring(0, result.path.lastIndexOf("/"));
      const fileName = Path.basename(result.path);
      console.log("gotoParentDir:", result.path, "→ parent:", parent, "fileName:", fileName);
      // 用 :: 分隔目录和文件名，NavigationDestination 解析后传给 GeneralBrowser
      const navTarget = "browser:" + parent + "::" + encodeURIComponent(fileName);
      console.log("navTarget:", navTarget);
      _navPath.setValue([..._navPath.value, navTarget]);
    };

    // 按文件分组，支持折叠
    return (
      <Section title={`深度搜索找到 ${deepSearchResults.reduce((s, r) => s + (r.allMatches?.length || 0 || (r.matchedLine ? 1 : 0)), 0)} 个匹配`}>
        {deepSearchResults.map((result) => {
          const matches =
            result.allMatches && result.allMatches.length > 0 ? result.allMatches : result.matchedLine != null ? [{ line: result.matchedLine, content: result.matchedContent || "" }] : [];
          const isExpanded = expandedPaths.has(result.path);
          const hasMatches = matches.length > 0;
          return (
            <Group key={result.path}>
              {hasMatches ? (
                <Button
                  action={() => toggleExpanded(result.path)}
                  contextMenu={{
                    menuItems: (
                      <Group>
                        <Button title="跳转到目录" action={() => gotoParentDir(result)} />
                        <Button title="删除" role="destructive" action={() => deleteFile(result)} />
                        <Button title="拷贝" action={() => copyToStorage(result)} />
                        <Button title="复制文件路径" action={() => copyFilePath(result)} />
                        {!result.isDirectory ? (
                          <Menu title="默认打开方式" systemImage="gear">
                            {OPENER_OPTIONS.map((opt) => (
                              <Button
                                title={opt.label}
                                action={async () => {
                                  setDefaultOpener(Path.extname(result.path), opt.prefix);
                                }}
                              />
                            ))}
                          </Menu>
                        ) : (
                          <EmptyView />
                        )}
                      </Group>
                    ),
                  }}
                  trailingSwipeActions={(() => {
                    const actions = resultTrailingActions?.(result);
                    if (!actions || actions.length === 0) return undefined;
                    return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={wrapTrailingAction(a.action, result.path)} />) };
                  })()}
                  leadingSwipeActions={(() => {
                    const actions = resultLeadingActions?.(result);
                    if (!actions || actions.length === 0) return undefined;
                    return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={a.action} />) };
                  })()}
                >
                  <HStack spacing={12} alignment="center" padding={{ vertical: 6, leading: -9, trailing: 6 }}>
                    <Image
                      systemName="chevron.right"
                      frame={{ width: 12, height: 12 }}
                      foregroundStyle="tertiaryLabel"
                      rotationEffect={{ degrees: isExpanded ? 90 : 0, anchor: "center" }}
                      animation={{ animation: Animation.default(), value: isExpanded }}
                    />
                    <Image systemName={result.icon} frame={{ width: 20, height: 20 }} foregroundStyle={result.iconColor as any} />
                    <VStack alignment="leading" spacing={0}>
                      <Text font="body" lineLimit={1}>
                        {result.name}
                      </Text>
                      <Text font="caption2" foregroundStyle="quaternaryLabel" lineLimit={1}>
                        {result.relativePath}
                      </Text>
                    </VStack>
                    <Spacer />
                    <Text font="caption" foregroundStyle="tertiaryLabel">
                      {matches.length}行
                    </Text>
                  </HStack>
                </Button>
              ) : (
                <Button
                  action={() => navigateToFile(result)}
                  contextMenu={{
                    menuItems: (
                      <Group>
                        <Button title="跳转到目录" action={() => gotoParentDir(result)} />
                        <Button title="删除" role="destructive" action={() => deleteFile(result)} />
                        <Button title="拷贝" action={() => copyToStorage(result)} />
                        <Button title="复制文件路径" action={() => copyFilePath(result)} />
                        {!result.isDirectory ? (
                          <Menu title="默认打开方式" systemImage="gear">
                            {OPENER_OPTIONS.map((opt) => (
                              <Button
                                title={opt.label}
                                action={async () => {
                                  setDefaultOpener(Path.extname(result.path), opt.prefix);
                                }}
                              />
                            ))}
                          </Menu>
                        ) : (
                          <EmptyView />
                        )}
                      </Group>
                    ),
                  }}
                  trailingSwipeActions={(() => {
                    const actions = resultTrailingActions?.(result);
                    if (!actions || actions.length === 0) return undefined;
                    return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={wrapTrailingAction(a.action, result.path)} />) };
                  })()}
                  leadingSwipeActions={(() => {
                    const actions = resultLeadingActions?.(result);
                    if (!actions || actions.length === 0) return undefined;
                    return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={a.action} />) };
                  })()}
                >
                  <HStack spacing={12} alignment="center" padding={{ vertical: 6, leading: 15, trailing: 6 }}>
                    <Image systemName={result.icon} frame={{ width: 20, height: 20 }} foregroundStyle={result.iconColor as any} />
                    <VStack alignment="leading" spacing={0}>
                      <Text font="body" lineLimit={1}>
                        {result.name}
                      </Text>
                      <Text font="caption2" foregroundStyle="quaternaryLabel" lineLimit={1}>
                        {result.relativePath}
                      </Text>
                    </VStack>
                    <Spacer />
                    <Text font="caption" foregroundStyle="tertiaryLabel">
                      0行
                    </Text>
                  </HStack>
                </Button>
              )}
              {isExpanded && hasMatches ? (
                matches.map((m, i) => (
                  <Button
                    key={i}
                    action={() => navigateToFile(result, m.line)}
                    contextMenu={{
                      menuItems: (
                        <Group>
                          <Button title="跳转到目录" action={() => gotoParentDir(result)} />
                          <Button title="删除" role="destructive" action={() => deleteFile(result)} />
                          <Button title="拷贝" action={() => copyToStorage(result)} />
                          <Button title="复制文件路径" action={() => copyFilePath(result)} />
                          {!result.isDirectory ? (
                            <Menu title="默认打开方式" systemImage="gear">
                              {OPENER_OPTIONS.map((opt) => (
                                <Button
                                  title={opt.label}
                                  action={async () => {
                                    setDefaultOpener(Path.extname(result.path), opt.prefix);
                                  }}
                                />
                              ))}
                            </Menu>
                          ) : (
                            <EmptyView />
                          )}
                        </Group>
                      ),
                    }}
                  >
                    <HStack spacing={8} alignment="firstTextBaseline" padding={{ vertical: 6, leading: 6, trailing: 16 }}>
                      <Text font={12} foregroundStyle="tertiaryLabel" frame={{ width: 44, alignment: "trailing" }}>
                        {m.line}
                      </Text>
                      <HighlightedText text={m.content} query={searchQuery} />
                    </HStack>
                  </Button>
                ))
              ) : (
                <EmptyView />
              )}
            </Group>
          );
        })}
      </Section>
    );
  }, [enableDeepSearch, deepSearchResults, expandedPaths, onResultTapRef, navPathRef, searchQuery]);

  return (
    <>
      {/* ── 深度搜索状态栏 ── */}
      {enableDeepSearch && searchQuery.trim() ? (
        <Section listRowSeparator="hidden" padding={{ vertical: 0, horizontal: 0 }}>
          <Button
            action={() => {
              if (deepSearchEnabled) {
                toggleDeepSearch(false);
              } else {
                toggleDeepSearch(true);
              }
            }}
          >
            <HStack spacing={6} alignment="center" padding={{ vertical: 8, horizontal: 16 }}>
              <Image systemName="magnifyingglass.circle" frame={{ width: 16, height: 16 }} foregroundStyle={deepSearchEnabled ? "systemBlue" : "tertiaryLabel"} />
              <Text font="body">深度搜索</Text>
              <Text font="body" foregroundStyle={deepSearchEnabled ? "systemGreen" : "secondaryLabel"}>
                {deepSearchEnabled ? "ON" : "OFF"}
              </Text>

              {deepSearchEnabled && !isBuildingIndex && indexStats ? (
                <Text font="caption" foregroundStyle="tertiaryLabel">
                  文件数 {indexStats.total}
                </Text>
              ) : (
                <EmptyView />
              )}

              {deepSearchEnabled && isBuildingIndex ? (
                <Text font="caption" foregroundStyle="tertiaryLabel">
                  文件 {indexingCount}
                </Text>
              ) : (
                <EmptyView />
              )}

              <Spacer />

              {deepSearchEnabled && !isBuildingIndex ? <Button title="重建索引" action={() => buildDeepSearchIndex(true)} /> : <EmptyView />}

              {deepSearchEnabled && isBuildingIndex ? <Button title="取消索引" action={handleCancelIndexing} /> : <EmptyView />}
            </HStack>
          </Button>
        </Section>
      ) : (
        <EmptyView />
      )}

      {resultsSection}

      {hasMoreResults ? (
        <Group key="load-more">
          <Button
            action={() => {
              if (!isLoadingMore) loadMoreResults();
            }}
          >
            <HStack padding={{ vertical: 12, horizontal: 16 }} alignment="center">
              {isLoadingMore ? (
                <Text font="caption" foregroundStyle="tertiaryLabel">
                  加载中…
                </Text>
              ) : (
                <Text font="caption" foregroundStyle="secondaryLabel">
                  加载更多
                </Text>
              )}
            </HStack>
          </Button>
        </Group>
      ) : (
        <EmptyView />
      )}
    </>
  );
}

export { searchFromIndex, closeDatabase, getIndexStats, buildIndex, cancelBuildIndex };
export type { DeepSearchResult, IndexStats };
