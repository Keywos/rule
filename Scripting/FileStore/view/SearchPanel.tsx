// 通用搜索面板组件 - 深度搜索功能

import { Section, HStack, VStack, Spacer, Text, Image, Button, useState, useEffect, useRef, useMemo, VirtualNode, Group, Menu, Path, StyledText, EmptyView } from "scripting";
import { buildIndex, searchFromIndex, DeepSearchResult, getIndexStats, IndexStats, isIndexValid, cancelBuildIndex, closeDatabase } from "../manager/DeepSearch";
import { setDeepSearchPref, getDeepSearchPref } from "../manager/SearchState";
import { writeClipboardPath, shareFilePath, ensureLocalFile } from "../manager/utils";
import { ContextMenuItem } from "./FileListItem";
import { resolveOpenerForFile } from "./DefaultOpenerPicker";
import { setDefaultOpener, OPENER_OPTIONS } from "../manager/DefaultOpener";
import { showToast } from "../manager/ToastManager";

interface SearchPanelProps {
  searchQuery: string;
  dirPath: string;
  enableDeepSearch?: boolean;
  destinationForResult?: (result: DeepSearchResult) => VirtualNode;
  onResultTap?: (result: DeepSearchResult) => void;
  showSize?: boolean;
  onResultsChange?: (results: DeepSearchResult[]) => void;
  navPath?: any;
  onNavigateToParentDirectory?: (result: DeepSearchResult) => void;
  resultLeadingActions?: (result: DeepSearchResult) => ContextMenuItem[];
  resultTrailingActions?: (result: DeepSearchResult) => ContextMenuItem[];
  resultContextMenuItems?: (result: DeepSearchResult) => ContextMenuItem[];
}

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

export function SearchPanel({
  searchQuery,
  dirPath,
  enableDeepSearch = true,
  destinationForResult,
  onResultTap,
  onResultsChange,
  navPath,
  onNavigateToParentDirectory,
  resultLeadingActions,
  resultTrailingActions,
  resultContextMenuItems
}: SearchPanelProps) {
  const [deepSearchResults, setDeepSearchResults] = useState<DeepSearchResult[]>([]);
  const deepSearchResultsRef = useRef<DeepSearchResult[]>(deepSearchResults);
  deepSearchResultsRef.current = deepSearchResults;
  
  const [deepSearchEnabled, setDeepSearchEnabled] = useState(false);
  const [isBuildingIndex, setIsBuildingIndex] = useState(false);
  const [indexStats, setIndexStats] = useState<IndexStats | null>(null);
  const [indexingCount, setIndexingCount] = useState(0);
  const indexingCountRef = useRef(0);

  const [searchOffset, setSearchOffset] = useState(0);
  const [hasMoreResults, setHasMoreResults] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const pageSize = 200;

  const deletedPathsRef = useRef(new Set<string>());
  const searchSeqRef = useRef(0);

  const lastIndexingRenderRef = useRef(0);
  const lastIndexingTimeRef = useRef(0);

  const flushIndexingProgress = () => {
    setIndexingCount(indexingCountRef.current);
    lastIndexingRenderRef.current = indexingCountRef.current;
    lastIndexingTimeRef.current = Date.now();
  };

  const maybeReportIndexingProgress = () => {
    const count = indexingCountRef.current;
    const now = Date.now();
    if (count - lastIndexingRenderRef.current >= 50 || now - lastIndexingTimeRef.current >= 100) {
      flushIndexingProgress();
    }
  };

  const deepSearchInitedRef = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      cancelBuildIndex();
    };
  }, []);

  useEffect(() => {
    if (!deepSearchEnabled || deepSearchInitedRef.current || !dirPath) return;
    deepSearchInitedRef.current = true;
    (async () => {
      try {
        const stats = await getIndexStats(dirPath);
        if (!mountedRef.current) return;
        setIndexStats(stats);
        if (stats.total === 0 || !(await isIndexValid(dirPath))) {
          setIsBuildingIndex(true);
          try {
            await buildIndex(dirPath, (count) => {
              indexingCountRef.current = count;
              maybeReportIndexingProgress();
            });
            if (!mountedRef.current) return;
            const freshStats = await getIndexStats(dirPath);
            if (!mountedRef.current) return;
            setIsBuildingIndex(false);
            setIndexStats(freshStats);
          } catch (buildErr) {
            console.log("自动构建索引失败:", buildErr);
            if (!mountedRef.current) return;
            setIsBuildingIndex(false);
          }
        }
      } catch {}
    })();
  }, [deepSearchEnabled]);

  const buildDeepSearchIndex = async (forceRebuild: boolean = false) => {
    setIsBuildingIndex(true);
    setIndexingCount(0);
    indexingCountRef.current = 0;
    lastIndexingRenderRef.current = 0;
    lastIndexingTimeRef.current = 0;
    try {
      await buildIndex(
        dirPath,
        (count) => {
          indexingCountRef.current = count;
          maybeReportIndexingProgress();
        },
        forceRebuild,
      );
      if (!mountedRef.current) return;
      flushIndexingProgress();
      const stats = await getIndexStats(dirPath);
      setIndexStats(stats);
      if (searchQuery.trim()) {
        await performDeepSearch(searchQuery);
      }
    } catch (e) {
      console.log("构建索引失败:", e);
    } finally {
      if (mountedRef.current) setIsBuildingIndex(false);
    }
  };

  const performDeepSearch = async (query: string, append: boolean = false) => {
    const currentDirPath = dirPath;
    if (!query.trim()) {
      setSearchOffset(0);
      setHasMoreResults(false);
      notifyResults([]);
      return;
    }
    const seq = ++searchSeqRef.current;
    try {
      const offset = append ? searchOffset : 0;
      const results = await searchFromIndex(currentDirPath, query, pageSize, offset);
      if (seq !== searchSeqRef.current) return;
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

  const notifyResults = (results: DeepSearchResult[]) => {
    const filtered = results.filter((r) => !deletedPathsRef.current.has(r.path));
    setDeepSearchResults(filtered);
    deepSearchResultsRef.current = filtered;
    onResultsChange?.(filtered);
  };

  const toggleDeepSearch = async (enabled: boolean) => {
    setDeepSearchEnabled(enabled);
    if (enabled) deepSearchInitedRef.current = true;
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

  useEffect(() => {
    if (searchQuery.trim() && !deepSearchEnabled && dirPath && getDeepSearchPref(dirPath)) {
      setDeepSearchEnabled(true);
    }
  }, [searchQuery]);

  useEffect(() => {
    if (deepSearchEnabled && searchQuery.trim()) {
      const timer = setTimeout(() => {
        performDeepSearch(searchQuery);
      }, 300);
      return () => {
        searchSeqRef.current++;
        clearTimeout(timer);
      };
    } else if (deepSearchEnabled && !searchQuery.trim()) {
      searchSeqRef.current++;
      notifyResults([]);
    }
  }, [searchQuery, deepSearchEnabled]);

  useEffect(() => {
    if (!searchQuery.trim()) {
      searchSeqRef.current++;
      setDeepSearchResults([]);
      deepSearchResultsRef.current = [];
      setSearchOffset(0);
      setHasMoreResults(false);
    }
  }, [searchQuery]);

  const handleCancelIndexing = () => {
    cancelBuildIndex();
    setIsBuildingIndex(false);
    setIndexingCount(0);
  };

  const navPathRef = useRef(navPath);
  const onResultTapRef = useRef(onResultTap);
  navPathRef.current = navPath;
  onResultTapRef.current = onResultTap;
  const navigatingRef = useRef<string | null>(null);

  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const toggleExpanded = (path: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const resultsSection = useMemo(() => {
    if (!enableDeepSearch || deepSearchResults.length === 0) return <EmptyView />;

    const navigateToFile = async (result: DeepSearchResult, specificLine?: number) => {
      const path_ = result.path;
      if (navigatingRef.current === path_) return;
      navigatingRef.current = path_;
      setTimeout(() => {
        navigatingRef.current = null;
      }, 1000);

      const _onResultTap = onResultTapRef.current;
      const _navPath = navPathRef.current;

      if (result.isDirectory) {
        if (_onResultTap) {
          _onResultTap(result);
        } else if (_navPath) {
          _navPath.setValue([..._navPath.value, "browser:" + result.path]);
        }
        return;
      }

      showToast("正在准备文件...");
      const downloaded = await ensureLocalFile(result.path, 12000);
      if (!downloaded) {
        showToast("iCloud 文件下载超时或失败，请稍后重试");
        return;
      }

      if (_onResultTap) {
        _onResultTap(specificLine ? { ...result, matchedLine: specificLine } : result);
      } else if (_navPath) {
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
      }
    };

    const deleteFile = async (result: DeepSearchResult) => {
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

    const wrapTrailingAction = (origAction: () => void | Promise<void>, path: string) => {
      return async () => {
        await origAction();
        let stillExists = true;
        try {
          stillExists = await FileManager.exists(path);
        } catch {
          stillExists = false;
        }
        if (stillExists) return;
        deletedPathsRef.current.add(path);
        const updated = deepSearchResultsRef.current.filter((r) => r.path !== path);
        deepSearchResultsRef.current = updated;
        setDeepSearchResults(updated);
        onResultsChange?.(updated);
      };
    };

    const gotoParentDir = (result: DeepSearchResult) => {
      if (onNavigateToParentDirectory) {
        onNavigateToParentDirectory(result);
        return;
      }
      const _navPath = navPathRef.current;
      if (!_navPath) return;
      const parent = result.path.substring(0, result.path.lastIndexOf("/"));
      const fileName = Path.basename(result.path);
      const navTarget = "browser:" + parent + "::" + encodeURIComponent(fileName);
      _navPath.setValue([..._navPath.value, navTarget]);
    };

     const renderContextMenu = (result: DeepSearchResult) => {
      const customItems = resultContextMenuItems?.(result);

      // 1. 如果外部传入了自定义菜单（通常已包含 删除、重命名、分享 等）
    /*   if (customItems && customItems.length > 10) {
        const hasGotoDir = customItems.some((item) => item.title === "跳转到目录");
        return (
          <Group>
          
            {!hasGotoDir && (
              <Button title="跳转到目录" action={() => gotoParentDir(result)} />
            )}
            {customItems.map((item, idx) => (
              <Button key={idx} title={item.title} role={item.role} action={item.action} />
            ))}
          </Group>
        );
      } */

      // 2. 未传入自定义菜单时，使用默认的完整菜单
      return (
        <Group>
          <Button title="跳转到目录" action={() => gotoParentDir(result)} />
       {/*    <Button title="删除" role="destructive" action={() => deleteFile(result)} /> */}
          <Button title="拷贝" action={() => copyToStorage(result)} />
          <Button title="复制文件路径" action={() => copyFilePath(result)} />
          {!result.isDirectory ? (
            <Menu title="默认打开方式" systemImage="gear">
              {OPENER_OPTIONS.map((opt) => (
                <Button
                  key={opt.prefix}
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
      );
    };

    return (
      <Section monospaced title={`深度搜索找到 ${deepSearchResults.reduce((s, r) => s + (r.allMatches?.length || 0 || (r.matchedLine ? 1 : 0)), 0)} 个匹配`}>
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
                  buttonStyle="plain"
                  frame={{ maxWidth: "infinity", alignment: "leading" }}
                  contentShape="rect"
                  contextMenu={{ menuItems: renderContextMenu(result) }}
                  trailingSwipeActions={(() => {
                    const actions = resultTrailingActions?.(result);
                    if (!actions || actions.length === 0) return undefined;
                    return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={wrapTrailingAction(a.action, result.path)} />) };
                  })()}
                  leadingSwipeActions={(() => {
                    const actions = resultLeadingActions?.(result);
                    if (actions && actions.length > 0) {
                      return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={a.action} />) };
                    }
                    return {
                      actions: [<Button title="跳转到目录" action={() => gotoParentDir(result)} />]
                    };
                  })()}
                >
                  <HStack spacing={0} alignment="center" frame={{ maxWidth: "infinity", alignment: "leading" }} contentShape="rect">
                    <HStack frame={{ width: 28, height: 32 }} alignment="center">
                      <Image
                        systemName="chevron.right"
                        frame={{ width: 12, height: 12 }}
                        foregroundStyle="tertiaryLabel"
                        rotationEffect={{ degrees: isExpanded ? 90 : 0, anchor: "center" }}
                        animation={{ animation: Animation.default(), value: isExpanded }}
                      />
                    </HStack>
                    <HStack spacing={12} alignment="center" padding={{ vertical: 6, leading: 0, trailing: 12 }}>
                      <Image systemName={result.icon} frame={{ width: 20, height: 20 }} foregroundStyle={result.iconColor as any} />
                      <VStack alignment="leading" spacing={0}>
                        <Text font="body" lineLimit={1}>
                          {result.name}
                        </Text>
                        <Text font="caption2" monospaced foregroundStyle="quaternaryLabel" lineLimit={1}>
                          {result.relativePath}
                        </Text>
                      </VStack>
                      <Spacer />
                      <Text font="caption" foregroundStyle="tertiaryLabel">
                        {matches.length}行
                      </Text>
                    </HStack>
                  </HStack>
                </Button>
              ) : (
                <Button
                  action={() => navigateToFile(result)}
                  buttonStyle="plain"
                  frame={{ maxWidth: "infinity", alignment: "leading" }}
                  contentShape="rect"
                  contextMenu={{ menuItems: renderContextMenu(result) }}
                  trailingSwipeActions={(() => {
                    const actions = resultTrailingActions?.(result);
                    if (!actions || actions.length === 0) return undefined;
                    return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={wrapTrailingAction(a.action, result.path)} />) };
                  })()}
                  leadingSwipeActions={(() => {
                    const actions = resultLeadingActions?.(result);
                    if (actions && actions.length > 0) {
                      return { actions: actions.map((a) => <Button title={a.title} role={a.role} action={a.action} />) };
                    }
                    return {
                      actions: [<Button title="跳转到目录" action={() => gotoParentDir(result)} />]
                    };
                  })()}
                >
                  <HStack spacing={0} alignment="center" frame={{ maxWidth: "infinity", alignment: "leading" }} contentShape="rect">
                    <HStack frame={{ width: 28, height: 32 }} alignment="center" />
                    <HStack spacing={12} alignment="center" padding={{ vertical: 6, leading: 0, trailing: 12 }}>
                      <Image systemName={result.icon} frame={{ width: 20, height: 20 }} foregroundStyle={result.iconColor as any} />
                      <VStack alignment="leading" spacing={0}>
                        <Text font="body" lineLimit={1}>
                          {result.name}
                        </Text>
                        <Text font="caption2" monospaced foregroundStyle="quaternaryLabel" lineLimit={1}>
                          {result.relativePath}
                        </Text>
                      </VStack>
                      <Spacer />
                    </HStack>
                  </HStack>
                </Button>
              )}

              {isExpanded && hasMatches ? (
                matches.map((m, i) => (
                  <Button
                    key={i}
                    action={() => navigateToFile(result, m.line)}
                    buttonStyle="plain"
                    listRowInsets={0}
                    contentShape="rect"
                    contextMenu={{ menuItems: renderContextMenu(result) }}
                  >
                    <HStack spacing={8} alignment="firstTextBaseline" padding={{ vertical: 6, leading: 36, trailing: 16 }} frame={{ maxWidth: "infinity", alignment: "leading" }} contentShape="rect">
                      <Text font={12} monospaced foregroundStyle="tertiaryLabel" frame={{ width: 44, alignment: "trailing" }}>
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
                <Text font="caption" monospaced foregroundStyle="tertiaryLabel">
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
