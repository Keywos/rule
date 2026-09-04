// 设置标签 - 核心功能一览 + 应用设置
// 汇集：9 项核心功能入口，以及原 SettingsPage 的显示模式

import { NavigationStack, List, Section, Text, Button, Toggle, HStack, VStack, Spacer, Image, EmptyView, Rectangle, useState, useEffect } from "scripting";
import { AppSettings } from "../manager/Settings";
import { Bookmark }from "../manager/BookmarkManager";
import { getMaxIndexFileSizeKB, setMaxIndexFileSizeKB } from "../manager/SearchState";
import { getServerCount, subscribe as subscribeHttpServers } from "../manager/LocalHttpServer";
import { resetAllDefaultOpeners } from "../manager/DefaultOpener";
import { showToast } from "../manager/ToastManager";

interface SettingsTabPageProps {
  settings: AppSettings;
  onSettingsChange: (newSettings: AppSettings) => void;
  bookmarks?: Bookmark[];
  onSwitchTab?: (index: number) => void;
}

/* ───── 功能行：图标 + 标题 + 描述，可选点击跳转 ───── */
type FeatureIconColor = "systemBlue" | "systemGreen" | "systemOrange" | "systemPurple" | "systemTeal" | "systemPink" | "systemBrown" | "systemIndigo";

function FeatureRow({
  icon,
  iconColor,
  title,
  caption,
  action,
  hideTopSeparator,
}: {
  icon: string;
  iconColor?: FeatureIconColor;
  title: string;
  caption: string;
  action?: () => void;
  hideTopSeparator?: boolean;
}) {
  const content = (
    <HStack spacing={12} alignment="center" padding={8} listRowSeparator={hideTopSeparator ? { visibility: "hidden", edges: "top" } : undefined}>
      <Image systemName={icon} frame={{ width: 26, height: 26 }} foregroundStyle={iconColor ?? "systemBlue"} />
      <VStack alignment="leading" spacing={2}>
        <Text font="body">{title}</Text>
        <Text font="caption2" monospaced foregroundStyle="secondaryLabel">{caption}</Text>
      </VStack>
      <Spacer />
      {action ? (
        <Image systemName="chevron.right" frame={{ width: 12, height: 12 }} foregroundStyle="systemGray" />
      ) : (
        <EmptyView />
      )}
    </HStack>
  );
  return action ? (
    <Button action={action} listRowSeparator={hideTopSeparator ? { visibility: "hidden", edges: "top" } : undefined}>
      {content}
    </Button>
  ) : (
    content
  );
}

export function SettingsTabPage({ settings, onSettingsChange, bookmarks, onSwitchTab }: SettingsTabPageProps) {
  // 本地状态，修改后立即更新显示
  const [maxFileSizeKB, setMaxFileSizeKB] = useState(getMaxIndexFileSizeKB());
  const [serverCount, setServerCount] = useState(getServerCount());

  // 本地 HTTP 服务数量变化时刷新
  useEffect(() => subscribeHttpServers(() => setServerCount(getServerCount())), []);

  /** 合并部分设置 → 保存 + 通知父级刷新 */
  const update = (updates: Partial<AppSettings>) => {
    onSettingsChange({ ...settings, ...updates });
  };

  /* ── 默认打开方式：重置 ── */
  const handleResetOpeners = async () => {
    const confirmed = await Dialog.confirm({
      title: "重置默认打开方式",
      message: "将清除所有扩展名记忆的打开方式，之后点击未知类型文件会重新询问。",
      cancelLabel: "取消",
      confirmLabel: "重置",
    });
    if (!confirmed) return;
    resetAllDefaultOpeners();
    showToast("已重置默认打开方式");
  };

  /* ── 深度搜索：索引最大文件限制（同原 SettingsPage） ── */
  const handleSetMaxIndexSize = async () => {
    const result = await Dialog.prompt({
      title: "最大文件限制",
      message: "输入文件大小限制（KB），大于此值的文件不会被索引",
      defaultValue: String(maxFileSizeKB),
      placeholder: "50",
      confirmLabel: "保存",
      cancelLabel: "取消",
    });
    if (result != null && result.trim()) {
      const val = parseInt(result.trim());
      if (!isNaN(val) && val > 0) {
        setMaxIndexFileSizeKB(val);
        setMaxFileSizeKB(val);
      }
    }
  };

  const mountedCount = bookmarks?.length ?? 0;

  return (
    <NavigationStack>
      <List
        listStyle="plain" 
        scrollContentBackground="hidden"
        navigationTitle="设置"
      >
        {/* ── 核心功能一览 ── */}
        {/* <Section title=""> */}
          <FeatureRow
            icon="tray.2.fill"
            iconColor="systemGreen"
            title="1. 目录挂载（书签）"
            caption={`持久书签，重启后按需恢复路径 · 已挂载 ${mountedCount} 个目录`}
            action={() => onSwitchTab?.(1)}
            hideTopSeparator
          />
          <FeatureRow
            icon="rectangle.split.2x1"
            title="2. 双栏浏览"
            caption="左右/上下双栏，跨栏复制，可拖拽调整比例、点击拖拽条可调整分栏方向、左上角图标 R 可以切换单/双栏模式"
            action={() => onSwitchTab?.(0)}
          />
          <FeatureRow
            icon="textformat"
            iconColor="systemOrange"
            title="3. 多编码文本读取"
            caption="脚本编辑器自动识别 UTF-8 / GBK / UTF-16 / Shift-JIS 等编码、还支持JS Terser 压缩 / 格式化等"
          />
          <FeatureRow
            icon="photo.on.rectangle.angled"
            iconColor="systemPurple"
            title="4. 多媒体预览"
            caption="图片、视频、实况照片、压缩包修改、预览、PDF、HTML 网页、Markdown、SVG"
          />
          <FeatureRow
            icon="magnifyingglass"
            title="5. 深度搜索"
            caption={`SQLite 索引 + 文本内容搜索/可以跳转到文本的某行 · 索引限制 ${maxFileSizeKB} KB，点此修改`}
            action={handleSetMaxIndexSize}
          />
          <FeatureRow
            icon="network"
            iconColor="systemTeal"
            title="6. 本地 HTTP 服务"
            caption={serverCount > 0 ? `目录转局域网静态服务，后台保活 · 运行中 ${serverCount} 个` : "目录转局域网静态服务，后台保活 · 当前未运行"}
          />
          <FeatureRow
            icon="arrow.right.doc.on.clipboard"
            iconColor="systemPink"
            title="7. 默认打开方式"
            caption="按扩展名记忆打开方式，长按文件可选默认打开方式，点此一键重置"
            action={handleResetOpeners}
          />
          <FeatureRow
            icon="square.and.arrow.down"
            iconColor="systemBrown"
            title="8. 拖放支持"
            caption="拖放照片、文件、文本等到目标目录，App 外拖动进来可以拖到当前目录的搜索栏、标题栏"
          />
          <FeatureRow
            icon="square.grid.2x2"
            iconColor="systemIndigo"
            title="9. 桌面模式"
            caption="主屏双栏浏览 UI，左上角可以切换单、双栏模式，一键打开 FileStore"
          />
          <FeatureRow
            icon="square.grid.2x2"
            iconColor="systemIndigo"
            title="10. 压缩文件/查看/解压缩"
            caption="查看 / 修改 / 解压缩 加密 ZIP / 7z AES256"
          />
        {/* </Section> */}

        {/* ── 显示模式（原 SettingsPage） ── */}
        <Section header={<Text padding={{ leading: 20, trailing: 5 }}>显示模式</Text>}>
          <Toggle title="显示文件夹内项目个数" value={settings.showFolderItemCounts ?? true} onChanged={(value: boolean) => update({ showFolderItemCounts: value })} listRowInsets={{ top: 0, bottom: 0, leading: 30, trailing: 10 }} />
          <Toggle title="滑动时隐藏TAB" value={settings.tabBarMinimizeOnScroll ?? true} onChanged={(value: boolean) => update({ tabBarMinimizeOnScroll: value })} listRowInsets={{ top: 0, bottom: 0, leading: 30, trailing: 10 }} />
          <Toggle title="独立显示退出按钮" value={settings.showExitButton} onChanged={(value: boolean) => update({ showExitButton: value })} listRowInsets={{ top: 0, bottom: 0, leading: 30, trailing: 10 }} />
        </Section>

        {/* ── 底部留白 ── */}
        <HStack frame={{ maxWidth: "infinity", height: 60 }} listRowBackground={<Rectangle fill="clear" />} listRowSeparator={{ visibility: "hidden", edges: "all" }}>
          <EmptyView />
        </HStack>
      </List>
    </NavigationStack>
  );
}
