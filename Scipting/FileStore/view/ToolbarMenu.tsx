// 通用工具栏菜单组件 — 三点按钮弹出菜单，支持选择、排序（切换按钮）、筛选（单选 radio）

import { Menu, Button, Divider } from 'scripting'
import {FilterOption, SortOrder, resolveSortOrder, FILE_SORT_TOGGLES, FILE_FILTER_OPTIONS } from '../manager/sortFilter'

/* ─── 选择模式配置 ─── */
export interface SelectModeConfig {
  /** 是否启用选择模式功能 */
  enabled: boolean
  /** 当前是否处于选择模式 */
  isSelectMode: boolean
  /** 切换选择模式 */
  onToggleSelectMode: () => void
  /** 全选 */
  onSelectAll?: () => void
  /** 取消选择 */
  onDeselectAll?: () => void
  /** 已选数量 */
  selectedCount?: number
  /** 删除选中 */
  onDeleteSelected?: () => void
  /** 移动选中 */
  onMoveSelected?: () => void
  /** 复制路径 */
  onCopyPaths?: () => void
  /** 导出选中到相册 */
  onExportPhotos?: () => void
  /** 拷贝选中（记住路径） */
  onCopyToClipboard?: () => void
  /** 压缩选中 */
  onCompressSelected?: () => void
}

/* ─── 排序配置 ─── */
export interface SortConfig {
  /** 当前排序（如 'modified-asc'） */
  sortOrder: SortOrder
  /** 排序变更回调 */
  onSortChange: (order: SortOrder) => void
}

/* ─── 筛选配置 ─── */
export interface FilterConfig<F extends string = string> {
  /** 当前筛选类型 */
  filterType: F
  /** 筛选变更回调 */
  onFilterChange: (type: F) => void
  /** 筛选选项列表（默认使用 FILE_FILTER_OPTIONS） */
  filterOptions?: FilterOption[]
}

/* ─── 菜单配置 ─── */
export interface ToolbarMenuProps<F extends string = string> {
  /** 选择模式配置（可选） */
  selectMode?: SelectModeConfig
  /** 排序配置 */
  sort?: SortConfig
  /** 筛选配置（可选） */
  filter?: FilterConfig<F>
  /** 额外的菜单项 - 排在筛选之后（可选） */
  extraItems?: any
  /** 底部的菜单项（可选），如"新建文件" */
  otherItems?: any
  /** 最底部的菜单项（可选），显示在筛选之后，如"设置" */
  bottomItem?: any
}

export function ToolbarMenu<F extends string = string>({
  selectMode,
  sort,
  filter,
  extraItems,
  otherItems,
  bottomItem,
}: ToolbarMenuProps<F>) {
  const hasSelectMode = selectMode?.enabled
  const hasSort = !!sort
  const filterOptions = filter?.filterOptions ?? FILE_FILTER_OPTIONS
  const hasFilter = !!(filter && filterOptions.length > 0)

  return (
    <Menu title="" systemImage="ellipsis">
      {/* ─── 选择模式 ─── */}
      {hasSelectMode && (
        <>
          <Button
            title={selectMode.isSelectMode ? "完成选择" : "选择"}
            systemImage="checkmark.circle"
            action={selectMode.onToggleSelectMode}
          />
          {selectMode.isSelectMode && (
            <>
              <Button title="全选" action={selectMode.onSelectAll ?? (() => {})} />
              <Button title="取消选择" action={selectMode.onDeselectAll ?? (() => {})} />
            </>
          )}
        </>
      )}

      {/* ─── 选择模式下的操作 ─── */}
      {hasSelectMode && selectMode.isSelectMode && selectMode.selectedCount !== undefined && selectMode.selectedCount > 0 && (
        <>
          <Divider />
          <Button title={`压缩 ${selectMode.selectedCount} 项`} systemImage="archivebox" action={selectMode.onCompressSelected ?? (() => {})} />
          <Button title="删除选中" systemImage="trash" role="destructive" action={selectMode.onDeleteSelected ?? (() => {})} />
          <Button title={`移动 ${selectMode.selectedCount} 项`} systemImage="folder" action={selectMode.onMoveSelected ?? (() => {})} />
          <Button title="复制路径" systemImage="doc.on.doc" action={selectMode.onCopyPaths ?? (() => {})} />
          <Button title="导出到相册" systemImage="square.and.arrow.down" action={selectMode.onExportPhotos ?? (() => {})} />
          <Button title="拷贝" systemImage="arrow.right.doc.on.clipboard" action={selectMode.onCopyToClipboard ?? (() => {})} />
        </>
      )}

      {/* ─── 额外菜单项（导入/新建等） ─── */}
      {extraItems && (
        <>
          <Divider />
          {extraItems}
        </>
      )}

      {/* ─── 排序（切换按钮） ─── */}
      {hasSort && (
        <>
          <Divider />
          {FILE_SORT_TOGGLES.map(toggle => {
            const isActive = sort!.sortOrder.startsWith(toggle.key)
            const currentDir = isActive ? sort!.sortOrder.split('-')[1] : 'asc'
            const displayedTitle = toggle.togglable
              ? `${toggle.title} (${currentDir === 'asc' ? '最旧' : '最新'})`
              : toggle.title
            return (
              <Button
                key={toggle.key}
                title={displayedTitle}
                systemImage={isActive ? 'checkmark' : toggle.systemImage}
                action={() => {
                  sort!.onSortChange(resolveSortOrder(sort!.sortOrder, toggle.key))
                }}
              />
            )
          })}
        </>
      )}

      {/* ─── 底部菜单项（如"新建文件"） ─── */}
      {otherItems && (
        <>
          <Divider />
          {otherItems}
        </>
      )}

      {/* ─── 筛选（单选 radio） ─── */}
      {hasFilter && (
        <>
          <Divider />
          {filterOptions.map(opt => {
            const isSelected = filter!.filterType === opt.key
            return (
              <Button
                key={opt.key}
                title={`${isSelected ? '● ' : '○ '}${opt.title}`}
                systemImage={isSelected ? 'checkmark.circle.fill' : opt.systemImage}
                action={() => filter!.onFilterChange(opt.key as F)}
              />
            )
          })}
        </>
      )}

      {/* ─── 最底部菜单项（如"设置"） ─── */}
      {bottomItem && (
        <>
          <Divider />
          {bottomItem}
        </>
      )}
    </Menu>
  )
}
