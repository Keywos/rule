// 默认打开方式选择器 - 弹出页面
// 当未知类型的文件被点击时，弹窗让用户选择用哪种方式打开

import {
  Navigation, NavigationStack, Path,
  List, Section, Text, Button,
  VStack, HStack, Image,
} from 'scripting'
import { OPENER_OPTIONS, getDefaultOpener, setDefaultOpener, isKnownCategory, OpenerPrefix } from '../manager/DefaultOpener'
import { ensureLocalFile } from '../manager/utils'

// ============ 选择器页面组件 ============

function OpenerPickerPage({
  ext,
  onSelect,
}: {
  ext: string
  onSelect: (prefix: OpenerPrefix | null) => void
}) {
  const dismiss = Navigation.useDismiss()

  const handleCancel = () => {
    onSelect(null)
    dismiss()
  }

  return (
    <NavigationStack>
      <List
        navigationTitle={`选择 .${ext} 的打开方式`}
        navigationBarTitleDisplayMode="inline"
        toolbar={{
          topBarLeading: [
            <Button title="取消" action={handleCancel} />,
          ],
        }}
      >
        <Section>
          {OPENER_OPTIONS.map((opt) => (
            <Button
              key={opt.prefix}
              action={() => {
                onSelect(opt.prefix)
                dismiss()
              }}
            >
              <HStack spacing={12} alignment="center" padding={8}>
                <Image systemName={openerIcon(opt.prefix)} frame={{ width: 24, height: 24 }} foregroundStyle="systemBlue" />
                <VStack alignment="leading" spacing={2}>
                  <Text font="body">{opt.label}</Text>
                  <Text font="caption" foregroundStyle="secondaryLabel">{openerDescription(opt.prefix)}</Text>
                </VStack>
              </HStack>
            </Button>
          ))}
        </Section>
      </List>
    </NavigationStack>
  )
}

function openerIcon(prefix: OpenerPrefix): string {
  switch (prefix) {
    case 'editor:': return 'chevron.left.forwardslash.chevron.right'
    case 'preview:': return 'doc.text'
    case 'image:': return 'photo'
    case 'video:': return 'video'
    case 'pdf:': return 'doc.richtext'
    case 'webpage:': return 'safari'
    case 'markdown:': return 'doc.text.magnifyingglass'
    case 'archive:': return 'archivebox.fill'
    case 'livephoto:': return 'livephoto'
    case 'extract:': return 'archivebox'
    case 'extractfolder:': return 'folder.badge.gearshape'
    case 'share:': return 'square.and.arrow.up'
  }
}

function openerDescription(prefix: OpenerPrefix): string {
  switch (prefix) {
    case 'editor:': return '使用内置代码编辑器打开'
    case 'preview:': return '使用文件预览查看'
    case 'image:': return '使用图片查看器打开'
    case 'video:': return '使用视频播放器打开'
    case 'pdf:': return '使用系统 PDF 预览器打开'
    case 'webpage:': return '使用内置浏览器预览 HTML 页面'
    case 'markdown:': return '使用系统预览渲染 Markdown 文档'
    case 'archive:': return '在内存中查看压缩文件目录，不解压到磁盘'
    case 'livephoto:': return '使用 Live Photo 查看器打开'
    case 'extract:': return '解压归档文件到当前目录'
    case 'extractfolder:': return '解压到以文件名命名的子文件夹'
    case 'share:': return '使用系统分享菜单打开'
  }
}

// ============ 对外接口 ============

/** 展示默认打开方式选择器弹窗，返回用户选择的 prefix，取消返回 null */
export function showOpenerPicker(ext: string): Promise<OpenerPrefix | null> {
  return new Promise((resolve) => {
    Navigation.present({
      element: <OpenerPickerPage ext={ext} onSelect={(prefix) => resolve(prefix)} />,
      modalPresentationStyle: 'pageSheet',
    })
  })
}

/** 获取某个扩展名当前的默认打开方式的中文标签，没有则返回 null */
export async function getCurrentOpenerLabel(ext: string): Promise<string | null> {
  const saved = await getDefaultOpener(ext)
  if (!saved) return null
  const opt = OPENER_OPTIONS.find(o => o.prefix === saved)
  return opt ? opt.label : null
}

/**
 * 处理文件打开：如果文件类型有专用处理器则直接返回 prefix，
 * 否则查询/弹窗默认打开方式。
 * 
 * @param filePath 文件路径
 * @param category 文件分类（来自 getFileCategory）
 * @returns 打开的 prefix，或 null（用户取消）
 */
export async function resolveOpenerForFile(
  filePath: string,
  category: string,
): Promise<OpenerPrefix | null> {
  // iCloud 仅云端文件先下载再打开（FileManager.downloadFileFromiCloud）
  await ensureLocalFile(filePath)

  const ext = Path.extname(filePath)

  // livephoto 只能用专用处理器，ImageViewer/VideoViewer 无法处理
  if (category === 'livephoto') {
    return 'livephoto:'
  }

  // 先检查是否有用户手动设置的默认打开方式（优先于内置映射）
  const saved = await getDefaultOpener(ext)
  if (saved) return saved

  // .html/.htm 文件默认使用网页预览（而非代码编辑器）
  if (ext === '.html' || ext === '.htm') {
    return 'webpage:'
  }

  // .md 文件默认使用 Markdown 预览
  if (ext === '.md' || ext === '.markdown') {
    return 'markdown:'
  }

  // 已有专用处理器的类型（无用户默认时）
  if (category === 'text' || category === 'code' || category === 'data') {
    return 'editor:'
  }
  if (category === 'image') {
    return 'image:'
  }
  if (category === 'pdf') {
    return 'pdf:'
  }

  if (category === 'video') {
    return 'video:'
  }

  // 未知类型：弹窗让用户选择
  if (!isKnownCategory(category)) {
    const chosen = await showOpenerPicker(ext)
    if (chosen) {
      setDefaultOpener(ext, chosen)
      return chosen
    }
    return null
  }

  // 压缩文件默认以内存方式读取并查看目录
  if (category === 'archive') {
    return 'archive:'
  }

  // 其他已知类型（audio）默认预览
  return 'preview:'
}
