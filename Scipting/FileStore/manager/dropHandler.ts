// 拖拽放置处理工具 — 从外部 App 拖入文件/文本/URL 到本应用的目录
// 配合 GeneralBrowser、MountDirectoriesPage 的 onDrop 使用

import { Path } from 'scripting'
import { ensureDir, makeTimestamp } from './importHelpers'

// 接受的 UTType — 覆盖文件、URL、文本、图片

// 最近一次应用内拖拽的源文件路径（用于在拖放目标端获取原始文件名）
let _dragSourcePath: string | null = null

export function setDragSourcePath(path: string | null) {
  _dragSourcePath = path
}

export function getDragSourcePath(): string | null {
  return _dragSourcePath
}

export const DROP_ACCEPTED_TYPES: UTType[] = [
  "public.item",
  "public.content",
  "public.data",
  "public.file-url",
  "public.folder",
  "public.directory",
  "public.url",
  "public.text",
  "public.plain-text",
  "public.utf8-plain-text",
  "public.image",
]

// 仅文件类型（用于文件导入兜底）
const FILE_TYPES: UTType[] = ["public.item", "public.content", "public.data", "public.file-url", "public.folder", "public.directory"]

/**
 * 把从外部拖入的项目导入到指定目录。
 * 需在 performDrop 回调内同步调用（读取动作必须在 performDrop 返回前启动）。
 * 注意：必须先在 performDrop 中同步调用 info.itemProviders() 获取 providers，
 * 再传入此函数进行异步读取，否则 DropInfo 会在 performDrop 返回后失效。
 */
export async function handleDropToDirectory(
  info: DropInfo,
  dirPath: string,
  onRefresh: () => void,
): Promise<string[]> {
  console.log('handleDropToDirectory called, dirPath:', dirPath)
  //  必须在任何 await 之前同步调用 itemProviders（performDrop 返回后 DropInfo 失效）
  const providers = info.itemProviders(DROP_ACCEPTED_TYPES)
  console.log('handleDropToDirectory: providers count:', providers.length)
  if (providers.length === 0) return []

  // 不在此等待目录创建：handleItemProvidersToDirectory 会立即启动 Provider 读取，
  // 并仅在写入前等待目录就绪。
  return handleItemProvidersToDirectory(providers, dirPath, onRefresh)
}

export async function handleItemProvidersToDirectory(
  providers: ItemProvider[],
  dirPath: string,
  onRefresh: () => void,
): Promise<string[]> {
  console.log('handleItemProvidersToDirectory called, dirPath:', dirPath, 'providers:', providers.length)
  if (providers.length === 0) return []

  // Provider 读取必须在 perform 回调内立即启动；目录创建承诺会在实际落盘前等待，
  // 因此既不破坏系统拖放生命周期，也不会在首次创建目录时抢先写入。
  const directoryReady = ensureDir(dirPath)
  const results = providers.map((provider, index) =>
    readAndImportProvider(provider, dirPath, index, directoryReady)
  )

  const imported = await Promise.allSettled(results)
  const successPaths: string[] = []
  imported.forEach(r => {
    if (r.status === 'fulfilled' && r.value) {
      successPaths.push(r.value)
    }
  })
  if (successPaths.length > 0) {
    onRefresh()
  }
  return successPaths
}

/**
 * 读取单个 ItemProvider 并保存到目标目录
 */
async function readAndImportProvider(
  provider: ItemProvider,
  dirPath: string,
  index: number,
  directoryReady: Promise<void>,
): Promise<string | null> {
  const ts = makeTimestamp()

  // ─── 0. 应用内拖拽：直接从记录的源路径复制文件（跳过 ItemProvider）───
  const dragSource = getDragSourcePath()
  if (dragSource) {
    setDragSourcePath(null)
    await directoryReady
    const name = Path.basename(dragSource)
    const dest = Path.join(dirPath, name)
    if (await FileManager.exists(dest)) {
      const ext = Path.extname(name)
      const body = Path.basename(name, ext)
      const renamed = `${body}_${ts}${ext}`
      const destPath = Path.join(dirPath, renamed)
      await FileManager.copyFile(dragSource, destPath)
      console.log(`应用内拖拽文件: ${name} -> ${dirPath}`)
      return destPath
    } else {
      await FileManager.copyFile(dragSource, dest)
      console.log(`应用内拖拽文件: ${name} -> ${dirPath}`)
      return dest
    }
  }

  const types = provider.registeredTypes || []

  // ─── 1. 优先尝试 loadFilePath（其他 app 拖出的真实文件）───
  const fileLoadTypes = [...FILE_TYPES, ...(provider.registeredTypes || [])]
  for (const type of fileLoadTypes) {
    try {
      const filePath = await provider.loadFilePath(type)
      if (filePath) {
        // Provider 已在回调中完成读取启动；现在才等待目录，避免写入与创建竞态。
        await directoryReady
        const name = Path.basename(filePath)
        const dest = Path.join(dirPath, name)
        if (await FileManager.exists(dest)) {
          // 同名文件，加时间戳后缀
          const ext = Path.extname(name)
          const body = Path.basename(name, ext)
          const renamed = `${body}_${ts}${ext}`
          const destPath = Path.join(dirPath, renamed)
          await FileManager.copyFile(filePath, destPath)
          try { await FileManager.remove(filePath) } catch {}
          console.log(`拖拽导入文件: ${name} -> ${dirPath}`)
          return destPath
        } else {
          await FileManager.copyFile(filePath, dest)
          try { await FileManager.remove(filePath) } catch {}
          console.log(`拖拽导入文件: ${name} -> ${dirPath}`)
          return dest
        }
      }
    } catch (e) {
      console.log(`loadFilePath(${type}) 失败:`, e)
    }
  }

  // ─── 2. 尝试 loadUIImage（图片）───
  const canLoadImage = provider.canLoadUIImage?.() ?? provider.hasItemConforming("public.image")
  if (canLoadImage) {
    try {
      const image = await provider.loadUIImage()
      if (image) {
        await directoryReady
        const jpegData = image.toJPEGData(0.92)
        if (jpegData) {
          const name = `IMG_${ts}.jpg`
          const destPath = Path.join(dirPath, name)
          await FileManager.writeAsData(destPath, jpegData)
          console.log(`拖拽导入图片: ${name} -> ${dirPath}`)
          return destPath
        }
      }
    } catch (e) {
      console.log('loadUIImage 失败:', e)
    }
  }

  // ─── 3. 尝试 loadURL（URL 链接）───
  if (
    types.includes("public.url") ||
    types.includes("public.file-url") ||
    provider.hasItemConforming("public.url")
  ) {
    try {
      const url = await provider.loadURL()
      if (url) {
        await directoryReady
        const weblocContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>URL</key>
  <string>${escapeXml(url)}</string>
</dict>
</plist>`
        const name = `URL_${ts}.webloc`
        const destPath = Path.join(dirPath, name)
        await FileManager.writeAsString(destPath, weblocContent, 'utf8')
        console.log(`拖拽导入 URL: ${url} -> ${dirPath}`)
        return destPath
      }
    } catch (e) {
      console.log('loadURL 失败:', e)
    }
  }

  // ─── 4. 尝试 loadText（文本）───
  if (
    types.includes("public.text") ||
    types.includes("public.plain-text") ||
    types.includes("public.utf8-plain-text") ||
    provider.hasItemConforming("public.text")
  ) {
    try {
      const text = await provider.loadText()
      if (text && text.length > 0) {
        await directoryReady
        const name = `Text_${ts}.txt`
        const destPath = Path.join(dirPath, name)
        await FileManager.writeAsString(destPath, text, 'utf8')
        console.log(`拖拽导入文本: ${name} -> ${dirPath}`)
        return destPath
      }
    } catch (e) {
      console.log('loadText 失败:', e)
    }
  }

  // ─── 5. 最终兜底：loadData 通用二进制 ───
  for (const type of types) {
    try {
      const data = await provider.loadData(type)
      if (data) {
        await directoryReady
        const ext = typeToExtension(type)
        const name = `data_${ts}.${ext}`
        const destPath = Path.join(dirPath, name)
        await FileManager.writeAsData(destPath, data)
        console.log(`拖拽导入数据: ${name} -> ${dirPath}`)
        return destPath
      }
    } catch {}
  }

  console.log(`无法读取拖入的项目 #${index + 1}`)
  return null
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function typeToExtension(type: UTType): string {
  const map: Record<string, string> = {
    'public.jpeg': 'jpg',
    'public.png': 'png',
    'public.gif': 'gif',
    'public.heic': 'heic',
    'public.heif': 'heif',
    'public.mpeg-4': 'mp4',
    'public.plain-text': 'txt',
    'public.rtf': 'rtf',
    'com.adobe.pdf': 'pdf',
    'public.zip-archive': 'zip',
    'org.openxmlformats.wordprocessingml.document': 'docx',
  }
  return map[type] || 'bin'
}