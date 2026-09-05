// 拖拽放置处理工具 — 从外部 App 拖入文件/文本/URL 到本应用的目录
// 配合 GeneralBrowser、MountDirectoriesPage 的 onDrop 使用

import { Path } from 'scripting'
import { ensureDir, makeTimestamp } from './importHelpers'
import { packLivePhoto } from './LivePhotoPacker'
import { writeToUniquePath } from './utils'

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
  "com.apple.live-photo",
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
    // 双栏及目录内拖放只复制文件；递归复制文件夹未实现，禁止进入 copyFile 路径。
    if (await FileManager.isDirectory(dragSource)) {
      console.log(`跳过文件夹拖拽复制: ${dragSource}`)
      return null
    }
    await directoryReady
    const name = Path.basename(dragSource)
    const { path: dest } = await writeToUniquePath(Path.join(dirPath, name), (targetPath) => FileManager.copyFile(dragSource, targetPath))
    console.log(`应用内拖拽文件: ${name} -> ${dirPath}`)
    return dest
  }

  const types = provider.registeredTypes || []
  // 不依赖 canLoadLivePhoto() 预检：部分拖放来源会将实况照片声明为普通图片，
  // 但 loadLivePhoto() 仍可取得配对资源。必须立刻启动请求，不能等其他异步分支。
  const livePhotoRequest = provider.loadLivePhoto().catch(() => null)
  console.log('拖放提供器类型:', JSON.stringify(types), 'canLoadLivePhoto:', provider.canLoadLivePhoto())

  // ─── 1. 优先读取实况照片并打包为单个 .live 文件 ───
  // 仅在完整打包成功后返回，否则继续走下面的文件/图片等回退路径。
  try {
    const livePhoto = await livePhotoRequest
    if (livePhoto) {
      const packed = packDroppedLivePhoto(await livePhoto.getAssetResources())
      if (packed) {
        await directoryReady
        const name = `LIVE_${ts}.live`
        const { path: destPath } = await writeToUniquePath(Path.join(dirPath, name), (targetPath) => FileManager.writeAsData(targetPath, packed))
        console.log(`拖拽导入实况照片: ${name} -> ${dirPath}`)
        return destPath
      }
      console.log('实况照片资源不完整，回退到普通拖拽导入')
    }
  } catch (e) {
    console.log('实况照片打包失败，回退到普通拖拽导入:', e)
  }

  // ─── 2. 优先尝试 loadFilePath（其他 app 拖出的真实文件）───
  const fileLoadTypes = [...FILE_TYPES, ...(provider.registeredTypes || [])]
  for (const type of fileLoadTypes) {
    try {
      const filePath = await provider.loadFilePath(type)
      if (filePath) {
        // Provider 已在回调中完成读取启动；现在才等待目录，避免写入与创建竞态。
        await directoryReady
        const name = Path.basename(filePath)
        const { path: dest } = await writeToUniquePath(Path.join(dirPath, name), (targetPath) => FileManager.copyFile(filePath, targetPath))
        try { await FileManager.remove(filePath) } catch {}
        console.log(`拖拽导入文件: ${name} -> ${dirPath}`)
        return dest
      }
    } catch (e) {
      console.log(`loadFilePath(${type}) 失败:`, e)
    }
  }

  // ─── 3. 尝试 loadUIImage（图片）───
  const canLoadImage = provider.canLoadUIImage?.() ?? provider.hasItemConforming("public.image")
  if (canLoadImage) {
    try {
      const image = await provider.loadUIImage()
      if (image) {
        await directoryReady
        const jpegData = image.toJPEGData(0.92)
        if (jpegData) {
          const name = `IMG_${ts}.jpg`
          const { path: destPath } = await writeToUniquePath(Path.join(dirPath, name), (targetPath) => FileManager.writeAsData(targetPath, jpegData))
          console.log(`拖拽导入图片: ${name} -> ${dirPath}`)
          return destPath
        }
      }
    } catch (e) {
      console.log('loadUIImage 失败:', e)
    }
  }

  // ─── 4. 尝试 loadURL（URL 链接）───
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
        const { path: destPath } = await writeToUniquePath(Path.join(dirPath, name), (targetPath) => FileManager.writeAsString(targetPath, weblocContent, 'utf8'))
        console.log(`拖拽导入 URL: ${url} -> ${dirPath}`)
        return destPath
      }
    } catch (e) {
      console.log('loadURL 失败:', e)
    }
  }

  // ─── 5. 尝试 loadText（文本）───
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
        const { path: destPath } = await writeToUniquePath(Path.join(dirPath, name), (targetPath) => FileManager.writeAsString(targetPath, text, 'utf8'))
        console.log(`拖拽导入文本: ${name} -> ${dirPath}`)
        return destPath
      }
    } catch (e) {
      console.log('loadText 失败:', e)
    }
  }

  // ─── 6. 最终兜底：loadData 通用二进制 ───
  for (const type of types) {
    try {
      const data = await provider.loadData(type)
      if (data) {
        await directoryReady
        const ext = typeToExtension(type)
        const name = `data_${ts}.${ext}`
        const { path: destPath } = await writeToUniquePath(Path.join(dirPath, name), (targetPath) => FileManager.writeAsData(targetPath, data))
        console.log(`拖拽导入数据: ${name} -> ${dirPath}`)
        return destPath
      }
    } catch {}
  }

  console.log(`无法读取拖入的项目 #${index + 1}`)
  return null
}

function packDroppedLivePhoto(
  resources: Array<{ data: Data; contentType: UTType; originalFilename: string }>,
): Data | null {
  let imageData: Data | null = null
  let imageExt: string | null = null
  let videoData: Data | null = null

  for (const resource of resources) {
    const contentType = String(resource.contentType || '').toLowerCase()
    const filename = resource.originalFilename || ''
    const filenameExt = Path.extname(filename).toLowerCase().replace(/^\./, '')
    const resolvedImageExt = imageExtensionForLivePhotoResource(contentType, filenameExt)

    if (!imageData && resolvedImageExt) {
      imageData = resource.data
      imageExt = resolvedImageExt
      continue
    }

    if (!videoData && isLivePhotoVideoResource(contentType, filenameExt)) {
      videoData = resource.data
    }
  }

  return imageData && imageExt && videoData ? packLivePhoto(imageData, imageExt, videoData) : null
}

function imageExtensionForLivePhotoResource(contentType: string, filenameExt: string): string | null {
  const extensionByType: Record<string, string> = {
    'public.heic': 'heic',
    'public.heif': 'heif',
    'public.jpeg': 'jpg',
    'public.png': 'png',
  }
  if (extensionByType[contentType]) return extensionByType[contentType]
  if (['heic', 'heif', 'jpg', 'jpeg', 'png', 'dng'].includes(filenameExt)) {
    return filenameExt === 'jpeg' ? 'jpg' : filenameExt
  }
  return null
}

function isLivePhotoVideoResource(contentType: string, filenameExt: string): boolean {
  return (
    contentType === 'com.apple.quicktime-movie' ||
    contentType === 'public.movie' ||
    contentType === 'public.video' ||
    contentType === 'public.mpeg-4' ||
    filenameExt === 'mov'
  )
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