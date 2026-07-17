// 导入工具函数 — 文件/照片/视频导入通用 helper

import { Path } from 'scripting'
import { getFileInfo, FileInfo } from './utils'
import { packLivePhoto } from './LivePhotoPacker'

/** 导入文件存放目录（默认） */
export const DEFAULT_IMPORT_DIR = Path.join(FileManager.documentsDirectory, 'File Manager Imports')

/** 确保目录存在 */
export async function ensureDir(dir: string) {
  const exists = await FileManager.exists(dir)
  if (!exists) {
    await FileManager.createDirectory(dir, true)
  }
}

/** 读取目录中的文件列表，按修改日期降序 */
export async function listFilesInDir(dir: string): Promise<FileInfo[]> {
  await ensureDir(dir)
  const entries = await FileManager.readDirectory(dir)
  const results = await Promise.all(
    entries.map(async (entry) => {
      try {
        const fullPath = Path.join(dir, entry)
        return await getFileInfo(fullPath)
      } catch {
        return null
      }
    })
  )
  const items: FileInfo[] = results.filter((r): r is FileInfo => r != null)
  items.sort((a, b) => b.modificationDate - a.modificationDate)
  return items
}

/** 生成中国时区的时间戳文件名 YYYYMMDDHHmmss */
export function makeTimestamp() {
  const d = new Date(Date.now() + 8 * 3600 * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`
}

/** 判断 PHPickerResult 是否为 DNG 原始照片 */
export function isDngResult(result: any): boolean {
  const ip = result.itemProvider
  const types: string[] = ip?.registeredTypes ?? []
  return types.some(t =>
    t.includes('dng') ||
    t === 'com.adobe.raw-image' ||
    t === 'public.camera-raw-image'
  )
}

/** 从 registeredTypes 推断视频的正确扩展名（保留原始格式） */
export function getVideoExtension(result: any): string {
  const ip = result.itemProvider
  const types: string[] = ip?.registeredTypes ?? []
  const videoExtMap: Record<string, string> = {
    'public.mpeg-4': '.mp4',
    'public.mpeg-4-audio': '.m4a',
    'com.apple.protected-mpeg-4-video': '.m4v',
    'com.apple.quicktime-movie': '.mov',
    'public.mpeg': '.mpeg',
    'public.mpeg-2-video': '.m2v',
    'public.avi': '.avi',
    'public.3gpp': '.3gp',
    'public.3gpp2': '.3g2',
  }
  for (const t of types) {
    if (videoExtMap[t]) return videoExtMap[t]
  }
  for (const t of types) {
    if (t.includes('video') || t.includes('movie')) {
      if (t.includes('mp4') || t.includes('mpeg4') || t.includes('mpeg-4')) return '.mp4'
      if (t.includes('quicktime')) return '.mov'
      if (t.includes('avi')) return '.avi'
      if (t.includes('3gpp')) return '.3gp'
    }
  }
  return '.mov'
}

/** 导入单个 PHPickerResult 到指定目录（处理实况照片 / DNG / 普通图片 / 视频） */
export async function importSinglePhotoResult(result: any, destDir: string): Promise<string | null> {
  const ts = makeTimestamp()
  const ip = result.itemProvider
  const types = ip?.registeredTypes ?? []
  console.log('注册类型:', JSON.stringify(types))
  console.log('canLoadLivePhoto:', ip?.canLoadLivePhoto?.())

  // ───── 1. 先试 imagePath + videoPath ─────
  try {
    const [imgPath, vidPath] = await Promise.all([
      result.imagePath(),
      result.videoPath(),
    ])
    console.log('imagePath:', imgPath, 'videoPath:', vidPath)

    if (imgPath && vidPath) {
      const [imgData, vidData] = await Promise.all([
        FileManager.readAsData(imgPath),
        FileManager.readAsData(vidPath),
      ])
      if (imgData && vidData) {
        const ext = Path.extname(imgPath).toLowerCase() || '.heic'
        const packed = packLivePhoto(imgData, ext.replace(/^\./, ''), vidData)
        const _livePath = Path.join(destDir, `${ts}.live`)
        await FileManager.writeAsData(_livePath, packed)
        try { await FileManager.remove(imgPath) } catch {}
        try { await FileManager.remove(vidPath) } catch {}
        console.log('已导入为 .live 文件')
        return _livePath
      }
      // 注意：此处不要提前删除 imgPath/vidPath。下面的单资源回退分支会重新
      // 读取它们并各自清理；若在此删除，回退读取会失败，导致可读的图片/视频丢失。
    }

    if (imgPath) {
      const imgData = await FileManager.readAsData(imgPath)
      if (imgData) {
        const ext = isDngResult(result) ? '.dng' : (Path.extname(imgPath).toLowerCase() || '.heic')
        const _imgPath2 = Path.join(destDir, `${ts}${ext}`)
        await FileManager.writeAsData(_imgPath2, imgData)
        try { await FileManager.remove(imgPath) } catch {}
        console.log('已导入为图片:', ext)
        return _imgPath2
      }
      try { await FileManager.remove(imgPath) } catch {}
    }

    if (vidPath) {
      const vidData = await FileManager.readAsData(vidPath)
      if (vidData) {
        const ext = getVideoExtension(result)
        const _vidPath = Path.join(destDir, `${ts}${ext}`)
        await FileManager.writeAsData(_vidPath, vidData)
        try { await FileManager.remove(vidPath) } catch {}
        console.log('已导入为视频:', ext)
        return _vidPath
      }
      try { await FileManager.remove(vidPath) } catch {}
    }
  } catch (e) { console.log('imagePath失败:', e) }

  // ───── 2. 再用 livePhoto ─────
  try {
    const livePhoto = await result.livePhoto()
    console.log('livePhoto:', livePhoto ? '有数据' : 'null')
    if (livePhoto) {
      const resources = await livePhoto.getAssetResources()
      let imgData: Data | null = null
      let imgExt = 'heic'
      let vidData: Data | null = null
      for (const res of resources) {
        const ct = res.contentType?.toLowerCase?.() ?? ''
        const fn = res.originalFilename ?? ''
        console.log('资源:', ct, fn)
        if (ct.includes('image') || /\.(heic|jpg|jpeg|png|dng)$/i.test(fn)) {
          imgData = res.data
          if (/\.dng$/i.test(fn)) imgExt = 'dng'
          else if (/\.png$/i.test(fn)) imgExt = 'png'
          else if (/\.jpg$/i.test(fn)) imgExt = 'jpg'
        } else if (ct.includes('movie') || ct.includes('video') || /\.mov$/i.test(fn)) {
          vidData = res.data
        }
      }
      if (imgData && vidData) {
        const _lpPath = Path.join(destDir, `${ts}.live`)
        const packed = packLivePhoto(imgData, imgExt, vidData)
        await FileManager.writeAsData(_lpPath, packed)
        console.log('已从livePhoto导入为 .live')
        return _lpPath
      } else if (imgData) {
        const _imgPath3 = Path.join(destDir, `${ts}.${imgExt}`)
        await FileManager.writeAsData(_imgPath3, imgData)
        console.log('已从livePhoto导入为图片:', imgExt)
        return _imgPath3
      }
    }
  } catch (e) { console.log('livePhoto失败:', e) }

  // ───── 3. 最后手段：UIImage → JPEG（DNG 跳过 JPEG 兜底）─────
  try {
    if (isDngResult(result)) {
      console.log('DNG：跳过 JPEG 转换，尝试直接保存原始数据')
      const p = await result.imagePath()
      if (p) {
        const d = await FileManager.readAsData(p)
        if (d) {
          const _dngPath = Path.join(destDir, `${ts}.dng`)
          await FileManager.writeAsData(_dngPath, d)
          console.log('DNG 原始数据已保存')
          try { await FileManager.remove(p) } catch {}
          return _dngPath
        }
        try { await FileManager.remove(p) } catch {}
      }
    } else {
      const img = await result.uiImage()
      console.log('uiImage:', img ? '有数据' : 'null')
      if (img) {
        const jpegData = img.toJPEGData(1.0)
        if (jpegData) {
          const _jpegPath = Path.join(destDir, `photo_${ts}.jpg`)
          await FileManager.writeAsData(_jpegPath, jpegData)
          console.log('已导入为 JPEG 后备')
          return _jpegPath
        }
      }
    }
  } catch (e) { console.log('UIImage失败:', e) }
  return null
}
