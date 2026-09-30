import {
  Script,
  Navigation,
  NavigationStack,
  List,
  Section,
  Button,
  Text,
  VStack,
  HStack,
  ProgressView,
  useState,
} from "scripting"
import { loadProfileDirectory } from "./src/zip.js"
import { patch } from "./src/port.js"
import { discoverHeic } from "./src/heif.js"
import { addTexture, hasTexture } from "./src/texture.js"

// Shalielie is a container-level HEIC patcher. It deliberately operates on raw
// bytes, never UIImage/ImageIO, so the original HEVC pixels and Apple metadata
// remain untouched.

type JobResult = {
  input: string
  output?: string
  isLivePhoto?: boolean
  saved?: boolean
  message: string
  ok: boolean
}

type Profile = Awaited<ReturnType<typeof loadProfileDirectory>>
type PhotoInput = {
  imagePath: string
  isLivePhoto: boolean
}

const PROJECT_DIR = "/var/mobile/Library/Mobile Documents/iCloud~com~thomfang~Scripting/Documents/scripts/质感照片"
const PROFILE_DIR = `${PROJECT_DIR}/profiles`
const TEMP_DIR = FileManager.temporaryDirectory
const profileCache = new Map<string, Profile>()

function basename(path: string): string {
  return path.split("/").pop() || "input.HEIC"
}

function extension(path: string, fallback = "heic"): string {
  const match = basename(path).match(/\.([^.]+)$/)
  return match ? match[1].toLowerCase() : fallback
}

function isHeic(bytes: Uint8Array): boolean {
  if (bytes.length < 12) return false
  const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11])
  return String.fromCharCode(bytes[4], bytes[5], bytes[6], bytes[7]) === "ftyp"
    && /^(hei|mif|msf|avi)/.test(brand)
}

async function getProfile(key: string): Promise<Profile> {
  const cached = profileCache.get(key)
  if (cached) return cached
  const profile = await loadProfileDirectory(`${PROFILE_DIR}/${key}`)
  profileCache.set(key, profile)
  return profile
}

async function saveOutput(bytes: Uint8Array, sourcePath: string, suffix: string): Promise<string> {
  const ext = /\.(heic|heif)$/i.test(sourcePath) ? extension(sourcePath) : "heic"
  const path = `${TEMP_DIR}/IMG_${Date.now()}.${ext}`
  await FileManager.writeAsBytes(path, bytes)
  return path
}

function imageResourceExtension(contentType: string, filename: string): string | null {
  const ext = extension(filename, "")
  if (["heic", "heif", "jpg", "jpeg", "png", "dng"].includes(ext)) {
    return ext === "jpeg" ? "jpg" : ext
  }
  if (contentType === "public.heic") return "heic"
  if (contentType === "public.heif") return "heif"
  if (contentType === "public.jpeg") return "jpg"
  if (contentType === "public.png") return "png"
  return null
}

function isVideoResource(contentType: string, filename: string): boolean {
  const ext = extension(filename, "")
  return contentType.includes("movie") || contentType.includes("video")
    || ["mov", "mp4", "m4v"].includes(ext)
}

/**
 * 从 PHPickerResult 取得原始 HEIF 和实况照片的 MOV 配对。
 * 优先使用 ItemProvider 的 HEIF 文件表示，避免 UIImage/JPEG 转码。
 */
async function resolvePhotoInput(result: any, index: number): Promise<PhotoInput | null> {
  // 先读取实况的静态资源，不读取 MOV。
  let livePhoto: any = null
  try { livePhoto = await result.livePhoto() } catch {}
  if (livePhoto) {
    try {
      const resources = await livePhoto.getAssetResources()
      let imageData: Data | null = null
      let imageExt = "heic"

      for (const resource of resources) {
        const contentType = String(resource.contentType || "").toLowerCase()
        const filename = String(resource.originalFilename || "")
        const imageExtForResource = imageResourceExtension(contentType, filename)
        if (!imageData && (imageExtForResource === "heic" || imageExtForResource === "heif")) {
          imageData = resource.data
          imageExt = imageExtForResource
        }
      }

      // 实况照片只取同一组资源中的静态 HEIF，完全不读取、不输出 MOV。
      if (!imageData) return null
      const stamp = `${Date.now()}-${index}`
      const imagePath = `${TEMP_DIR}/IMG_${stamp}`
      await FileManager.writeAsData(imagePath, imageData)
      return { imagePath, isLivePhoto: true }
    } catch {
      return null
    }
  }

  // 普通照片优先读取原始 HEIF/HEIF 文件表示，不经过 UIImage/JPEG 转码。
  let imagePath: string | null = null
  const provider = result.itemProvider
  for (const type of ["public.heic", "public.heif"]) {
    try {
      if (provider?.hasItemConforming?.(type)) {
        imagePath = await provider.loadFilePath(type)
        if (imagePath) break
      }
    } catch {}
  }
  if (!imagePath) {
    try { imagePath = await result.imagePath() } catch {}
  }
  if (!imagePath) return null
  return { imagePath, isLivePhoto: false }
}

async function processOne(path: string, isLivePhoto = false): Promise<JobResult> {
  const name = basename(path)
  try {
    const bytes = await FileManager.readAsBytes(path)
    if (!isHeic(bytes)) {
      return { input: name, message: "不是原始 HEIF/HEIC（相册可能提供了 JPEG 表示）", ok: false }
    }

    const discovered = discoverHeic(bytes)
    let output: Uint8Array
    let suffix: string
    let message: string

    if (discovered.stylesItem !== null) {
      // Native iPhone 16/17 style photos already contain the real photographic
      // style. Add the same Texture/Grain item graph for both static and Live
      // Photos; the static HEIF bytes are kept raw and are never ImageIO-reencoded.
      if (hasTexture(discovered.infos)) {
        return { input: name, message: "已经包含摄影风格和质感/颗粒，跳过", ok: false }
      }
      output = addTexture(bytes).data
      suffix = "_TextureGrain"
      message = isLivePhoto
        ? "原有摄影风格保留，已加入质感/颗粒；仅导出静态 HEIF"
        : "原有摄影风格保留，已加入质感/颗粒"
    } else {
      if (discovered.thumbnail === null) {
        return { input: name, message: "缺少内嵌缩略图；此原型无法补 HEVC 缩略图", ok: false }
      }
      const key = `${discovered.primaryTiles.length}-${discovered.hdrTiles.length}`
      if (key !== "48-12" && key !== "45-15") {
        return { input: name, message: `不支持的 tile layout：${key}`, ok: false }
      }
      const profile = await getProfile(key)
      // Scripting currently exposes no libheif/Core Image bridge. Use the same
      // validated donor-statistics fallback as Shalielie Web when decoding is
      // unavailable; this still writes the real style and texture item graph.
      const result = await patch(bytes, profile, {
        sceneStats: "donor",
        texture: true,
      })
      output = result.data
      suffix = "_PhotographicStyle"
      message = isLivePhoto
        ? "已加入摄影风格调色盘和质感/颗粒；仅导出静态 HEIF"
        : "已加入摄影风格调色盘，并加入质感/颗粒（donor fallback）"
    }

    const outPath = await saveOutput(output, path, suffix)
    return { input: name, output: outPath, message, ok: true }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    return { input: name, message: `HEIF 结构不受支持：${detail}`, ok: false }
  }
}

async function saveProcessed(result: JobResult): Promise<boolean> {
  if (!result.output) return false
  // 实况照片也只保存已经处理好的静态 HEIF，不再调用 Live Photo 保存接口。
  // 因而不会把 MOV、音频或动态 metadata 带入图库。
  return Photos.savePhoto(result.output, { fileName: basename(result.output) })
}

function Home() {
  const dismiss = Navigation.useDismiss()
  const [running, setRunning] = useState(false)
  const [status, setStatus] = useState("请从相册选择 HEIF/HEIC；实况照片只会导出静态 HEIF。")
  const [results, setResults] = useState<JobResult[]>([])

  async function chooseAndProcess() {
    if (running) return
    setRunning(true)
    setStatus("正在打开相册选择器…")
    try {
      const picked = await Photos.pick({
        filter: PHPickerFilter.any([
          PHPickerFilter.images(),
          PHPickerFilter.livePhotos(),
        ]),
        // 0 表示允许多选，与 live 可用项目的导入逻辑一致。
        limit: 0,
      })
      if (!picked?.length) {
        setStatus("已取消")
        return
      }

      const next: JobResult[] = []
      for (let index = 0; index < picked.length; index += 1) {
        const input = await resolvePhotoInput(picked[index], index)
        if (!input) {
          next.push({ input: `相册项目 ${index + 1}`, message: "无法读取相册中的原始 HEIF/HEIC", ok: false })
          setResults([...next])
          continue
        }

        setStatus(`正在逐项处理并导出：${index + 1}/${picked.length}（${basename(input.imagePath)}）`)
        const result = await processOne(input.imagePath, input.isLivePhoto)
        if (result.ok && input.isLivePhoto) {
          result.isLivePhoto = true
          result.message += "；仅导出静态 HEIF，不输出实况 MOV"
        }
        if (result.ok) {
          try {
            result.saved = await saveProcessed(result)
            if (result.saved) result.message += "；已保存到照片图库"
          } catch (error) {
            result.message += `；保存到图库失败：${String(error)}`
          }
        }
        next.push(result)
        setResults([...next])
      }
      setStatus(`完成：${next.filter((x) => x.saved).length}/${next.filter((x) => x.ok).length} 个静态 HEIF 已逐项保存到照片图库。`)
    } catch (error) {
      setStatus(`相册选择或处理失败：${String(error)}`)
    } finally {
      setRunning(false)
    }
  }

  async function saveToPhotos() {
    const pending = results.filter((result) => result.ok && result.output && !result.saved)
    if (!pending.length) {
      setStatus("没有待保存的处理结果。")
      return
    }
    setRunning(true)
    try {
      let saved = 0
      for (const result of pending) {
        try {
          if (await saveProcessed(result)) {
            result.saved = true
            saved += 1
          }
        } catch (error) {
          result.message += `；保存失败：${String(error)}`
        }
        setResults([...results])
      }
      setStatus(`已逐项保存 ${saved}/${pending.length} 个静态 HEIF 到照片图库。`)
    } catch (error) {
      setStatus(`保存到照片失败：${String(error)}`)
    } finally {
      setRunning(false)
    }
  }

  return (
    <NavigationStack>
      <List
        navigationTitle="质感照片"
        navigationBarTitleDisplayMode="inline"
        toolbar={{ cancellationAction: <Button title="关闭" action={dismiss} /> }}
      >
        <Section title="从相册导入">
          <Text>从照片图库读取原始 HEIF/HEIC。普通照片和实况照片都会逐项处理，并只将静态 HEIF/HEIC 保存到照片图库；实况 MOV 和声音不会输出。</Text>
          <Button
            title={running ? "处理中…" : "从相册选择并处理"}
            systemImage="photo.badge.arrow.down"
            action={chooseAndProcess}
          />
          {running ? <ProgressView title="正在处理" /> : null}
          <Text>{status}</Text>
        </Section>
        <Section title="输出">
          {results.length === 0 ? <Text>暂无处理结果</Text> : results.map((result) => (
            <VStack spacing={4}>
              <HStack spacing={8}>
                <Text>{result.ok ? (result.saved ? "✓" : "○") : "!"}</Text>
                <Text>{result.input}</Text>
              </HStack>
              <Text>{result.message}</Text>
              {result.isLivePhoto ? <Text>类型：实况照片的静态 HEIF（不输出 MOV）</Text> : null}
              {result.output ? <Text>{result.output}</Text> : null}
            </VStack>
          ))}
          <Button title="保存未保存的处理结果到照片" systemImage="photo.badge.checkmark" action={saveToPhotos} />
        </Section>
        <Section title="说明">
          <Text>批量选择会按相册顺序逐项处理、逐项导出并逐项保存。选择实况照片时只读取和保存其中的静态 HEIF/HEIC，不输出 MOV。</Text>
        </Section>
      </List>
    </NavigationStack>
  )
}

async function run() {
  await Navigation.present(<Home />)
  Script.exit()
}

run()
