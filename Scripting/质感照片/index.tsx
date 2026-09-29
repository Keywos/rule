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
import { patch, selectProfile } from "./src/port.js"
import { discoverHeic } from "./src/heif.js"
import { addTexture, hasTexture } from "./src/texture.js"

// Shalielie is a container-level HEIC patcher. It deliberately operates on raw
// bytes, never UIImage/ImageIO, so the original HEVC pixels and Apple metadata
// remain untouched.

type JobResult = {
  input: string
  output?: string
  message: string
  ok: boolean
}

type Profile = Awaited<ReturnType<typeof loadProfileDirectory>>

const PROJECT_DIR = `${FileManager.scriptsDirectory}/1`
const PROFILE_DIR = `${PROJECT_DIR}/profiles`
const TEMP_DIR = FileManager.temporaryDirectory
const profileCache = new Map<string, Profile>()

function basename(path: string): string {
  return path.split("/").pop() || "input.HEIC"
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
  const inputName = basename(sourcePath).replace(/\.(heic|heif)$/i, "")
  const path = `${TEMP_DIR}/${inputName}${suffix}.HEIC`
  await FileManager.writeAsBytes(path, bytes)
  return path
}

async function processOne(path: string): Promise<JobResult> {
  const name = basename(path)
  try {
    const bytes = await FileManager.readAsBytes(path)
    if (!isHeic(bytes)) {
      return { input: name, message: "不是原始 HEIC/HEIF（可能已被系统转成 JPEG）", ok: false }
    }

    const discovered = discoverHeic(bytes)
    let output: Uint8Array
    let suffix: string
    let message: string

    if (discovered.stylesItem !== null) {
      // Native iPhone 16/17 style photos retain their real palette. Only append
      // the iOS 27 Texture/Grain metadata set.
      if (hasTexture(discovered.infos)) {
        return { input: name, message: "已经包含质感/颗粒，跳过", ok: false }
      }
      output = addTexture(bytes).data
      suffix = "_TextureGrain"
      message = "原有摄影风格保留，已加入质感/颗粒"
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
      message = "已加入摄影风格调色盘，并加入质感/颗粒（donor fallback）"
    }

    const outPath = await saveOutput(output, path, suffix)
    return { input: name, output: outPath, message, ok: true }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    return { input: name, message: `HEIC 结构不受支持：${detail}`, ok: false }
  }
}

function Home() {
  const dismiss = Navigation.useDismiss()
  const [running, setRunning] = useState(false)
  const [status, setStatus] = useState("请选择从“文件”中导出的原始 HEIC；不要从照片图库直接选。")
  const [results, setResults] = useState<JobResult[]>([])

  async function chooseAndProcess() {
    if (running) return
    setRunning(true)
    setStatus("正在打开文件选择器…")
    try {
      const paths = await DocumentPicker.pickFiles({
        types: ["public.heic", "public.heif"],
        allowsMultipleSelection: true,
        shouldShowFileExtensions: true,
      })
      if (!paths.length) {
        setStatus("已取消")
        setRunning(false)
        return
      }
      const next: JobResult[] = []
      for (const path of paths) {
        setStatus(`处理中：${basename(path)}`)
        next.push(await processOne(path))
        setResults([...next])
      }
      setStatus(`完成：${next.filter((x) => x.ok).length}/${next.length} 张成功。`)
    } catch (error) {
      setStatus(`选择或处理失败：${String(error)}`)
    } finally {
      setRunning(false)
    }
  }

  async function saveToPhotos() {
    const paths = results.flatMap((x) => x.output ? [x.output] : [])
    if (!paths.length) return
    try {
      let saved = 0
      for (const path of paths) {
        if (await Photos.savePhoto(path, { fileName: basename(path) })) saved += 1
      }
      setStatus(`已保存 ${saved}/${paths.length} 个 HEIC 到照片图库。`)
    } catch (error) {
      setStatus(`保存到照片失败：${String(error)}`)
    }
  }

  async function saveAll() {
    const paths = results.flatMap((x) => x.output ? [x.output] : [])
    if (!paths.length) return
    try {
      // Exporting the original HEIC bytes is the important path: unlike
      // Photos.pick().uiImage(), this does not transcode or discard item data.
      const exported = await DocumentPicker.exportFiles({
        files: await Promise.all(paths.map(async (path) => ({
          data: await FileManager.readAsData(path),
          name: basename(path),
        }))),
      })
      setStatus(`已导出 ${exported.length} 个 HEIC 文件。`)
    } catch (error) {
      setStatus(`导出失败：${String(error)}`)
    }
  }

  return (
    <NavigationStack>
      <List
        navigationTitle="质感照片"
        navigationBarTitleDisplayMode="inline"
        toolbar={{ cancellationAction: <Button title="关闭" action={dismiss} /> }}
      >
        <Section title="原始 HEIC">
          <Text>为iPhone 16 等 机型拍摄的兼容 HEIC 照片添加 iPhone 16 系列引入的摄影风格调色盘，并一并加入 iOS 27 随 iPhone 18 Pro 推出的「质感」与「颗粒」控制 HEIF/ISO-BMFF item graph 原版https://github.com/nathanatgit/Shalielie</Text>
          <Button
            title={running ? "处理中…" : "选择 HEIC 并处理"}
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
                <Text>{result.ok ? "✓" : "!"}</Text>
                <Text>{result.input}</Text>
              </HStack>
              <Text>{result.message}</Text>
              {result.output ? <Text>{result.output}</Text> : null}
            </VStack>
          ))}
          <Button title="保存成功的 HEIC 到照片" systemImage="photo.badge.checkmark" action={saveToPhotos} />
          <Button title="导出成功的 HEIC 到文件" systemImage="square.and.arrow.up" action={saveAll} />
        </Section>
        <Section title="限制">
          <Text>请先在照片 App 中“共享 → 存储到文件”，再在这里选择；照片图库选择器常会把 HEIC 转成 JPEG。</Text>
          <Text>当前 Scripting 没有公开 libheif/Core Image/HEVC 编码桥接，因此使用上游验证过的 donor fallback；不会生成目标照片的 scene statistics/light maps。</Text>
          <Text>只处理静态 HEIC，不包含实况照片动态画面和声音。请保留原片。</Text>
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
