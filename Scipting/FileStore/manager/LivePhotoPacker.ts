// 实况照片 .live 打包/解包工具
//
// .live 文件格式（全二进制，不压缩）：
// ┌─────────────────────────┐
// │ Magic "LIVE"  (4 bytes) │
// │ 扩展名长度     (1 byte)  │  e.g. 4 for "heic"
// │ 扩展名        (N bytes)  │  e.g. "heic"
// │ 图片数据大小   (4 bytes)  │  big-endian uint32
// │ 视频数据大小   (4 bytes)  │  big-endian uint32
// ├─────────────────────────┤
// │ 图片数据                 │
// ├─────────────────────────┤
// │ 视频数据                 │
// └─────────────────────────┘

/**
 * 将图片数据和视频数据打包为 .live 文件格式
 */
export function packLivePhoto(imageData: Data, imageExt: string, videoData: Data): Data {
  const ext = imageExt.toLowerCase().replace(/^\./, '')
  const extData = Data.fromRawString(ext, 'ascii')!
  const imgSize = imageData.size
  const vidSize = videoData.size

  // 写入大端 uint32
  const writeUint32 = (arr: number[], val: number) => {
    arr.push((val >> 24) & 0xFF)
    arr.push((val >> 16) & 0xFF)
    arr.push((val >> 8) & 0xFF)
    arr.push(val & 0xFF)
  }

  const headerBytes: number[] = []
  // Magic "LIVE"
  headerBytes.push(0x4C, 0x49, 0x56, 0x45)
  // 扩展名长度 + 扩展名
  headerBytes.push(extData.size)
  headerBytes.push(...extData.toIntArray())
  // 图片大小
  writeUint32(headerBytes, imgSize)
  // 视频大小
  writeUint32(headerBytes, vidSize)

  return Data.combine([Data.fromIntArray(headerBytes), imageData, videoData])
}

/** 解包结果 */
export interface LivePhotoUnpacked {
  imageData: Data
  imageExt: string
  videoData: Data
}

/**
 * 从 .live 文件数据中解包出图片和视频
 * 返回 null 表示不是有效的 .live 文件
 */
export function unpackLivePhoto(data: Data): LivePhotoUnpacked | null {
  const bytes = data.toIntArray()

  // 检查 magic "LIVE"
  if (bytes.length < 13 || bytes[0] !== 0x4C || bytes[1] !== 0x49 || bytes[2] !== 0x56 || bytes[3] !== 0x45) {
    return null
  }

  const extLen = bytes[4]
  if (bytes.length < 5 + extLen + 8) return null

  // 读取扩展名
  const extBytes = bytes.slice(5, 5 + extLen)
  const imageExt = extBytes.map(b => String.fromCharCode(b)).join('')

  const offset = 5 + extLen

  // 读取大端 uint32
  const readUint32 = (arr: number[], pos: number) =>
    (arr[pos] << 24) | (arr[pos + 1] << 16) | (arr[pos + 2] << 8) | arr[pos + 3]

  const imgSize = readUint32(bytes, offset)
  const vidSize = readUint32(bytes, offset + 4)

  const headerSize = offset + 8

  if (bytes.length < headerSize + imgSize + vidSize) return null

  const imageData = data.slice(headerSize, headerSize + imgSize)
  const videoData = data.slice(headerSize + imgSize, headerSize + imgSize + vidSize)

  return { imageData, imageExt, videoData }
}

/**
 * 检查文件名是否为 .live 实况照片文件
 */
export function isLivePhotoFile(name: string): boolean {
  return /\.live$/i.test(name)
}
