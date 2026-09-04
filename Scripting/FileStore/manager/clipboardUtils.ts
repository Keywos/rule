import { Path } from "scripting"

const clipboardPathFile = Path.join(FileManager.temporaryDirectory, ".fstore_copied_path")

/** 读取跨标签和子目录保留的复制路径。 */
export async function readClipboardPath(): Promise<string | null> {
  try {
    if (await FileManager.exists(clipboardPathFile)) {
      return await FileManager.readAsString(clipboardPathFile)
    }
  } catch { }
  return null
}

/** 写入或清除跨标签和子目录保留的复制路径。 */
export async function writeClipboardPath(path: string | null) {
  try {
    if (path) {
      await FileManager.writeAsString(clipboardPathFile, path)
    } else if (await FileManager.exists(clipboardPathFile)) {
      await FileManager.remove(clipboardPathFile)
    }
  } catch { }
}
