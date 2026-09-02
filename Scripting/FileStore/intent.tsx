import { Intent, Navigation, Script, Path } from "scripting";
import { resolveOpenerForFile } from "./view/DefaultOpenerPicker";
import { getFileCategory, sanitizeExtractDirName, safeUnzip, ensureLocalFile } from "./manager/utils";
import { EditorPage } from "./view/EditorPage";
import { ArchiveBrowserPage, ImageViewer, VideoViewerPage, LivePhotoPreviewPage } from "./view/MediaViewer";

/** Intent 扩展内存有限，超过此大小的文件跳转主 App 处理 */
const INTENT_MAX_SIZE = 10 * 1024 * 1024; // 10 MB

async function run() {
  try {
  // ── 1. 获取文件路径：支持 Intent 入口 和 URL Scheme 回调两种来源 ──
  const intentFiles = Intent.fileURLsParameter;
  const queryFileURL = Script.queryParameters?.fileURL as string | undefined;
  const path = intentFiles?.[0] ?? queryFileURL;
  if (!path) {
    return;
  }

  // ── 2. 获取文件大小 ──
  let fileSize = 0;
  try {
    fileSize = (await FileManager.stat(path)).size;
  } catch {}

  // ── 3. 大文件：拷贝到 App Group 共享目录，通过 URL Scheme 跳转主 App ──
  if (fileSize > INTENT_MAX_SIZE) {
    const fileName = Path.basename(path);
    const transferDir = Path.join(FileManager.appGroupDocumentsDirectory, "_intent_transfer");
    await FileManager.createDirectory(transferDir, true);

    // 避免重名覆盖
    let destPath = Path.join(transferDir, fileName);
    if (await FileManager.exists(destPath)) {
      const ts = Date.now();
      destPath = Path.join(transferDir, `${Path.basename(fileName, Path.extname(fileName))}_${ts}${Path.extname(fileName)}`);
    }

    // copyFile 是文件系统级操作，不会把整个文件读进内存
    await FileManager.copyFile(path, destPath);

    const runURL = Script.createRunURLScheme(Script.name, { fileURL: destPath });
    await Safari.openURL(runURL);
    return;
  }

  // ── 4. 小文件：在扩展内直接处理 ──
  try {
    await ensureLocalFile(path);
  } catch (e) {
    console.error("ensureLocalFile 失败:", e);
    return;
  }

  const ext = Path.extname(path);
  const category = getFileCategory(ext);

  const prefix = await resolveOpenerForFile(path, category);
  if (!prefix) {
    return;
  }

  if (prefix === "editor:" || prefix === "preview:") {
    await Navigation.present({
      element: (
        <EditorPage
          path={path}
          fileName={Path.basename(path)}
          fileSize={fileSize}
          mode="present"
        />
      ),
      modalPresentationStyle: prefix === "editor:" ? "overFullScreen" : undefined,
    });
  } else if (prefix === "archive:") {
    await Navigation.present({
      element: <ArchiveBrowserPage filePath={path} />,
    });
  } else if (prefix === "video:") {
    await Navigation.present({
      element: <VideoViewerPage filePath={path} />,
    });
  } else if (prefix === "image:") {
    await Navigation.present({
      element: <ImageViewer filePath={path} />,
    });
  } else if (prefix === "livephoto:") {
    await Navigation.present({
      element: <LivePhotoPreviewPage livePath={path} />,
    });
  } else if (prefix === "extract:") {
    const parentDir = Path.dirname(path);
    await safeUnzip(path, parentDir);
  } else if (prefix === "extractfolder:") {
    const archiveName = sanitizeExtractDirName(Path.basename(path));
    const parentDir = Path.dirname(path);
    let extractDir = Path.join(parentDir, archiveName);
    if (await FileManager.exists(extractDir)) {
      let counter = 1;
      while (await FileManager.exists(Path.join(parentDir, `${archiveName}_${String(counter).padStart(2, "0")}`))) {
        counter++;
      }
      extractDir = Path.join(parentDir, `${archiveName}_${String(counter).padStart(2, "0")}`);
    }
    await FileManager.createDirectory(extractDir, true);
    await FileManager.unzip(path, extractDir);
  }

  } catch (error) {
    console.error("无法打开外部文件:", error);
  } finally {
    Script.exit();
  }
}
void run();
