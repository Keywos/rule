import { Intent, Navigation, Script, Path } from "scripting";
import { resolveOpenerForFile } from "./view/DefaultOpenerPicker";
import { getFileCategory, sanitizeExtractDirName, safeUnzip, ensureLocalFile, copyFileToFileStore, uniquePath } from "./manager/utils";
import { packLivePhoto } from "./manager/LivePhotoPacker";
import { EditorPage } from "./view/EditorPage";
import { ArchiveBrowserPage, ImageViewer, VideoViewerPage, LivePhotoPreviewPage } from "./view/MediaViewer";

/** Intent 扩展内存有限，超过此大小的文件跳转主 App 处理 */
const INTENT_MAX_SIZE = 10 * 1024 * 1024; // 10 MB

/** 将文件复制到 App Group 共享目录，返回目标路径（扩展进程有权限时可做） */
async function copyToAppGroupTransfer(src: string): Promise<string | null> {
  try {
    const fileName = Path.basename(src);
    const transferDir = Path.join(FileManager.appGroupDocumentsDirectory, "_intent_transfer");
    await FileManager.createDirectory(transferDir, true);
    let destPath = Path.join(transferDir, fileName);
    if (await FileManager.exists(destPath)) {
      const ts = Date.now();
      destPath = Path.join(transferDir, `${Path.basename(fileName, Path.extname(fileName))}_${ts}${Path.extname(fileName)}`);
    }
    await FileManager.copyFile(src, destPath);
    console.log("copyToAppGroupTransfer: 成功", destPath);
    return destPath;
  } catch (e) {
    console.log("copyToAppGroupTransfer: 失败", e);
    return null;
  }
}

async function run() {
  try {
  // ── 1. 获取文件路径：支持 Intent 入口 和 URL Scheme 回调两种来源 ──
  const intentFiles = Intent.fileURLsParameter ?? [];
  const imageFiles = Intent.imagePathsParameter ?? [];
  const queryFileURL = Script.queryParameters?.fileURL as string | undefined;
  // 实况照片分享可能同时传入图片和 MOV；交给主 App 打包，避免扩展进程写入/读取资源失败。
  if (!queryFileURL) {
    const allFiles = [...intentFiles, ...imageFiles];
    const imagePath = allFiles.find((p) => /\.(heic|heif|jpg|jpeg|png|dng)$/i.test(p));
    const videoPath = allFiles.find((p) => /\.(mov|mp4|m4v)$/i.test(p));
    if (imagePath && videoPath) {
      await Safari.openURL(Script.createRunURLScheme(Script.name, {
        action: "importLivePhoto",
        imagePath,
        videoPath,
      }));
      Script.exit();
      return;
    }
  }
  // 已打包的 .live 文件优先；普通照片再使用 image/file URL。
  const liveFile = intentFiles.find((p) => /\.live$/i.test(p)) ?? imageFiles.find((p) => /\.live$/i.test(p));
  const shortcutValue = (Intent.shortcutParameter as any)?.value;
  const shortcutPath = typeof shortcutValue === "string" ? shortcutValue : undefined;
  const path = liveFile ?? intentFiles[0] ?? imageFiles[0] ?? queryFileURL ?? shortcutPath;
  if (!path) {
    console.log("intent.tsx: 未收到可用文件路径", { intentFiles, imageFiles, queryFileURL, shortcutValue });
    Script.exit();
    return;
  }

  console.log("intent.tsx: 收到文件路径", path, "Script.env =", Script.env);

  // ── 2. 解析文件大小（用于判断是否走大文件中转） ──
  let fileSize = 0;
  try {
    fileSize = (await FileManager.stat(path)).size;
  } catch {}

  // ── 3. 非文本文件：直接打开主 App 保存到 File Store ──
  // 扩展进程复制到临时目录的文件在 File Store 里不可见，改为直接跳转主 App 通过书签解析保存到 File Store。
  // 仅在直接来自分享面板（无 fileURL 回调参数）时跳转，避免 URL 回调再次触发造成循环。
  if (!queryFileURL) {
    const ext0 = Path.extname(path);
    const category0 = getFileCategory(ext0);
    if (category0 !== "text" && category0 !== "code" && category0 !== "data") {
      // 扩展不能可靠地写入主 App 的 documentsDirectory：先把原文件放入 App Group 中转，
      // 主 App 再立即移动到 File Store。中转目录不是最终保存位置。
      const transferPath = await copyToAppGroupTransfer(path);
      if (transferPath) {
        await Safari.openURL(Script.createRunURLScheme(Script.name, { fileURL: transferPath, action: "importNonText" }));
        Script.exit();
        return;
      }
      // 中转失败时再尝试直接传原路径，让主 App 通过 bookmark 解析。
      await Safari.openURL(Script.createRunURLScheme(Script.name, { fileURL: path, action: "importNonText" }));
      Script.exit();
      return;
    }
  }

  // ── 4. 大文件：拷贝到 App Group 共享目录，通过 URL Scheme 跳转主 App ──
  // 扩展进程内存有限，大文件直接处理会触发系统终止。中转后主 App 通过 copyFileToFileStore 保存到 File Store。
  if (fileSize > INTENT_MAX_SIZE) {
    const transferPath = await copyToAppGroupTransfer(path);
    if (transferPath) {
      const runURL = Script.createRunURLScheme(Script.name, { fileURL: transferPath });
      await Safari.openURL(runURL);
      return;
    }
    // 中转失败则降级到小文件逻辑继续处理
    console.log("intent.tsx: 大文件中转失败, 降级处理");
  }

  // ── 4. 是否通过 URL scheme 回调（来自 _intent_transfer 中转） ──
  const isFromTransfer = !!queryFileURL;

  // ── 5. 统一处理小文件：先尝试保存到 File Store ──
  // 如果是 URL scheme 回调，文件已在 appGroup 可直接读，走 copyFileToFileStore 必定成功
  // 如果是从分享面板进来（Intent.fileURLsParameter），可能是扩展或 App 进程
  let accessiblePath = path;
  let saved = false;

  if (!isFromTransfer) {
    // 从分享面板进来的文件
    // 先尝试直接复制到 File Store（含 bookmark 解析）
    const result = await copyFileToFileStore(path);
    accessiblePath = result.path;
    saved = result.saved;

    if (saved) {
      console.log("intent.tsx: 已复制到 File Store", accessiblePath);
    } else {
      // 复制失败：尝试备用方案（严格按文件名匹配，绝不打开无关文件）
      console.log("intent.tsx: copyFileToFileStore 未保存, 尝试备用方案");

      // 检查源路径是否可读（扩展进程场景）
      let readable = false;
      try {
        const probe = await FileManager.readAsData(path);
        readable = !!(probe && probe.size > 0);
      } catch {}

      // 尝试通过 bookmark 解析（仅采用文件名与源文件一致的候选）
      if (!readable) {
        const srcName = Path.basename(path);
        try {
          const bookmarks = FileManager.getAllFileBookmarks();
          console.log("intent.tsx: 尝试遍历 bookmarks, 共", bookmarks.length, "个");
          for (const b of bookmarks) {
            try {
              // 书签原始路径与解析路径的文件名都必须与源文件一致
              const bPathName = Path.basename((b.path || "").replace(/\\/g, "/"));
              if (bPathName !== srcName) continue;
              const resolved = FileManager.bookmarkedPath(b.name);
              if (!resolved || !resolved.trim()) continue;
              if (Path.basename(resolved) !== srcName) continue;
              const probe = await FileManager.readAsData(resolved);
              if (probe && probe.size > 0) {
                accessiblePath = resolved;
                readable = true;
                console.log("intent.tsx: 通过 bookmark 解析到可读路径", resolved);
                break;
              }
            } catch {}
          }
        } catch {}
      }

      if (!readable) {
        // 完全不可读：尝试通过 appGroup 中转（仅当扩展进程可读时有效）
        const transferPath = await copyToAppGroupTransfer(path);
        if (transferPath) {
          // 复制到 appGroup 成功，跳转主 App 处理
          const runURL = Script.createRunURLScheme(Script.name, { fileURL: transferPath });
          await Safari.openURL(runURL);
          return;
        }

        // 所有方案都失败，提示用户
        await Dialog.alert({
          title: "无法打开分享文件",
          message: "主 App 进程无法读取该文件，且无法通过书签或中转获取对应文件。\n\n请尝试先选择「运行」而非「在App里运行」。\n\n路径：" + path,
        });
        return;
      }
    }
  } else {
    // 来自 URL scheme 回调（_intent_transfer 中转），文件一定可读
    // 直接保存到 File Store
    const result = await copyFileToFileStore(path);
    accessiblePath = result.path;
    saved = result.saved;
    if (saved) {
      console.log("intent.tsx: 中转文件已保存到 File Store", accessiblePath);
    }
  }

  // ── 5. 打开文件（使用 accessiblePath） ──
  try {
    await ensureLocalFile(accessiblePath);
  } catch (e) {
    console.error("ensureLocalFile 失败:", e);
    return;
  }

  const ext = Path.extname(accessiblePath);
  const category = getFileCategory(ext);

  let targetSize = fileSize;
  if (saved) {
    try {
      targetSize = (await FileManager.stat(accessiblePath)).size;
    } catch {}
  }

  const prefix = await resolveOpenerForFile(accessiblePath, category);
  if (!prefix) {
    return;
  }

  if (prefix === "editor:" || prefix === "preview:") {
    await Navigation.present({
      element: (
        <EditorPage
          path={accessiblePath}
          fileName={Path.basename(accessiblePath)}
          fileSize={targetSize}
          mode="present"
        />
      ),
      modalPresentationStyle: prefix === "editor:" ? "overFullScreen" : undefined,
    });
  } else if (prefix === "archive:") {
    await Navigation.present({
      element: <ArchiveBrowserPage filePath={accessiblePath} />,
    });
  } else if (prefix === "video:") {
    await Navigation.present({
      element: <VideoViewerPage filePath={accessiblePath} />,
    });
  } else if (prefix === "image:") {
    await Navigation.present({
      element: <ImageViewer filePath={accessiblePath} />,
    });
  } else if (prefix === "livephoto:") {
    await Navigation.present({
      element: <LivePhotoPreviewPage livePath={accessiblePath} />,
    });
  } else if (prefix === "extract:") {
    const parentDir = Path.dirname(accessiblePath);
    await safeUnzip(accessiblePath, parentDir);
  } else if (prefix === "extractfolder:") {
    const archiveName = sanitizeExtractDirName(Path.basename(accessiblePath));
    const parentDir = Path.dirname(accessiblePath);
    let extractDir = Path.join(parentDir, archiveName);
    if (await FileManager.exists(extractDir)) {
      let counter = 1;
      while (await FileManager.exists(Path.join(parentDir, `${archiveName}_${String(counter).padStart(2, "0")}`))) {
        counter++;
      }
      extractDir = Path.join(parentDir, `${archiveName}_${String(counter).padStart(2, "0")}`);
    }
    await FileManager.createDirectory(extractDir, true);
    await FileManager.unzip(accessiblePath, extractDir);
  }

  } catch (error) {
    console.error("无法打开外部文件:", error);
  } finally {
    Script.exit();
  }
}
void run();
