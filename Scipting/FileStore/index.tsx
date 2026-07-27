// 文件管理器 - 主入口

import { Script, Intent, Navigation, Path } from "scripting";
import { getFileInfo, readTextFile } from "./manager/utils";
import { FilePreviewView } from "./view/FilePreview";
import { ArchiveBrowserPage, ImageViewer, VideoViewerPage, LivePhotoPreviewPage } from "./view/MediaViewer";
import { HomeView } from "./view/preview";
import { openEditorDirectly } from "./view/EditorDirectly";
import { EditorPage } from "./view/EditorPage";
import { resolveOpenerForFile } from "./view/DefaultOpenerPicker";

/** 清理 _intent_transfer/ 中超过 maxAgeMs 的旧文件 */
async function cleanupTransferDir(maxAgeMs = 60 * 1000) {
  const dir = Path.join(FileManager.appGroupDocumentsDirectory, "_intent_transfer");
  try {
    if (!(await FileManager.exists(dir))) return;
    const entries = await FileManager.readDirectory(dir);
    const now = Date.now();
    for (const name of entries) {
      try {
        const fullPath = Path.join(dir, name);
        const stat = await FileManager.stat(fullPath);
        // modificationDate 可能是秒或毫秒，统一转为毫秒比较
        const raw = stat.modificationDate;
        if (!raw) continue; // modificationDate 为 0 表示 stat 异常，跳过不删
        const modMs = raw > 1e12 ? raw : raw * 1000;
        if (now - modMs > maxAgeMs) {
          await FileManager.remove(fullPath);
        }
      } catch {}
    }
  } catch {}
}

async function run() {
  // URL Scheme 跳转回来的是刚 copy 的文件，跳过清理避免误删
  const queryFileURL = Script.queryParameters?.fileURL as string | undefined;
  if (!queryFileURL) {
    await cleanupTransferDir();
  }

  // 检查是否有通过 Intent 传入的文件，或通过 URL Scheme 跳转回来的大文件
  const intentFiles = Intent.fileURLsParameter;
  const filePath = intentFiles?.[0] ?? queryFileURL;
  if (filePath) {
    try {
      const fileInfo = await getFileInfo(filePath);
      const cat = fileInfo.category;

      // ── 来自 URL Scheme 的大文件（跳转回来的）：和 intent.tsx 一样用 resolveOpenerForFile ──
      if (queryFileURL) {
        const prefix = await resolveOpenerForFile(filePath, cat);
        if (!prefix) {
          // 清理临时文件
          try { await FileManager.remove(filePath); } catch {}
          Script.exit();
          return;
        }

        // 不在这里删文件 — Navigation.present 只是挂载 view，
        // EditorPage 等 viewer 的 useEffect 还没读文件内容。
        // 由下次启动时 cleanupTransferDir() 统一清理旧文件。
        if (prefix === "editor:" || prefix === "preview:") {
          await Navigation.present({
            element: (
              <EditorPage
                path={filePath}
                fileName={fileInfo.name}
                fileSize={fileInfo.size}
                mode="present"
              />
            ),
            modalPresentationStyle: prefix === "editor:" ? "overFullScreen" : undefined,
          });
        } else if (prefix === "archive:") {
          await Navigation.present({ element: <ArchiveBrowserPage filePath={filePath} /> });
        } else if (prefix === "video:") {
          await Navigation.present({ element: <VideoViewerPage filePath={filePath} /> });
        } else if (prefix === "image:") {
          await Navigation.present({ element: <ImageViewer filePath={filePath} /> });
        } else if (prefix === "livephoto:") {
          await Navigation.present({ element: <LivePhotoPreviewPage livePath={filePath} /> });
        } else {
          await Navigation.present({
            element: <FilePreviewView fileInfo={fileInfo} content={null} />,
            modalPresentationStyle: "fullScreen",
          });
        }
        Script.exit();
        return;
      }

      // ── 来自 Intent 的文件：保持原有逻辑 ──
      let content: string | null = null;
      if (cat === "text" || cat === "code" || cat === "data") {
        content = await readTextFile(filePath);
      }

      if (content !== null) {
        await openEditorDirectly(fileInfo, content);
        Script.exit();
        return;
      }

      await Navigation.present({
        element: cat === "archive" ? <ArchiveBrowserPage filePath={filePath} /> : <FilePreviewView fileInfo={fileInfo} content={content} />,
        modalPresentationStyle: "fullScreen",
      });
      Script.exit();
      return;
    } catch (e) {
      console.log("预览文件失败:", e);
    }
  }

  await Navigation.present({
    element: <HomeView />,
    modalPresentationStyle: "fullScreen",
  });
}

run();
