// 文件管理器 - 主入口

import { Script, Intent, Navigation, Path } from "scripting";
import { getFileInfo, readTextFile, copyFileToFileStore, uniquePath } from "./manager/utils";
import { packLivePhoto } from "./manager/LivePhotoPacker";
import { showToast } from "./manager/ToastManager";
import { FilePreviewView } from "./view/FilePreview";
import { ArchiveBrowserPage, ImageViewer, VideoViewerPage, LivePhotoPreviewPage } from "./view/MediaViewer";
import { HomeView } from "./view/preview";
import { openEditorDirectly } from "./view/EditorDirectly";
import { EditorPage } from "./view/EditorPage";
import { resolveOpenerForFile } from "./view/DefaultOpenerPicker";

async function run() {
  // 检查 URL Scheme 动作：编辑器“保存到 File Store”（经 appGroup 中转的内容）
  const action = Script.queryParameters?.action as string | undefined;
  const queryFileURL = Script.queryParameters?.fileURL as string | undefined;
  if (action === "saveToFileStore" && queryFileURL) {
    try {
      const content = await FileManager.readAsString(queryFileURL);
      const srcName = Path.basename(queryFileURL);
      const fileStoreDir = Path.join(FileManager.documentsDirectory, "File Store");
      await FileManager.createDirectory(fileStoreDir, true);
      let destPath = Path.join(fileStoreDir, srcName);
      destPath = await uniquePath(destPath);
      await FileManager.writeAsString(destPath, content);
      // 保存成功后打开 EditorPage 展示文件，让用户确认保存结果
      await Navigation.present({
        element: (
          <EditorPage
            path={destPath}
            fileName={srcName}
            mode="present"
            savedMessage="已保存到 File Store"
          />
        ),
        modalPresentationStyle: "overFullScreen",
      });
    } catch (e) {
      console.log("saveToFileStore 失败:", e);
      await Navigation.present({
        element: <HomeView initialToast="保存到 File Store 失败" />,
        modalPresentationStyle: "overFullScreen",
      });
    }
    Script.exit();
    return;
  }

  // 实况照片导入：主 App 读取原始图片 + MOV 资源，打包为 FileStore 的 .live 文件
  const liveImagePath = Script.queryParameters?.imagePath as string | undefined;
  const liveVideoPath = Script.queryParameters?.videoPath as string | undefined;
  if (action === "importLivePhoto" && liveImagePath && liveVideoPath) {
    try {
      const imageData = await FileManager.readAsData(liveImagePath);
      const videoData = await FileManager.readAsData(liveVideoPath);
      if (!imageData || !videoData) throw new Error("无法读取实况照片的图片或视频资源");
      const fileStoreDir = Path.join(FileManager.documentsDirectory, "File Store");
      await FileManager.createDirectory(fileStoreDir, true);
      const ext = Path.extname(liveImagePath).replace(/^\./, "").toLowerCase() || "heic";
      const baseName = Path.basename(liveImagePath, Path.extname(liveImagePath));
      const destPath = await uniquePath(Path.join(fileStoreDir, `${baseName}.live`));
      await FileManager.writeAsData(destPath, packLivePhoto(imageData, ext, videoData));
      await Navigation.present({
        element: <HomeView initialLeftPath={fileStoreDir} initialToast="实况照片已保存到 File Store" />,
        modalPresentationStyle: "overFullScreen",
      });
    } catch (e) {
      console.log("importLivePhoto 失败:", e);
      await Navigation.present({
        element: <HomeView initialLeftPath={Path.join(FileManager.documentsDirectory, "File Store")} initialToast="实况照片保存失败" />,
        modalPresentationStyle: "overFullScreen",
      });
    }
    Script.exit();
    return;
  }

  // 非文本文件导入：保存到 File Store 后打开主界面，用户可立即在双栏浏览中看到
  if (action === "importNonText" && queryFileURL) {
    let saved = false;
    try {
      const result = await copyFileToFileStore(queryFileURL);
      saved = result.saved || result.path !== queryFileURL;
      // 中转文件只在确认已复制到 File Store 后删除，避免误删原始分享文件。
      if (saved && queryFileURL.includes("/_intent_transfer/")) {
        try { await FileManager.remove(queryFileURL); } catch {}
      }
    } catch (e) {
      console.log("importNonText 保存失败:", e);
    }
    await Navigation.present({
      element: <HomeView initialLeftPath={Path.join(FileManager.documentsDirectory, "File Store")} initialToast={saved ? "文件已保存到 File Store" : "文件保存失败"} />,
      modalPresentationStyle: "overFullScreen",
    });
    Script.exit();
    return;
  }

  // 检查是否有通过 Intent 传入的文件，或通过 URL Scheme 跳转回来的大文件
  const intentFiles = Intent.fileURLsParameter;
  const filePath = intentFiles?.[0] ?? queryFileURL;
  if (filePath) {
    try {
      const { path: accessiblePath, saved } = await copyFileToFileStore(filePath);

      const fileInfo = await getFileInfo(accessiblePath);
      const cat = fileInfo.category;

      // ── 来自 URL Scheme 的大文件（跳转回来的）：和 intent.tsx 一样用 resolveOpenerForFile ──
      if (queryFileURL) {
        // 保存到 File Store 后，删除 _intent_transfer 中转文件（最终只保留 File Store 副本）
        if (saved && filePath !== accessiblePath) {
          try { await FileManager.remove(filePath); } catch {}
        }

        const prefix = await resolveOpenerForFile(accessiblePath, cat);
        if (!prefix) {
          Script.exit();
          return;
        }

        if (prefix === "editor:" || prefix === "preview:") {
          await Navigation.present({
            element: (
              <EditorPage
                path={accessiblePath}
                fileName={fileInfo.name}
                fileSize={fileInfo.size}
                mode="present"
                savedMessage={saved ? "已保存到 File Store" : undefined}
              />
            ),
            modalPresentationStyle: prefix === "editor:" ? "overFullScreen" : undefined,
          });
        } else if (prefix === "archive:") {
          await Navigation.present({ element: <ArchiveBrowserPage filePath={accessiblePath} /> });
        } else if (prefix === "video:") {
          await Navigation.present({ element: <VideoViewerPage filePath={accessiblePath} /> });
        } else if (prefix === "image:") {
          await Navigation.present({ element: <ImageViewer filePath={accessiblePath} /> });
        } else if (prefix === "livephoto:") {
          await Navigation.present({ element: <LivePhotoPreviewPage livePath={accessiblePath} /> });
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
        content = await readTextFile(accessiblePath);
      }

      if (content !== null) {
        await openEditorDirectly(fileInfo, content, saved ? "已保存到 File Store" : undefined);
        Script.exit();
        return;
      }

      await Navigation.present({
        element: cat === "archive" ? <ArchiveBrowserPage filePath={accessiblePath} /> : <FilePreviewView fileInfo={fileInfo} content={content} />,
        modalPresentationStyle: "overFullScreen",
      });
      Script.exit();
      return;
    } catch (e) {
      console.log("预览文件失败:", e);
    }
  }

  await Navigation.present({
    element: <HomeView />,
    modalPresentationStyle: "overFullScreen",
  });
}

run();
