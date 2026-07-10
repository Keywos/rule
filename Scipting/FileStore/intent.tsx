import { Intent, Navigation, Script, Path } from "scripting";
import { resolveOpenerForFile } from "./view/DefaultOpenerPicker";
import { getFileCategory, sanitizeExtractDirName, safeUnzip, readTextFile, ensureLocalFile } from "./manager/utils";
import { EditorPage } from "./view/EditorPage";
import { ImageViewer, VideoViewerPage, LivePhotoPreviewPage } from "./view/MediaViewer";

async function run() {
  const files = Intent.fileURLsParameter;
  if (!files || files.length === 0) {
    Script.exit();
    return;
  }
  const path = files[0];
  await ensureLocalFile(path);

  const ext = Path.extname(path);
  const category = getFileCategory(ext);

  const prefix = await resolveOpenerForFile(path, category);
  if (!prefix) {
    Script.exit();
    return;
  }

  if (prefix === "editor:" || prefix === "preview:") {
    let fileSize = 0;
    try {
      fileSize = (await FileManager.stat(path)).size;
    } catch {}
    const content = (await readTextFile(path)) ?? undefined;
    await Navigation.present({
      element: (
        <EditorPage
          path={path}
          content={content}
          fileName={Path.basename(path)}
          fileSize={fileSize}
          mode="present"
        />
      ),
      modalPresentationStyle: prefix === "editor:" ? "overFullScreen" : undefined,
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
    // 解压到当前目录
    const parentDir = Path.dirname(path);
    await safeUnzip(path, parentDir);
  } else if (prefix === "extractfolder:") {
    // 解压到以文件名命名的子文件夹
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

  Script.exit();
}
run();
