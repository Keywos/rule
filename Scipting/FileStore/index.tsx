// 文件管理器 - 主入口

import { Script, Intent, Navigation } from "scripting";
import { getFileInfo } from "./manager/utils";
import { FilePreviewView } from "./view/FilePreview";
import { HomeView } from "./view/preview";
import { openEditorDirectly } from "./view/EditorDirectly";

async function run() {
  // 检查是否有通过 Intent 传入的文件
  const intentFiles = Intent.fileURLsParameter;
  if (intentFiles && intentFiles.length > 0) {
    const filePath = intentFiles[0];
    try {
      const fileInfo = await getFileInfo(filePath);
      let content: string | null = null;

      const cat = fileInfo.category;
      if (cat === "text" || cat === "code" || cat === "data") {
        try {
          // 先试不传 encoding（系统自动检测/默认 UTF-8）
          try {
            content = await FileManager.readAsString(filePath);
          } catch {
            for (const enc of ["utf8", "utf-16", "ascii"] as const) {
              try {
                const text = await FileManager.readAsString(filePath, enc);
                if (text != null) {
                  content = text;
                  break;
                }
              } catch {}
            }
            // 如果以上都失败，尝试 'utf-8'
            if (!content) {
              try {
                content = await FileManager.readAsString(filePath, "utf-8");
              } catch {}
            }
          }
        } catch {}
      }

      // 文本/代码文件：直接调用 controller.present()，只弹一层
      if (content !== null) {
        await openEditorDirectly(fileInfo, content);
        Script.exit();
        return;
      }

      // 其他文件类型：用 Navigation.present()
      await Navigation.present({
        element: <FilePreviewView fileInfo={fileInfo} content={content} />,
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
