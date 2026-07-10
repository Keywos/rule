// 文件管理器 - 主入口

import { Script, Intent, Navigation } from "scripting";
import { getFileInfo, readTextFile } from "./manager/utils";
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
        content = await readTextFile(filePath);
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
