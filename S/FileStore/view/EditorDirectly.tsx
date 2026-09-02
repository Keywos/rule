import { Navigation } from "scripting";
import type { FileInfo } from "../manager/utils";
import { EditorPage } from "./EditorPage";

export async function openEditorDirectly(fileInfo: FileInfo, content: string): Promise<void> {
  await new Promise<void>((resolve) => {
    Navigation.present({
      element: <EditorPage path={fileInfo.path} content={content} fileName={fileInfo.name} mode="present" onClose={resolve} />,
      modalPresentationStyle: "overFullScreen",
    });
  });
}
