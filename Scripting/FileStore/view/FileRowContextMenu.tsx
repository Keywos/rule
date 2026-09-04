import {
  ControlGroup,
  Divider,
  EmptyView,
  Group,
  Menu,
  Button,
  Navigation,
  Path,
} from "scripting";
import { FileInfo, getFileCategory } from "../manager/utils";
import { ArchiveBrowserPage } from "./MediaViewer";
import { setDefaultOpener, OPENER_OPTIONS } from "../manager/DefaultOpener";
import { isLivePhotoFile, unpackLivePhoto } from "../manager/LivePhotoPacker";
import { showToast } from "../manager/ToastManager";
import { FileInfoDialog } from "./FileListItem";

export interface FileRowContextMenuProps {
  file: FileInfo;
  defaultOpener: string | null;
  isLivePhoto: boolean;
  isImage: boolean;
  isVideo: boolean;
  isPreviewableText: boolean;
  isMarkdown: boolean;
  extractFolderName: string;
  copyToDirTitle?: string;
  onCopyPath?: (path: string) => void;
  onCopyToDir?: (path: string) => void;
  onRefresh: () => void;
  onRename: () => void;
  onDelete: () => void;
  onShare: () => void;
  onOpenEditor: () => void;
  onExtractToFolder: () => void;
  onPlainZipCompress: () => void;
  onZipCompress: () => void;
  onSevenZCompress: () => void;
  navPath?: any;
  dirPath?: string;
}

export function FileRowContextMenu({
  file,
  defaultOpener,
  isLivePhoto,
  isImage,
  isVideo,
  isPreviewableText,
  isMarkdown,
  extractFolderName,
  copyToDirTitle,
  onCopyPath,
  onCopyToDir,
  onRefresh,
  onRename,
  onDelete,
  onShare,
  onOpenEditor,
  onExtractToFolder,
  onPlainZipCompress,
  onZipCompress,
  onSevenZCompress,
  navPath,
  dirPath,
}: FileRowContextMenuProps) {
  const handleShowInfo = () => {
    Navigation.present({ element: <FileInfoDialog file={file} />, modalPresentationStyle: "pageSheet" });
  };

  return (
    <Group>
      <ControlGroup>
        <Button title="拷贝" systemImage="doc.on.doc" action={async () => { await onCopyPath?.(file.path); }} />
        <Button title="重命名" systemImage="pencil" action={onRename} />
        <Button title="分享" systemImage="square.and.arrow.up" action={onShare} />
      </ControlGroup>
      {isLivePhoto ? (
        <Button
          title="保存到相册"
          systemImage="square.and.arrow.down"
          action={async () => {
            let tmpImg: string | null = null;
            let tmpVid: string | null = null;
            try {
              const data = await FileManager.readAsData(file.path);
              if (!data) {
                showToast("读取文件失败");
                return;
              }
              const unpacked = unpackLivePhoto(data);
              if (!unpacked) {
                showToast("Live Photo 格式无效");
                return;
              }
              const tmpDir = FileManager.temporaryDirectory;
              tmpImg = tmpDir + `/_lp_save_${Date.now()}.${unpacked.imageExt}`;
              tmpVid = tmpDir + `/_lp_save_${Date.now()}.mov`;
              await FileManager.writeAsData(tmpImg, unpacked.imageData);
              await FileManager.writeAsData(tmpVid, unpacked.videoData);
              await Photos.saveLivePhoto({ imagePath: tmpImg, videoPath: tmpVid });
              showToast("已保存到相册");
            } catch (e) {
              console.log("保存到相册失败:", e);
              showToast("保存失败");
            } finally {
              if (tmpImg) try { await FileManager.remove(tmpImg); } catch { }
              if (tmpVid) try { await FileManager.remove(tmpVid); } catch { }
            }
          }}
        />
      ) : <EmptyView />}
      {isImage ? (
        <Button title="保存到相册" systemImage="square.and.arrow.down" action={async () => {
          try {
            await Photos.savePhoto(file.path);
            showToast("已保存到相册");
          } catch (e) {
            console.log("保存图片失败:", e);
            showToast("保存失败");
          }
        }} />
      ) : <EmptyView />}
      {isVideo ? (
        <Button title="导出到相册" systemImage="square.and.arrow.down" action={async () => {
          try {
            await Photos.saveVideo(file.path);
            showToast("已导出到相册");
          } catch (e) {
            console.log("导出视频失败:", e);
            showToast("导出失败");
          }
        }} />
      ) : <EmptyView />}
      {isPreviewableText ? (
        <>
          {isMarkdown ? (
            <Button title="预览 Markdown" systemImage="doc.text.magnifyingglass" action={() => {
              navPath?.setValue([...navPath.value, "markdown:" + file.path]);
            }} />
          ) : (
            <Button title="预览网页" systemImage="safari" action={async () => {
              const wv = new WebViewController();
              await wv.loadFile(file.path);
              await wv.present({ fullscreen: true, navigationTitle: file.name });
              wv.dispose();
            }} />
          )}
          <Button title="编辑" systemImage="chevron.left.forwardslash.chevron.right" action={onOpenEditor} />
          <Divider />
        </>
      ) : <EmptyView />}
      {copyToDirTitle && onCopyToDir ? (
        <Button title={copyToDirTitle} systemImage="arrow.right.doc.on.clipboard" action={() => onCopyToDir(file.path)} />
      ) : <EmptyView />}
      {getFileCategory(file.extension) === "archive" ? (
        <>
          <Button title="查看压缩文件" systemImage="archivebox.fill" action={() => {
            Navigation.present({ element: <ArchiveBrowserPage filePath={file.path} />, modalPresentationStyle: "pageSheet" });
          }} />
          <Divider />
        </>
      ) : <EmptyView />}
      {!file.isDirectory ? (
        <Button title={`解压到（${extractFolderName}）`} systemImage="lock.open" action={onExtractToFolder} />
      ) : <EmptyView />}
      <Button title="压缩" systemImage="shippingbox" action={onPlainZipCompress} />
      <Button title="ZIP 加密压缩 (AES-256)" systemImage="lock.doc" action={onZipCompress} />
      <Button title="7z 加密压缩 (AES-256)" systemImage="lock.doc" action={onSevenZCompress} />
      <Divider />
      {!file.isDirectory ? (
        <Menu title="默认打开方式" systemImage="gear">
          {OPENER_OPTIONS.map((opt) => (
            <Button
              title={opt.label}
              systemImage={defaultOpener === opt.prefix ? "checkmark" : undefined}
              action={async () => {
                setDefaultOpener(Path.extname(file.path), opt.prefix);
                onRefresh();
              }}
            />
          ))}
        </Menu>
      ) : <EmptyView />}
      <Button title="简介" systemImage="info.circle" action={handleShowInfo} />
      <Button title="删除" systemImage="trash" role="destructive" action={onDelete} />
    </Group>
  );
}
