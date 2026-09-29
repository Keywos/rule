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
import { FileInfo, getFileCategory, invalidateDirectoryCache } from "../manager/utils";
import { ArchiveBrowserPage } from "./MediaViewer";
import { setDefaultOpener, OPENER_OPTIONS } from "../manager/DefaultOpener";
import { unpackLivePhoto, packLivePhoto } from "../manager/LivePhotoPacker";
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
        <>
          <Button
            title="替换图片"
            systemImage="photo.badge.arrow.down"
            action={async () => {
              let imagePath: string | null = null;
              let taggedImagePath: string | null = null;
              try {
                const results = await Photos.pick({ filter: PHPickerFilter.images(), limit: 1 });
                const result = results?.[0];
                if (!result) return;
                imagePath = await result.imagePath();
                if (!imagePath) {
                  showToast("无法读取所选图片");
                  return;
                }
                const imageData = await FileManager.readAsData(imagePath);
                const liveData = await FileManager.readAsData(file.path);
                if (!imageData || !liveData) {
                  showToast("替换图片失败");
                  return;
                }
                const unpacked = unpackLivePhoto(liveData);
                if (!unpacked) {
                  showToast("不是有效的 live 文件");
                  return;
                }

                // 新图片必须带上原 Live Photo 的 asset identifier，才能继续与原视频配对。
                const originalMeta = await ImageIO.readMetadata(unpacked.imageData).catch(() => null);
                const assetIdentifier = originalMeta?.makerApple?.["17"];
                if (typeof assetIdentifier !== "string" || !assetIdentifier) {
                  showToast("原 live 缺少配对信息，无法替换图片");
                  return;
                }

                taggedImagePath = Path.join(FileManager.temporaryDirectory, `_live_replace_${Date.now()}.heic`);
                await ImageIO.writeImage({
                  source: imageData,
                  to: taggedImagePath,
                  format: "heic",
                  metadata: { makerApple: { "17": assetIdentifier } },
                });
                const taggedImageData = await FileManager.readAsData(taggedImagePath);
                if (!taggedImageData) {
                  showToast("无法生成配对图片");
                  return;
                }

                await FileManager.writeAsData(file.path, packLivePhoto(taggedImageData, "heic", unpacked.videoData));
                invalidateDirectoryCache(dirPath || Path.dirname(file.path));
                onRefresh();
                showToast("已替换图片");
              } catch (e) {
                console.log("替换图片失败:", e);
                showToast("替换图片失败");
              } finally {
                if (imagePath) {
                  try { await FileManager.remove(imagePath); } catch { }
                }
                if (taggedImagePath) {
                  try { await FileManager.remove(taggedImagePath); } catch { }
                }
              }
            }}
          />
          <Button
            title="替换视频"
            systemImage="video.badge.plus"
            action={async () => {
              let videoPath: string | null = null;
              const generatedPairPaths: string[] = [];
              try {
                const results = await Photos.pick({ filter: PHPickerFilter.videos(), limit: 1 });
                const result = results?.[0];
                if (!result) return;
                videoPath = await result.videoPath();
                if (!videoPath) {
                  showToast("无法读取所选视频");
                  return;
                }
                const videoData = await FileManager.readAsData(videoPath);
                const liveData = await FileManager.readAsData(file.path);
                if (!videoData || !liveData) {
                  showToast("替换视频失败");
                  return;
                }
                const unpacked = unpackLivePhoto(liveData);
                if (!unpacked) {
                  showToast("不是有效的 live 文件");
                  return;
                }

                // 普通相册视频不一定带 Live Photo 所需的配对元数据，先由系统生成标准配对视频。
                const originalMeta = await ImageIO.readMetadata(unpacked.imageData).catch(() => null);
                const originalAssetIdentifier = originalMeta?.makerApple?.["17"];
                const pair = await LivePhoto.createFromVideo({
                  videoPath,
                  assetIdentifier: typeof originalAssetIdentifier === "string" ? originalAssetIdentifier : undefined,
                  maxDuration: 10,
                  imageFormat: "heic",
                });
                generatedPairPaths.push(pair.imagePath, pair.videoPath);
                const pairedVideoData = await FileManager.readAsData(pair.videoPath);
                if (!pairedVideoData) {
                  showToast("无法生成 Live Photo 视频");
                  return;
                }

                // 原图片没有配对标识时，使用系统生成的配套静态图，确保图片和视频标识匹配。
                let imageData = unpacked.imageData;
                if (typeof originalAssetIdentifier !== "string") {
                  const generatedImageData = await FileManager.readAsData(pair.imagePath);
                  if (generatedImageData) imageData = generatedImageData;
                }
                await FileManager.writeAsData(
                  file.path,
                  packLivePhoto(imageData, typeof originalAssetIdentifier === "string" ? unpacked.imageExt : "heic", pairedVideoData)
                );
                invalidateDirectoryCache(dirPath || Path.dirname(file.path));
                onRefresh();
                showToast("已替换视频");
              } catch (e) {
                console.log("替换视频失败:", e);
                showToast("替换视频失败");
              } finally {
                if (videoPath) {
                  try { await FileManager.remove(videoPath); } catch { }
                }
                for (const generatedPath of generatedPairPaths) {
                  try { await FileManager.remove(generatedPath); } catch { }
                }
              }
            }}
          />
          <Button
            title="提取图片"
            systemImage="photo"
            action={async () => {
              try {
                const data = await FileManager.readAsData(file.path);
                const unpacked = data ? unpackLivePhoto(data) : null;
                if (!unpacked) {
                  showToast("不是有效的 live 文件");
                  return;
                }
                const imagePath = Path.join(Path.dirname(file.path), Path.basename(file.name, ".live") + "." + unpacked.imageExt);
                await FileManager.writeAsData(imagePath, unpacked.imageData);
                invalidateDirectoryCache(dirPath || Path.dirname(file.path));
                onRefresh();
                showToast("已提取图片");
              } catch (e) {
                console.log("提取图片失败:", e);
                showToast("提取图片失败");
              }
            }}
          />
          <Button
            title="提取视频"
            systemImage="video"
            action={async () => {
              try {
                const data = await FileManager.readAsData(file.path);
                const unpacked = data ? unpackLivePhoto(data) : null;
                if (!unpacked) {
                  showToast("不是有效的 live 文件");
                  return;
                }
                const videoPath = Path.join(Path.dirname(file.path), Path.basename(file.name, ".live") + ".mov");
                await FileManager.writeAsData(videoPath, unpacked.videoData);
                invalidateDirectoryCache(dirPath || Path.dirname(file.path));
                onRefresh();
                showToast("已提取视频");
              } catch (e) {
                console.log("提取视频失败:", e);
                showToast("提取视频失败");
              }
            }}
          />
          <Button
            title="导出到相册"
            systemImage="square.and.arrow.down"
            action={async () => {
              let imgTmp: string | null = null;
              let vidTmp: string | null = null;
              try {
                const data = await FileManager.readAsData(file.path);
                const unpacked = data ? unpackLivePhoto(data) : null;
                if (!unpacked) {
                  showToast("不是有效的 live 文件");
                  return;
                }
                const stamp = String(Date.now());
                const baseName = Path.basename(file.name, ".live");
                imgTmp = Path.join(FileManager.temporaryDirectory, `${baseName}_${stamp}.${unpacked.imageExt}`);
                vidTmp = Path.join(FileManager.temporaryDirectory, `${baseName}_${stamp}.mov`);
                await FileManager.writeAsData(imgTmp, unpacked.imageData);
                await FileManager.writeAsData(vidTmp, unpacked.videoData);
                await Photos.saveLivePhoto({ imagePath: imgTmp, videoPath: vidTmp });
                showToast("已导出到相册");
              } catch (e) {
                console.log("导出到相册失败:", e);
                showToast("导出失败");
              } finally {
                if (imgTmp) try { await FileManager.remove(imgTmp); } catch { }
                if (vidTmp) try { await FileManager.remove(vidTmp); } catch { }
              }
            }}
          />
        </>
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
