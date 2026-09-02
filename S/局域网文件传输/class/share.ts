import { Path } from "scripting";

type SharedFile = {
  name: string;
  size: number;
};

class Share {
  private server = new HttpServer();
  private cashePath = Path.join(FileManager.temporaryDirectory, "current");
  private zipPath = Path.join(FileManager.temporaryDirectory, "scripting.zip");
  ip = Device.networkInterfaces()?.en0?.filter((i) => i.family === "IPv4")[0].address;

  async getLink(paths: string[]) {
    const files = await Promise.all(
      paths.map(async (path) => ({
        name: Path.basename(path),
        size: (await FileManager.stat(path)).size,
      })),
    );
    // 页面始终保留 ZIP 下载，同时为每个原始文件提供独立下载入口。
    if (await FileManager.exists(this.cashePath)) await FileManager.remove(this.cashePath);
    await FileManager.createDirectory(this.cashePath, true);
    await Promise.all(
      paths.map((path) => FileManager.copyFile(path, Path.join(this.cashePath, Path.basename(path)))),
    );
    if (await FileManager.exists(this.zipPath)) await FileManager.remove(this.zipPath);
    await FileManager.zip(this.cashePath, this.zipPath);

    this.server = new HttpServer();
    let error = this.server.start({ port: 60000 });
    if (error) {
      this.server = new HttpServer();
      error = this.server.start({ port: 0 });
    }
    if (error) throw new Error(`HTTP 服务启动失败：${error}`);

    const port = this.server.port;
    if (typeof port !== "number") throw new Error("HTTP 服务未能获取端口");

    this.server.registerFile("/download", this.zipPath);
    paths.forEach((path, index) => this.server.registerFile(`/file/${index}`, path));
    this.server.registerHandler("/", () => HttpResponse.ok(HttpResponseBody.html(this.createPage(files))));

    return `http://${this.ip}:${port}`;
  }

  private createPage(files: SharedFile[]) {
    const totalSize = files.reduce((total, file) => total + file.size, 0);
    const fileRows = files
      .map(
        (file, index) => `
          <li class="file-item">
            <span class="file-icon" aria-hidden="true">${this.fileIcon(file.name)}</span>
            <span class="file-name">${this.escapeHtml(file.name)}</span>
            <span class="file-size">${this.formatSize(file.size)}</span>
            <a class="file-download" href="/file/${index}" download="${this.escapeHtml(file.name)}" aria-label="下载 ${this.escapeHtml(file.name)}">↓</a>
          </li>`,
      )
      .join("");
    const description = "可单独下载文件，或一次下载 ZIP 压缩包";

    return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport"
    content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="color-scheme" content="light dark" />
  <meta name="theme-color" media="(prefers-color-scheme: light)" content="#f5f5f7" />
  <meta name="theme-color" media="(prefers-color-scheme: dark)" content="#141414" />
  <title>文件分享</title>
  <style>
    :root { color-scheme: light dark; --bg: #f5f5f7; --glow: radial-gradient(ellipse at center, color-mix(in srgb, var(--accent) 2%, transparent) 0%, color-mix(in srgb, var(--accent) 1%, transparent) 42%, transparent 72%); --card: rgba(255,255,255,.26); --text: #1d1d1f; --muted: #6e6e73; --line: rgba(60,60,67,.05); --accent: #007aff; --accent-text: #fff; --icon: rgba(232,242,255,.42); }
    @media (prefers-color-scheme: dark) { :root { --bg: #141414; --glow: radial-gradient(ellipse at center, rgba(83, 71, 124, .22) 0%, rgba(77, 65, 112, .12) 30%, rgba(73, 61, 103, .04) 58%, transparent 82%); --card: rgba(22,25,42,.3); --text: #f5f5f7; --muted: #b5b6c8; --line: rgba(255,255,255,.05); --accent: #8aaef0; --icon: rgba(65,75,112,.3); } }
    * { box-sizing: border-box; }
    html { min-height: 100%; background: var(--bg); }
    body { margin: 0; min-height: 100%; min-height: 100dvh; display: grid; place-items: center; padding: env(safe-area-inset-top) 0 env(safe-area-inset-bottom); background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", sans-serif; }
    main { position: relative; isolation: isolate; width: min(100% - 32px, 620px); margin: 32px 0; }
    main::before { content: ""; position: absolute; z-index: -1; inset: -72px -64px -96px; border-radius: 50%; background: var(--glow); filter: blur(20px); pointer-events: none; }
    .card { overflow: hidden; border: 1px solid var(--line); border-radius: 24px; background: var(--card); box-shadow: 0 18px 50px rgba(0,0,0,.12); backdrop-filter: blur(28px) saturate(150%); -webkit-backdrop-filter: blur(28px) saturate(150%); }
    header { padding: 30px 28px 22px; text-align: center; }
    .share-icon { width: 56px; height: 56px; margin: 0 auto 16px; display: grid; place-items: center; border-radius: 17px; background: var(--accent); color: #fff; font-size: 28px; }
    h1 { margin: 0; font-size: 24px; letter-spacing: -.4px; } p { margin: 9px 0 0; color: var(--muted); font-size: 14px; line-height: 1.5; }
    .summary { display: flex; justify-content: center; gap: 8px; margin-top: 13px; color: var(--muted); font-size: 13px; } .dot { opacity: .55; }
    ul { margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--line); }
    .file-item { display: grid; grid-template-columns: 40px minmax(0,1fr) auto 34px; align-items: center; gap: 12px; padding: 14px 20px; border-bottom: 1px solid var(--line); }
    .file-icon { display: grid; place-items: center; width: 40px; height: 40px; border-radius: 12px; background: var(--icon); font-size: 19px; } .file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 15px; font-weight: 500; } .file-size { color: var(--muted); font-size: 13px; white-space: nowrap; } .file-download { display: grid; place-items: center; width: 34px; height: 34px; border-radius: 10px; color: var(--accent); background: var(--icon); text-decoration: none; font-size: 18px; } .file-download:active { opacity: .65; }
    .footer { padding: 20px; } a.download { display: flex; justify-content: center; align-items: center; gap: 8px; min-height: 50px; border-radius: 14px; background: var(--accent); color: var(--accent-text); text-decoration: none; font-weight: 600; font-size: 16px; } a.download:active { opacity: .75; transform: scale(.99); }
  </style>
</head>
<body><main><section class="card">
  <header><div class="share-icon">↓</div><h1>文件分享</h1><p>${description}</p><div class="summary"><span>${files.length} 个文件</span><span class="dot">·</span><span>${this.formatSize(totalSize)}</span></div></header>
  <ul>${fileRows}</ul>
  <div class="footer"><a class="download" href="/download" download="scripting.zip">↓ 下载 ZIP 压缩包</a></div>
</section></main></body>
</html>`;
  }

  private escapeHtml(value: string) {
    return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]!);
  }

  private formatSize(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB", "TB"];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
    return `${(bytes / 1024 ** (index + 1)).toFixed(bytes >= 1024 ** (index + 2) ? 1 : 0)} ${units[index]}`;
  }

  private fileIcon(name: string) {
    const ext = name.split(".").pop()?.toLowerCase();
    if (["jpg", "jpeg", "png", "gif", "webp", "heic"].includes(ext ?? "")) return "🖼️";
    if (["mp4", "mov", "mkv", "avi"].includes(ext ?? "")) return "🎬";
    if (["mp3", "m4a", "wav", "flac"].includes(ext ?? "")) return "🎵";
    if (["pdf"].includes(ext ?? "")) return "📕";
    if (["zip", "rar", "7z", "tar", "gz"].includes(ext ?? "")) return "🗜️";
    return "📄";
  }
}

export const share = new Share();
