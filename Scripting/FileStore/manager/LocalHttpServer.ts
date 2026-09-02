// 本项目内 HTTP Server 管理模块。
// 服务实例与当前脚本生命周期绑定：有服务时主脚本可最小化保活，无服务时可完全退出。

import { Path } from "scripting";

interface ServerEntry {
  directory: string;
  port: number;
  url: string;
  server: HttpServer;
}

const servers: ServerEntry[] = [];
const listeners: Array<() => void> = [];
let keepAliveRequested = false;

function notifyListeners() {
  for (const listener of [...listeners]) listener();
}

async function updateKeepAlive() {
  const hasServers = servers.some((entry) => entry.server.state === "running");
  if (hasServers && !keepAliveRequested) {
    try {
      keepAliveRequested = await BackgroundKeeper.keepAlive();
    } catch {
      keepAliveRequested = false;
    }
    return;
  }
  if (!hasServers) {
    // stopKeepAlive 只释放当前项目实例的请求；即使标记丢失也要尝试释放，
    // 避免无 HTTP 服务时仍遗留在后台保活队列中。
    try {
      await BackgroundKeeper.stopKeepAlive();
    } catch {}
    keepAliveRequested = false;
  }
}

async function registerFilesRecursive(server: HttpServer, rootDir: string, currentDir: string): Promise<void> {
  let entries: string[] = [];
  try {
    entries = await FileManager.readDirectory(currentDir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const filePath = Path.join(currentDir, entry);
    try {
      if (await FileManager.isDirectory(filePath)) {
        await registerFilesRecursive(server, rootDir, filePath);
        continue;
      }
      const relativePath = filePath.slice(rootDir.length).replace(/^\/+/, "");
      server.registerFile(`/${relativePath}`, filePath);
    } catch {
      // 单个不可读取文件不影响其他静态文件的注册。
    }
  }
}

export interface ActiveServerInfo {
  directory: string;
  port: number;
  url: string;
}

/** 订阅本项目内 HTTP 服务变更，双列目录会共同收到通知。 */
export function subscribe(listener: () => void): () => void {
  listeners.push(listener);
  return () => {
    const index = listeners.indexOf(listener);
    if (index !== -1) listeners.splice(index, 1);
  };
}

export async function startLocalHttpServer(directory: string): Promise<string> {
  const existing = servers.find((entry) => entry.directory === directory && entry.server.state === "running");
  if (existing) return existing.url;

  const indexPath = (await FileManager.exists(Path.join(directory, "index.html")))
    ? Path.join(directory, "index.html")
    : Path.join(directory, "index.htm");
  if (!(await FileManager.exists(indexPath))) throw new Error("当前目录没有 index.html 入口");

  const server = new HttpServer();
  server.registerFile("/", indexPath);
  await registerFilesRecursive(server, directory, directory);

  let error = server.start({ port: 8080, forceIPv4: true });
  if (error) error = server.start({ port: 0, forceIPv4: true });
  if (error || server.port == null) throw new Error(error || "未能取得 HTTP 服务端口");

  const entry: ServerEntry = {
    directory,
    port: server.port,
    url: `http://127.0.0.1:${server.port}`,
    server,
  };
  servers.push(entry);
  await updateKeepAlive();
  notifyListeners();
  return entry.url;
}

export function getActiveServers(): ActiveServerInfo[] {
  return servers
    .filter((entry) => entry.server.state === "running")
    .map(({ directory, port, url }) => ({ directory, port, url }));
}

export async function stopServer(directory: string): Promise<boolean> {
  const index = servers.findIndex((entry) => entry.directory === directory);
  if (index === -1) return false;
  try {
    servers[index].server.stop();
  } catch {}
  servers.splice(index, 1);
  await updateKeepAlive();
  notifyListeners();
  return true;
}

export async function stopAllServers(): Promise<void> {
  for (const entry of servers) {
    try {
      entry.server.stop();
    } catch {}
  }
  servers.length = 0;
  await updateKeepAlive();
  notifyListeners();
}

export function hasActiveServers(): boolean {
  return servers.some((entry) => entry.server.state === "running");
}

export function getServerCount(): number {
  return getActiveServers().length;
}

/** 无 HTTP 服务时释放本项目申请的后台保活。 */
export async function stopHttpBackgroundIfIdle(): Promise<void> {
  await updateKeepAlive();
}
