// npm 依赖自动安装：检测 prettier / terser 是否可用，缺失时弹出居中的“安装中”页面自动安装，完成后自动关闭并通知
import { Script, Notification, Navigation } from "scripting"
import { showToast } from "./ToastManager"
import { InstallingView } from "../view/InstallingView"

/** 与 package.json dependencies 保持一致 */
const REQUIRED_PACKAGES = ["prettier", "terser"]

/** 判断某个 npm 包当前是否可被 require（Scripting 将依赖全局安装到 App Group，不装到脚本目录） */
function isPackageInstalled(name: string): boolean {
  try {
    require(name)
    return true
  } catch {
    return false
  }
}

/**
 * 运行前检查 npm 依赖是否已安装，缺失则弹出居中的“安装中”页面并自动安装，完成后页面自动关闭并通知。
 * @returns 依赖已就绪（或安装流程已启动）返回 true；检查失败返回 false
 */
export async function ensureNpmDependencies(): Promise<boolean> {
  try {
    const missing = REQUIRED_PACKAGES.filter((name) => !isPackageInstalled(name))
    if (missing.length === 0) return true

    // 等 ToastOverlay 监听就绪后再提示
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 150))
    showToast("检测到缺少运行环境")

    // 弹出居中的“安装中”页面，页面内自动执行安装，完成后自动关闭
    await Navigation.present({
      element: <InstallingView install={() => runInstall(missing)} />,
      modalPresentationStyle: "formSheet",
    })
    return true
  } catch (e) {
    console.error("检查 npm 依赖失败:", e)
    try {
      showToast("运行环境检查失败")
    } catch {}
    return false
  }
}

/** 执行 npm install（Shell.run 异步执行，不阻塞 UI），完成后复查依赖并发送系统通知 */
async function runInstall(missing: string[]): Promise<boolean> {
  try {
    console.log(`缺少 npm 依赖: ${missing.join(", ")}，执行 npm install …`)
    const result = await Shell.run("npm install", {
      cwd: Script.directory,
      timeout: 300,
    })
    if (result.timedOut || result.exitCode !== 0) {
      console.error(`npm install 失败 (exitCode=${result.exitCode}, timedOut=${result.timedOut}):`, result.output)
      showToast("运行环境安装失败")
      await notify("FileStore 运行环境安装失败", "请检查网络后重新打开 FileStore 重试")
      return false
    }

    // npm 在找不到 package.json 时也会返回 exitCode=0，必须复查依赖是否真的可用
    const stillMissing = REQUIRED_PACKAGES.filter((name) => !isPackageInstalled(name))
    if (stillMissing.length > 0) {
      console.error("npm install 返回成功但依赖仍不可用:", stillMissing.join(", "), result.output)
      showToast("运行环境安装失败")
      await notify("FileStore 运行环境安装失败", `仍缺少: ${stillMissing.join(", ")}`)
      return false
    }

    showToast("运行环境安装完成")
    await notify("FileStore 运行环境安装完成", "所有功能已可用")
    return true
  } catch (e) {
    console.error("运行环境安装失败:", e)
    try {
      showToast("运行环境安装失败")
    } catch {}
    return false
  }
}

/** 发送本地系统通知（无论 app 是否在前台都能收到）；失败时仅记录日志 */
async function notify(title: string, body: string) {
  try {
    await Notification.schedule({ title, body })
  } catch (e) {
    console.error("发送通知失败:", e)
  }
}
