import { AppIntentManager, AppIntentProtocol, Widget } from "scripting";

/**
 * 刷新小组件数据的 AppIntent
 *
 * 用户点击刷新按钮时触发，重新加载健康数据并更新小组件
 */
export const RefreshWidgetIntent = AppIntentManager.register({
  name: "RefreshWidgetIntent",
  protocol: AppIntentProtocol.AppIntent,
  perform: async () => {
    console.log("用户触发刷新，重新加载小组件...");
    // 重新加载所有小组件
    Widget.reloadAll();
  },
});

export const openAppHealth = AppIntentManager.register({
  name: "openAppHealth",
  protocol: AppIntentProtocol.AppIntent,
  perform: async () => {
    Widget.openApp("com.apple.Health");
  },
});
