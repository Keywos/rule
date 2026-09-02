import { AppIntentManager, AppIntentProtocol, Widget } from "scripting";

export const RefreshWidgetIntent = AppIntentManager.register({
  name: "RefreshWidgetIntent",
  protocol: AppIntentProtocol.AppIntent,
  perform: async () => {
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
