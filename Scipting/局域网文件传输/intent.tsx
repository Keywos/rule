import { Intent, Navigation, NavigationStack, Script } from "scripting";
import { share } from "./class/share";
import { View } from "./page";

(async () => {
  const paths = [...(Intent.fileURLsParameter ?? []), ...(Intent.imagePathsParameter ?? [])];
  if (paths.length === 0) return;
  if (!share.ip) throw new Error("当前不处于局域网");
  const started = await BackgroundKeeper.keepAlive();
  await Navigation.present({
    element: (
      <NavigationStack>
        <View link={await share.getLink(paths)} />
      </NavigationStack>
    ),
    modalPresentationStyle: "pageSheet",
  });
  if (started) await BackgroundKeeper.stopKeepAlive();
})()
  .catch(async (e) => {
    await Dialog.alert({ title: "错误", message: String(e) });
  })
  .finally(() => Script.exit());
