import { Navigation, NavigationStack, Script } from "scripting";
import { View } from "./page";
import { share } from "./class/share";

(async () => {
  if (!share.ip) throw new Error("当前不处于局域网");

  const paths = await DocumentPicker.pickFiles({
    allowsMultipleSelection: true,
  });
  if (paths.length === 0) return;

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
  .finally(Script.exit);
