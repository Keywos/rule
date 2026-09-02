import { Script, Navigation } from "scripting"
import { App } from "./app"

async function run() {
  await Navigation.present({
    element: <App />,
    modalPresentationStyle: "pageSheet",
  })
  Script.exit()
}

run()
