import { Intent, Navigation, Script, Text, VStack } from "scripting"

const params = {
  texts: Intent.textsParameter,
  urls: Intent.urlsParameter,
  images: Intent.imagesParameter?.length ?? 0,
  fileURLs: Intent.fileURLsParameter,
  shortcut: Intent.shortcutParameter,
}

function View() {
  return <VStack>
    <Text>{
      JSON.stringify(params)
    }</Text>
  </VStack>
}

async function presentIntentView() {
  await Navigation.present({
    element: <View />
  })

  // Returns nothing
  Script.exit()
}

async function runIntent() {
  // Use Script.exit to return a result.
  Script.exit(
    // Intent.text("some text")
    Intent.json(params)
    // Intent.url("https://example.com")
    // Intent.file("/path/to/file")
  )
}

// presentIntentView()
runIntent()