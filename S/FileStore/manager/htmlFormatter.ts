/**
 * 轻量 HTML 格式化/压缩工具。
 * script、style、pre 和 textarea 中的原始内容不会被改写。
 */

const RAW_TEXT_TAGS = new Set(["script", "style", "pre", "textarea"])
const VOID_TAGS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img", "input",
  "link", "meta", "param", "source", "track", "wbr",
])

function tagName(token: string): string {
  const match = token.match(/^<\/?\s*([\w:-]+)/)
  return match?.[1]?.toLowerCase() ?? ""
}

function tokenizeHTML(html: string): string[] {
  const tokens: string[] = []
  let index = 0

  while (index < html.length) {
    if (html[index] !== "<") {
      const nextTag = html.indexOf("<", index)
      const end = nextTag < 0 ? html.length : nextTag
      tokens.push(html.slice(index, end))
      index = end
      continue
    }

    if (html.startsWith("<!--", index)) {
      const end = html.indexOf("-->", index + 4)
      const tokenEnd = end < 0 ? html.length : end + 3
      tokens.push(html.slice(index, tokenEnd))
      index = tokenEnd
      continue
    }

    const tagEnd = html.indexOf(">", index + 1)
    if (tagEnd < 0) {
      tokens.push(html.slice(index))
      break
    }

    const tag = html.slice(index, tagEnd + 1)
    tokens.push(tag)
    index = tagEnd + 1

    const name = tagName(tag)
    if (!tag.startsWith("</") && RAW_TEXT_TAGS.has(name)) {
      const closePattern = new RegExp(`<\\/\\s*${name}\\s*>`, "ig")
      closePattern.lastIndex = index
      const close = closePattern.exec(html)
      if (close) {
        if (close.index > index) tokens.push(html.slice(index, close.index))
        tokens.push(close[0])
        index = close.index + close[0].length
      } else if (index < html.length) {
        tokens.push(html.slice(index))
        index = html.length
      }
    }
  }

  return tokens
}

export function formatCSS(css: string): string {
  const protectedValues: string[] = []
  const protectedCSS = css.replace(
    /\/\*[\s\S]*?\*\/|(["'])(?:\\.|(?!\1)[\s\S])*\1/g,
    value => `___CSS_VALUE_${protectedValues.push(value) - 1}___`,
  )
  const compact = protectedCSS
    .replace(/\s+/g, " ")
    .replace(/\s*([{}:;,>+~])\s*/g, "$1")
    .trim()

  const lines: string[] = []
  let current = ""
  let depth = 0
  const pushLine = () => {
    const value = current.trim()
    if (value) lines.push(`${"  ".repeat(depth)}${value}`)
    current = ""
  }

  for (const char of compact) {
    if (char === "{") {
      current += " {"
      pushLine()
      depth += 1
    } else if (char === "}") {
      pushLine()
      depth = Math.max(0, depth - 1)
      current = "}"
      pushLine()
    } else if (char === ";") {
      current += ";"
      pushLine()
    } else if (char === ":") {
      current += ": "
    } else if (char === ",") {
      current += ", "
    } else {
      current += char
    }
  }
  pushLine()

  return lines.join("\n").replace(
    /___CSS_VALUE_(\d+)___/g,
    (_, index) => protectedValues[Number(index)] ?? "",
  )
}

export function formatHTML(html: string): string {
  const lines: string[] = []
  let depth = 0
  let rawTag = ""

  for (const token of tokenizeHTML(html)) {
    if (!token) continue

    if (!token.startsWith("<")) {
      if (rawTag) {
  const rawContent = rawTag === "style"
    ? formatCSS(token)
    : token.replace(/^\n|\n$/g, "")

  const rawLines = rawContent.split("\n")

const indent = "  ".repeat(depth)

for (const line of rawLines) {
  if (!line.trim()) continue

  if (rawTag === "style") {
    lines.push(indent + line) // 不 trim，不破坏 formatCSS 的缩进
  } else {
    lines.push(indent + line.trimEnd())
  }
}
        
}
      else {
        const text = token.replace(/\s+/g, " ").trim()
        if (text) lines.push(`${"  ".repeat(depth)}${text}`)
      }
      continue
    }

    const name = tagName(token)
    const isClosing = /^<\//.test(token)
    const isSpecial = /^<!|^<\?/.test(token)
    const isSelfClosing = /\/\s*>$/.test(token) || VOID_TAGS.has(name)

    if (isClosing) {
      depth = Math.max(0, depth - 1)
      lines.push(`${"  ".repeat(depth)}${token.trim()}`)
      if (name === rawTag) rawTag = ""
    } else {
      lines.push(`${"  ".repeat(depth)}${token.trim()}`)
      if (!isSpecial && !isSelfClosing) {
        depth += 1
        if (RAW_TEXT_TAGS.has(name)) rawTag = name
      }
    }
  }

  return lines.join("\n")
}

export function minifyCSS(css: string): string {
  const strings: string[] = []
  const protectedCSS = css
    .replace(/(["'])(?:\\.|(?!\1)[\s\S])*\1/g, value => {
      const index = strings.push(value) - 1
      return `___CSS_STRING_${index}___`
    })
    .replace(/\/\*[\s\S]*?\*\//g, "")

  return protectedCSS
    .replace(/\s+/g, " ")
    .replace(/\s*([{}:;,>+~])\s*/g, "$1")
    .replace(/;}/g, "}")
    .trim()
    .replace(/___CSS_STRING_(\d+)___/g, (_, index) => strings[Number(index)] ?? "")
}

export function minifyHTML(html: string, minifyEmbeddedCSS = false): string {
  let rawTag = ""
  let result = ""

  for (const token of tokenizeHTML(html)) {
    if (!token) continue

    if (!token.startsWith("<")) {
      result += rawTag === "style" && minifyEmbeddedCSS
        ? minifyCSS(token)
        : rawTag ? token : token.replace(/\s+/g, " ")
      continue
    }

    const name = tagName(token)
    const isClosing = /^<\//.test(token)

    // 保留 IE 条件注释，其余普通 HTML 注释可安全移除。
    if (/^<!--/.test(token) && !/^<!--\[if/i.test(token)) continue

    const compactTag = minifyEmbeddedCSS
      ? token.trim().replace(/(\sstyle\s*=\s*)(["'])([\s\S]*?)\2/gi, (_, prefix, quote, css) =>
        `${prefix}${quote}${minifyCSS(css)}${quote}`)
      : token.trim()
    result += compactTag
    if (isClosing && name === rawTag) rawTag = ""
    else if (!isClosing && RAW_TEXT_TAGS.has(name)) rawTag = name
  }

  return result.trim()
}
