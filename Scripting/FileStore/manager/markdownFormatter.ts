/** 轻量 Markdown 格式化，代码围栏中的内容保持原样。 */
export function formatMarkdown(markdown: string): string {
  const lines = markdown.replace(/\r\n?/g, "\n").split("\n")
  const result: string[] = []
  let fence = ""
  let blankCount = 0

  for (const sourceLine of lines) {
    const fenceMatch = sourceLine.match(/^\s*(`{3,}|~{3,})/)
    if (fenceMatch) {
      const marker = fenceMatch[1][0]
      if (!fence) fence = marker
      else if (fence === marker) fence = ""
      result.push(sourceLine.trimEnd())
      blankCount = 0
      continue
    }

    if (fence) {
      result.push(sourceLine)
      continue
    }

    let line = sourceLine.trimEnd()
      .replace(/^(\s{0,3})(#{1,6})\s*/, "$1$2 ")
      .replace(/^(\s*)[*+]\s+/, "$1- ")
      .replace(/^(\s*)-(?!\s|$)/, "$1- ")
      .replace(/^(\s*\d+\.)\s*/, "$1 ")
      .replace(/^(\s*>+)\s*/, "$1 ")
    // 仅对 ATX 标题行去除结尾的 # 闭合串（如 "# 标题 #" -> "# 标题"）。
    // 之前对所有行执行会误删普通段落结尾的 #（如 "请看 issue #"）。
    if (/^\s{0,3}#{1,6}(\s|$)/.test(line)) {
      line = line.replace(/\s+#+\s*$/, "")
    }

    if (!line.trim()) {
      blankCount += 1
      if (blankCount <= 1 && result.length) result.push("")
    } else {
      blankCount = 0
      result.push(line)
    }
  }

  while (result[0] === "") result.shift()
  while (result[result.length - 1] === "") result.pop()
  return `${result.join("\n")}\n`
}
