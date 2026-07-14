/**
 * 基于 Prettier 的统一格式化工具。
 * 支持 HTML / CSS / SCSS / Less / JS / TS / JSX / TSX / JSON / YAML / Markdown / GraphQL 等。
 * 遇到不规范 HTML（如标签未正确闭合）时自动降级到旧的自定义格式化。
 */

import * as prettier from "prettier"
import { formatHTML } from "./htmlFormatter"

/** 使用 HTML 解析器的扩展名集合（格式失败时可降级到 formatHTML） */
const HTML_PARSER_EXTS = new Set([".html", ".htm", ".xhtml", ".vue", ".svelte", ".svg", ".xml"])

/** 没有常规后缀、但内容可由 Prettier 识别的常见配置文件名 */
const fileNameToParser: Record<string, string> = {
  ".babelrc": "json",
  ".eslintrc": "json",
  ".prettierrc": "json",
  ".stylelintrc": "json",
  ".swcrc": "json",
}

/** 文件扩展名 → Prettier parser 映射 */
const extToParser: Record<string, string> = {
  ".js": "babel",
  ".jsx": "babel",
  ".mjs": "babel",
  ".cjs": "babel",
  ".es6": "babel",
  // TS / TSX
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  // CSS 家族
  ".css": "css",
  ".scss": "scss",
  ".less": "less",
  ".pcss": "css",
  ".postcss": "css",
  // HTML 家族
  ".html": "html",
  ".htm": "html",
  ".xhtml": "html",
  ".vue": "vue",
  // Prettier 核心不内置 Svelte 插件；按 HTML 语法格式化并保留失败降级。
  ".svelte": "html",
  // JSON 家族
  ".json": "json",
  ".jsonc": "json",
  ".json5": "json5",
  ".babelrc": "json",
  // Markdown
  ".md": "markdown",
  ".markdown": "markdown",
  ".mdown": "markdown",
  ".mkd": "markdown",
  ".mdx": "mdx",
  // YAML
  ".yaml": "yaml",
  ".yml": "yaml",
  // GraphQL
  ".graphql": "graphql",
  ".gql": "graphql",
  ".graphqls": "graphql",
  // SVG（使用 HTML 解析器）
  ".svg": "html",
  ".xml": "html",
}

export function getPrettierParser(fileNameOrExt: string): string | null {
  const value = fileNameOrExt.toLowerCase()
  const baseName = value.split(/[\\/]/).pop() ?? value
  const namedParser = fileNameToParser[baseName]
  if (namedParser) return namedParser

  // 既接受 ".tsx"，也接受 "page.tsx" 或完整路径。
  const matchedExt = Object.keys(extToParser)
    .sort((a, b) => b.length - a.length)
    .find((candidate) => baseName.endsWith(candidate))
  return matchedExt ? extToParser[matchedExt] : null
}

export function isPrettierSupported(fileNameOrExt: string): boolean {
  return getPrettierParser(fileNameOrExt) != null
}

/**
 * 使用 Prettier 格式化代码。
 * @param code  源代码
 * @param ext   文件扩展名、文件名或完整路径（如 ".js"、"page.tsx"）
 * @returns     格式化后的代码；若语言不支持则原样返回
 */
export async function formatWithPrettier(code: string, ext: string): Promise<string> {
  const parser = getPrettierParser(ext)
  if (!parser) return code

  try {
    const result = await prettier.format(code, {
      parser,
      tabWidth: 2,
      semi: true,
      singleQuote: false,
      trailingComma: "all",
      printWidth: 100,
      htmlWhitespaceSensitivity: "ignore",
      proseWrap: "preserve",
    })
    return result
  } catch (e) {
    console.log(`Prettier 格式化失败 (${ext}): ${e}`)
    // HTML 家族格式失败时降级到旧的自定义 formatHTML
    const lowerValue = ext.toLowerCase()
    if ([...HTML_PARSER_EXTS].some((htmlExt) => lowerValue.endsWith(htmlExt))) {
      try {
        return formatHTML(code)
      } catch (e2) {
        console.log(`降级 formatHTML 也失败:`, e2)
      }
    }
    return code
  }
}