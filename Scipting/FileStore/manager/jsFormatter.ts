/**
 * JS 格式化/压缩工具（基于 terser）
 */

import * as terser from "terser"

export async function formatJS(code: string): Promise<string> {
  const result = await terser.minify(code, {
    mangle: false,
    compress: false,
    output: {
      beautify: true,
      indent_level: 2,
      comments: true,
    },
  })
  return result.code ?? code
}

export async function minifyJSPreserveNames(code: string): Promise<string> {
  const result = await terser.minify(code, {
    mangle: false,
    compress: {
      defaults: true,
      keep_fnames: true,
      keep_classnames: true,
    },
    output: {
      comments: false,
    },
  })
  return result.code ?? code
}

export async function minifyJSPreserveNamesAndComments(code: string): Promise<string> {
  const result = await terser.minify(code, {
    mangle: false,
    compress: {
      defaults: true,
      keep_fnames: true,
      keep_classnames: true,
    },
    output: {
      comments: true,
    },
  })
  return result.code ?? code
}

export async function minifyJSAggressive(code: string): Promise<string> {
  const result = await terser.minify(code, {
    mangle: {
      toplevel: true,
    },
    compress: {
      defaults: true,
      passes: 2,
    },
    output: {
      comments: false,
    },
  })
  return result.code ?? code
}