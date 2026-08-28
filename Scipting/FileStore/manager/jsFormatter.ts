/**
 * JS 格式化/压缩工具（基于 terser）
 *
 * 实测：本环境 Thread.runInBackground 里的 JS 计算不走 JIT，同样的压缩会比主线程直接调用慢 ~6-8 倍
 * （128KB 激进压缩：后台 8.4s vs 主线程 1.3s），因此这里保持直接调用（主线程、最快）。
 * 大文件卡死问题改由 EditorPage 的尺寸守卫 + 编辑器增量写回解决。
 */

/** 惰性加载 terser：依赖未安装时不让整个脚本启动失败 */
function loadTerser() {
  return require("terser")
}

export async function formatJS(code: string): Promise<string> {
  const result = await loadTerser().minify(code, {
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

/**
 * terser 关闭 collapse_vars / reduce_vars / inline
 * 保留 defaults: true （sequences / unused / 等）
 */
const FAST_COMPRESS = {
  defaults: true,
  passes: 1,
  collapse_vars: false,
  reduce_vars: false,
  inline: false,
}

export async function minifyJSPreserveNames(code: string): Promise<string> {
  const result = await loadTerser().minify(code, {
    mangle: false,
    compress: {
      ...FAST_COMPRESS,
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
  const result = await loadTerser().minify(code, {
    mangle: false,
    compress: {
      ...FAST_COMPRESS,
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
  const result = await loadTerser().minify(code, {
    mangle: {
      toplevel: true,
    },
    compress: FAST_COMPRESS,
    output: {
      comments: false,
    },
  })
  return result.code ?? code
}