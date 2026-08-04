// 扩展名 → EditorController 支持的 ext 映射

export type EditorExt = 'tsx' | 'ts' | 'js' | 'jsx' | 'txt' | 'md' | 'css' | 'html' | 'json'

const extToEditorExt: Record<string, EditorExt> = {
  '.tsx': 'tsx', '.ts': 'ts', '.js': 'js', '.jsx': 'jsx',
  '.txt': 'txt', '.log': 'txt', '.csv': 'txt',
  '.md': 'md',
  '.css': 'css', '.scss': 'css', '.less': 'css',
  '.html': 'html', '.htm': 'html', '.vue': 'html', '.svelte': 'html', '.svg': 'html', '.xml': 'html',
  '.json': 'json',
}

export function getEditorExt(ext: string): EditorExt {
  return extToEditorExt[ext.toLowerCase()] || 'txt'
}
