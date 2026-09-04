import { useEffect, useObservable, Text } from 'scripting'

export interface FolderCountStore {
  get(path: string): number | undefined
  subscribe(path: string, listener: (count: number) => void): () => void
}

export function FolderCountLabel({ path, store }: { path: string; store: FolderCountStore }) {
  const count = useObservable<number | null>(null)

  useEffect(() => {
    const current = store.get(path)
    count.setValue(current ?? null)
    return store.subscribe(path, (next) => count.setValue(next))
  }, [path, store])

  return (
    <Text font="caption2" monospaced lineLimit={1} foregroundStyle="secondaryLabel">
      {count.value !== null ? `${count.value} 项` : '文件夹'}
    </Text>
  )
}
