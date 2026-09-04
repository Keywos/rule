// 通用文件行内容组件 — 图标 + 文件名 + 大小/日期/文件夹项数

import { HStack, VStack, Spacer, Text, Image } from 'scripting'
import { fmtSize, fmtDate, FileInfo } from '../manager/utils'
import { FolderCountLabel, FolderCountStore } from './FolderCountLabel'

export interface FileRowContentProps {
  file: FileInfo
  folderCountStore?: FolderCountStore
}

/** 文件行图标 + 名称 + 副标题布局 */
export function FileRowContent({ file, folderCountStore }: FileRowContentProps) {
  return (
    <HStack spacing={12} alignment="center">
      <Image
        systemName={file.icon}
        frame={{ width: 28, height: 28 }}
        foregroundStyle={file.iconColor}
      />
      <VStack alignment="leading" spacing={2}>
        <Text font="body" lineLimit={1} foregroundStyle="label">
          {file.name}
        </Text>
        <HStack spacing={6}>
          {file.isDirectory ? (
            folderCountStore ? <FolderCountLabel path={file.path} store={folderCountStore} /> : (
              <Text font="caption2" monospaced lineLimit={1} foregroundStyle="secondaryLabel">文件夹</Text>
            )
          ) : (
            <>
              <Text font="caption2" monospaced lineLimit={1} foregroundStyle="secondaryLabel">{fmtSize(file.size)}</Text>
              <Text font="caption2" monospaced lineLimit={1} foregroundStyle="tertiaryLabel">{fmtDate(file.modificationDate)}</Text>
            </>
          )}
        </HStack>
      </VStack>
      <Spacer />
    </HStack>
  )
}
