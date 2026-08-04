// 通用文件行内容组件 — 图标 + 文件名 + 大小/日期/文件夹项数

import { HStack, VStack, Spacer, Text, Image } from 'scripting'
import { fmtSize, fmtDate, FileInfo } from '../manager/utils'

export interface FileRowContentProps {
  file: FileInfo
  folderCounts?: Map<string, number>
}

/** 文件行图标 + 名称 + 副标题布局 */
export function FileRowContent({ file, folderCounts }: FileRowContentProps) {
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
            <Text font="caption2" lineLimit={1} foregroundStyle="secondaryLabel" >
              {folderCounts?.get(file.path) !== undefined
                ? `${folderCounts.get(file.path)} 项`
                : '文件夹'}
            </Text>
          ) : (
            <>
              <Text font="caption2" lineLimit={1} foregroundStyle="secondaryLabel">{fmtSize(file.size)}</Text>
              <Text font="caption2" lineLimit={1} foregroundStyle="tertiaryLabel">{fmtDate(file.modificationDate)}</Text>
            </>
          )}
        </HStack>
      </VStack>
      <Spacer />
    </HStack>
  )
}
