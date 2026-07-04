// 通用文件列表项组件 — 支持左滑右滑、上下文菜单、选择模式

import {
  Navigation,
  NavigationStack,
  List, Section,
  HStack, VStack, Spacer,
  Text, Button, Image, Group,
  useState, useEffect,
  Path,
  type VirtualNode,
} from 'scripting'
import { fmtSize, fmtDate, FileInfo, getFileInfo } from '../manager/utils'
import { unpackLivePhoto } from '../manager/LivePhotoPacker'
import { setDragSourcePath } from '../manager/dropHandler'

/* ─── 上下文菜单项配置 ─── */
export interface ContextMenuItem {
  title: string
  systemImage?: string
  role?: 'destructive' | 'cancel'
  action: () => void
}

/* ─── 列表项配置 ─── */
export interface FileListItemProps {
  file: FileInfo
  destination?: any
  trailingActions?: ContextMenuItem[]
  leadingActions?: ContextMenuItem[]
  contextMenuItems?: ContextMenuItem[]
  selectMode?: {
    isSelected: boolean
    onToggle: () => void
  }
  showChevron?: boolean
  subtitle?: string
  subtitleForegroundStyle?: string
  trailingContent?: any
  disabled?: boolean
  /** 导航路径 Observable（用于文件夹侧滑进入） */
  navPath?: any
  /** 导航页面 ID（文件夹用） */
  navPageId?: string
  /** 隐藏此行的顶部分割线 */
  hideTopSeparator?: boolean
  /** 深度搜索匹配信息 */
  matchInfo?: {
    line: number
    content: string
  }
  /** 拖拽出（支持把文件拖到其他 App） */
  onDrag?: {
    data: () => ItemProvider
    preview: VirtualNode
  }
}

/** 构建滑动操作配置 */
function buildSwipeConfig(actions?: ContextMenuItem[]) {
  if (!actions || actions.length === 0) return undefined
  return {
    actions: actions.map(a => (
      <Button 
        title={a.title} 
        role={a.role} 
        action={a.action} 
      />
    ))
  }
}

/** 构建上下文菜单 */
function buildContextMenu(items?: ContextMenuItem[]) {
  if (!items || items.length === 0) return undefined
  return {
    menuItems: (
      <Group>
        {items.map((item, idx) => (
          <Button 
            key={idx}
            title={item.title} 
            systemImage={item.systemImage} 
            role={item.role} 
            action={item.action} 
          />
        ))}
      </Group>
    ),
  }
}

export function FileListItem(props: FileListItemProps) {
  const {
    file,
    destination,
    trailingActions,
    leadingActions,
    contextMenuItems,
    selectMode,
    showChevron,
    subtitle,
    subtitleForegroundStyle,
    trailingContent,
    disabled,
    navPath,
    navPageId,
    hideTopSeparator,
    matchInfo,
    onDrag,
  } = props
  
  if (selectMode) {
    return (
      <Button
        action={selectMode.onToggle}
        listRowSeparator={hideTopSeparator ? {visibility:"hidden", edges:"top"} : undefined}
        onDrag={onDrag}
      >
        <HStack spacing={12} alignment="center" padding={{ vertical: 4 }}>
          <Image 
            systemName={selectMode.isSelected ? "checkmark.circle.fill" : "circle"} 
            frame={{ width: 28, height: 28 }} 
            foregroundStyle={selectMode.isSelected ? "systemBlue" : "tertiaryLabel"} 
          />
          <Image systemName={file.icon} frame={{ width: 28, height: 28 }} foregroundStyle={file.iconColor} />
          <VStack alignment="leading" spacing={2}>
            <Text font="body" lineLimit={1}>{file.name}</Text>
            <HStack spacing={6}>
              {file.isDirectory ? (
                <Text font="caption2" lineLimit={1} foregroundStyle={subtitleForegroundStyle as any || 'secondaryLabel'}>{subtitle || '文件夹'}</Text>
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
      </Button>
    )
  }

  const trailingSwipeConfig = buildSwipeConfig(trailingActions)
  const leadingSwipeConfig = buildSwipeConfig(leadingActions)
  const contextMenuConfig = buildContextMenu(contextMenuItems)

  if (destination && file.isDirectory && navPath && navPageId) {
    // 文件夹 + 有 navPath → Button 触发 navPath push
    return (
      <Button
        action={() => navPath.setValue([...navPath.value, navPageId])}
        listRowSeparator={hideTopSeparator ? {visibility:"hidden", edges:"top"} : undefined}
        trailingSwipeActions={trailingSwipeConfig}
        leadingSwipeActions={leadingSwipeConfig}
        contextMenu={contextMenuConfig}
        onDrag={onDrag}
      >
        <HStack spacing={12} alignment="center"
          //background="#ccc"
          >
          <Image systemName={file.icon} frame={{ width: 28, height: 28 }} foregroundStyle={file.iconColor} />
          <VStack alignment="leading" spacing={2}>
            <Text font="body" lineLimit={1}>{file.name}</Text>
            <HStack spacing={6}>
              {file.isDirectory ? (
                <Text font="caption2" lineLimit={1} foregroundStyle={subtitleForegroundStyle as any || 'secondaryLabel'}>{subtitle || '文件夹'}</Text>
              ) : (
                <>
                  <Text font="caption2" lineLimit={1} foregroundStyle="secondaryLabel">{fmtSize(file.size)}</Text>
                  <Text font="caption2" lineLimit={1} foregroundStyle="tertiaryLabel">{fmtDate(file.modificationDate)}</Text>
                </>
              )}
            </HStack>
          </VStack>
          <Spacer />
          {trailingContent ?? null}
          {showChevron && (
            <Image systemName="chevron.right" frame={{ width: 12, height: 12 }} foregroundStyle="tertiaryLabel" />
          )}
        </HStack>
      </Button>
    )
  }

  if (destination) {
    // 非目录或没有 navPath → Navigation.present() 上滑/全屏
    return (
      <Button
        action={() => Navigation.present({ element: destination, modalPresentationStyle: 'fullScreen' })}
        listRowSeparator={hideTopSeparator ? {visibility:"hidden", edges:"top"} : undefined}
        trailingSwipeActions={trailingSwipeConfig}
        leadingSwipeActions={leadingSwipeConfig}
        contextMenu={contextMenuConfig}
        onDrag={onDrag}
      >
        <HStack spacing={12} alignment="center"
          //background="#ccc"
          >
          <Image systemName={file.icon} frame={{ width: 28, height: 28 }} foregroundStyle={file.iconColor} />
          <VStack alignment="leading" spacing={2}>
            <Text font="body" lineLimit={1}>{file.name}</Text>
            <HStack spacing={6}>
              {file.isDirectory ? (
                <Text font="caption2" lineLimit={1} foregroundStyle={subtitleForegroundStyle as any || 'secondaryLabel'}>{subtitle || '文件夹'}</Text>
              ) : (
                <>
                  <Text font="caption2" lineLimit={1} foregroundStyle="secondaryLabel">{fmtSize(file.size)}</Text>
                  <Text font="caption2" lineLimit={1} foregroundStyle="tertiaryLabel">{fmtDate(file.modificationDate)}</Text>
                </>
              )}
            </HStack>
          </VStack>
          <Spacer />
          {trailingContent ?? null}
          {showChevron && (
            <Image systemName="chevron.right" frame={{ width: 12, height: 12 }} foregroundStyle="tertiaryLabel" />
          )}
        </HStack>
      </Button>
    )
  }

  return (
    <Button
      action={() => {}}
      disabled={disabled}
      listRowSeparator={hideTopSeparator ? {visibility:"hidden", edges:"top"} : undefined}
      trailingSwipeActions={trailingSwipeConfig}
      leadingSwipeActions={leadingSwipeConfig}
      contextMenu={contextMenuConfig}
      onDrag={onDrag}
    >
      <HStack spacing={12} alignment="center">
        <Image systemName={file.icon} frame={{ width: 28, height: 28 }} foregroundStyle={file.iconColor} />
        <VStack alignment="leading" spacing={2}>
          <Text font="body" lineLimit={1}>{file.name}</Text>
          <HStack spacing={6}>
            {file.isDirectory ? (
              <Text font="caption2" foregroundStyle="secondaryLabel">{subtitle || '文件夹'}</Text>
            ) : (
              <>
                <Text font="caption2" lineLimit={1} foregroundStyle="secondaryLabel">{fmtSize(file.size)}</Text>
                <Text font="caption2" lineLimit={1} foregroundStyle="tertiaryLabel">{fmtDate(file.modificationDate)}</Text>
              </>
            )}
          </HStack>
        </VStack>
        <Spacer />
        {matchInfo && (
          <Text font="caption2" foregroundStyle="systemYellow" lineLimit={2}>
            第{matchInfo.line}行: {matchInfo.content}
          </Text>
        )}
      </HStack>
    </Button>
  )
}

/* ─── EXIF key 中文映射 ─── */
const EXIF_KEY_MAP: Record<string, string> = {
  pixelWidth: '宽度（像素）', pixelHeight: '高度（像素）',
  dpiWidth: 'DPI 宽度', dpiHeight: 'DPI 高度',
  depth: '色深', colorModel: '色彩模式', orientation: '方向',
  hasAlpha: 'Alpha通道', profileName: '颜色配置',
  'tiff.Make': '设备制造商', 'tiff.Model': '设备型号', 'tiff.Software': '软件',
  'tiff.DateTime': 'TIFF日期', 'tiff.Artist': '作者', 'tiff.Copyright': '版权',
  'tiff.ImageWidth': '图像宽度', 'tiff.ImageLength': '图像高度',
  'tiff.Compression': '压缩方式',
  'tiff.Orientation': '拍摄方向',
  'tiff.PhotometricInterpretation': '颜色解释方式',
  'tiff.HostComputer': '创建设备',
  'tiff.XResolution': '水平分辨率',
  'tiff.YResolution': '垂直分辨率',
  'tiff.TileWidth': 'Tile 宽度（像素）',
  'tiff.TileLength': 'Tile 高度（像素）',
  'tiff.ResolutionUnit': '分辨率单位',
  'exif.DateTimeOriginal': '拍摄时间', 'exif.DateTimeDigitized': '数字化时间',
  'exif.ExposureTime': '快门速度', 'exif.FNumber': '光圈',
  'exif.ISOSpeedRatings': 'ISO', 'exif.FocalLength': '焦距',
  'exif.FocalLenIn35mmFilm': '等效焦距（35mm）', 'exif.LensModel': '镜头型号',
  'exif.LensMake': '镜头制造商', 'exif.LensSpecification': '镜头规格',
  'exif.WhiteBalance': '白平衡', 'exif.Flash': '闪光灯',
  'exif.ExposureBiasValue': '曝光补偿', 'exif.MeteringMode': '测光模式',
  'exif.ExposureProgram': '曝光程序', 'exif.SceneCaptureType': '场景类型',
  'exif.ExposureMode': '曝光模式', 'exif.ColorSpace': '色彩空间',
  'exif.PixelXDimension': '像素宽度', 'exif.PixelYDimension': '像素高度',
  'exif.ShutterSpeedValue': '快门速度值', 'exif.ApertureValue': '光圈值',
  'exif.BrightnessValue': '亮度值', 'exif.Contrast': '对比度',
  'exif.Saturation': '饱和度', 'exif.Sharpness': '锐度',
  'exif.ImageDescription': '图像描述', 'exif.UserComment': '用户备注',
  'exif.DigitalZoomRatio': '数字变焦比', 'exif.FlashEnergy': '闪光灯能量',
  'exif.SubjectDistance': '主体距离', 'exif.MaxApertureValue': '最大光圈',
  'exif.FileSource': '文件来源', 'exif.SceneType': '场景类型',
  'exif.SensingMethod': '传感方式', 'exif.CFAPattern': 'CFA 图案',
  'exif.SensitivityType': '感光度类型',
  'exif.CustomRendered': '处理方式',
  'exif.StandardOutputSensitivity': '标准输出感光度（SOS）',
  'exif.SubjectDistRange': '主体距离范围',
  'exif.SubjectArea': '主体区域',
  'exif.OffsetTime': '拍摄时区',
  'exif.OffsetTimeDigitized': '数字化时区',
  'exif.SubsecTimeDigitized': '小数秒',
  'gps.Latitude': '纬度', 'gps.Longitude': '经度', 'gps.Altitude': '海拔',
  'gps.Speed': '速度', 'gps.ImgDirection': '图像方向',
  'gps.HPositioningError': '水平定位误差', 'gps.TimeStamp': 'GPS时间戳',
  'gps.DateStamp': 'GPS日期', 'gps.GPSMapDatum': '地图基准',
  'iptc.ObjectName': '标题', 'iptc.Caption': '说明', 'iptc.Keywords': '关键词',
  'iptc.Byline': '作者', 'iptc.City': '城市', 'iptc.CountryPrimaryLocationName': '国家',
  'iptc.CopyrightNotice': '版权信息',
}

function formatExifValue(key: string, value: any): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'boolean') return value ? '是' : '否'
  if (Array.isArray(value)) return value.join(', ')
  if (key === 'exif.Flash') return (value % 2 === 1) ? '已触发' : '未触发'
  if (key === 'exif.WhiteBalance') return value === 0 ? '自动' : '手动'
  if (key === 'exif.ExposureTime') return value + 's'
  if (key === 'exif.FNumber' || key === 'exif.ApertureValue') return 'f/' + value
  if (key.includes('FocalLength') && !key.includes('Resolution')) return value + 'mm'
  if (key === 'depth') return value + ' 位'
  if (key === 'hasAlpha') return value ? '有' : '无'
  if (key === 'exif.MeteringMode') return ({ 0:'未知',1:'平均',2:'中央重点',3:'点测光',4:'多点',5:'矩阵',6:'局部' } as Record<number,string>)[value] || '未知'
  if (key === 'exif.ExposureProgram') return ({ 0:'未定义',1:'手动',2:'程序自动',3:'光圈优先',4:'快门优先',5:'创意',6:'运动',7:'人像',8:'风景' } as Record<number,string>)[value] || '未知'
  if (key === 'exif.ExposureMode') return ({ 0:'自动',1:'手动',2:'包围曝光' } as Record<number,string>)[value] || '未知'
  if (key === 'tiff.Compression') return ({ 1:'无压缩',5:'LZW',6:'JPEG',32773:'PackBits' } as Record<number,string>)[value] || `未知(${value})`
  if (key === 'tiff.Orientation' || key === 'orientation') return ({ 1:'正常',3:'旋转180°',6:'顺时针90°',8:'逆时针90°' } as Record<number,string>)[value] || `未知(${value})`
  if (key === 'tiff.PhotometricInterpretation') return ({ 0:'WhiteIsZero',1:'黑白',2:'RGB',5:'CMYK',6:'YCbCr',8:'CIELab' } as Record<number,string>)[value] || `未知(${value})`
  if (key === 'exif.SensitivityType') return ({ 0:'未知',1:'SOS',2:'REI',3:'ISO Speed',4:'SOS+REI',5:'SOS+ISO',6:'REI+ISO',7:'SOS+REI+ISO' } as Record<number,string>)[value] || `未知(${value})`
  if (key === 'exif.CustomRendered') return value === 0 ? '正常处理' : value === 1 ? '自定义处理(HDR/美颜/夜景)' : `未知(${value})`
  if (key === 'exif.SubjectDistRange') return ({ 0:'未知',1:'微距(几厘米~几十厘米)',2:'近景(0.5~3米)',3:'远景(几米~无限远)' } as Record<number,string>)[value] || `未知(${value})`
  if (key === 'exif.SensingMethod') return ({ 1:'未定义',2:'单芯片彩色面阵传感器',3:'双芯片彩色面阵传感器',4:'三芯片彩色面阵传感器',5:'顺序彩色面阵传感器',7:'三线扫描传感器',8:'顺序彩色线扫描传感器' } as Record<number,string>)[value] || `未知(${value})`
  if (key === 'tiff.ResolutionUnit') return ({ 1:'无单位',2:'英寸(DPI)',3:'厘米(DPCM)' } as Record<number,string>)[value] || `未知(${value})`
  if (key === 'exif.SubjectArea') {
    if (Array.isArray(value) && value.length === 2) return `x=${value[0]}, y=${value[1]}`
    if (Array.isArray(value) && value.length === 3) return `x=${value[0]}, y=${value[1]}, 直径=${value[2]}`
    if (Array.isArray(value) && value.length === 4) return `x=${value[0]}, y=${value[1]}, 宽=${value[2]}, 高=${value[3]}`
    return String(value)
  }
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(4)
  return String(value)
}

function flattenMeta(meta: any, prefix = ''): Array<{ key: string; label: string; value: string }> {
  const result: Array<{ key: string; label: string; value: string }> = []
  if (!meta) return result
  for (const k of Object.keys(meta)) {
    const fullKey = prefix ? `${prefix}.${k}` : k
    const val = meta[k]
    if (val === null || val === undefined) continue
    if (typeof val === 'object' && !Array.isArray(val)) { result.push(...flattenMeta(val, fullKey)); continue }
    const label = EXIF_KEY_MAP[fullKey] || fullKey
    const formatted = formatExifValue(fullKey, val)
    if (formatted) result.push({ key: fullKey, label, value: formatted })
  }
  return result
}

/* ─── 文件简介弹窗组件 ─── */
export function FileInfoDialog({ file, nested }: { file: FileInfo; nested?: boolean }) {
  const modalDismiss = Navigation.useDismiss()
  const dismiss = nested ? (() => {}) : modalDismiss
  const [showToast, setShowToast] = useState(false)
  const [toastMsg, setToastMsg] = useState('')
  const [imageMeta, setImageMeta] = useState<any>(null)
  
  useEffect(() => {
    const ext = file.extension.toLowerCase()
    const isImage = file.category === 'image' || file.category === 'video'
    const isLive = ext === '.live'
    
    const readMeta = async () => {
      try {
        if (isLive) {
          // Live photo: 解包后分别读取图片和视频的元数据
          const data = await FileManager.readAsData(file.path)
          if (data) {
            const unpacked = unpackLivePhoto(data)
            if (unpacked) {
              const tmpDir = FileManager.temporaryDirectory
              // 读取图片元数据
              const imgTmp = tmpDir + `/_live_info_img.${unpacked.imageExt}`
              await FileManager.writeAsData(imgTmp, unpacked.imageData)
              const imgMeta = await ImageIO.readMetadata(imgTmp).catch(() => null)
              try { await FileManager.remove(imgTmp) } catch {}
              // 读取视频元数据
              const vidTmp = tmpDir + '/_live_info_vid.mov'
              await FileManager.writeAsData(vidTmp, unpacked.videoData)
              const vidMeta = await ImageIO.readMetadata(vidTmp).catch(() => null)
              try { await FileManager.remove(vidTmp) } catch {}
              setImageMeta({ _livePhoto: true, image: imgMeta, video: vidMeta })
            }
          }
        } else if (isImage) {
          const meta = await ImageIO.readMetadata(file.path)
          setImageMeta(meta)
        } else {
          // 非图片文件也尝试读取（可能读不到但不报错）
          const meta = await ImageIO.readMetadata(file.path).catch(() => null)
          if (meta) setImageMeta(meta)
        }
      } catch {}
    }
    readMeta()
  }, [])
  
  const handleCopyPath = async () => {
    await Pasteboard.setString(file.path)
    setToastMsg('路径已复制')
    setShowToast(true)
    setTimeout(() => setShowToast(false), 1000)
  }
  
  // 提取 EXIF 元数据（支持 live photo 多段）
  const exifItems = imageMeta ? (
    imageMeta._livePhoto ? [] : flattenMeta(imageMeta)
  ) : []
  const liveImageItems = imageMeta?._livePhoto && imageMeta.image ? flattenMeta(imageMeta.image) : []
  const liveVideoItems = imageMeta?._livePhoto && imageMeta.video ? flattenMeta(imageMeta.video) : []
  
  const Wrapper = nested ? (props: any) => <>{props.children}</> : NavigationStack
  return (
    <Wrapper>
    <List
      navigationTitle="简介"
      navigationBarTitleDisplayMode="inline"
      toolbar={{
        topBarLeading: nested ? undefined : [
          <Button title="关闭" systemImage="xmark" action={dismiss} />,
        ],
      }}
      toast={{ isPresented: showToast, onChanged: setShowToast, message: toastMsg, duration: 1, position: "top" }}
    >
      {/* 基本信息 */}
      <Section title="基本信息">
        <HStack spacing={12} alignment="center">
          <Image systemName={file.icon} frame={{ width: 38, height: 38 }} foregroundStyle={file.iconColor} />
          <VStack alignment="leading" spacing={4}>
            <Text font="headline">{file.name}</Text>
          {/*   <Text font="caption" foregroundStyle="secondaryLabel">
              {file.isDirectory ? '文件夹' : file.extension || '未知类型'}
            </Text> */}
          </VStack>
        </HStack>
      </Section>

      {/* 路径 */}
      <Section title="点击路径复制">
        <VStack alignment="leading" spacing={8}>
             <Button action={handleCopyPath}>
          <Text font="footnote" foregroundStyle="secondaryLabel">{file.path}</Text>
       
            {/* <HStack spacing={6}> */}
              {/* <Image systemName="doc.on.doc" frame={{ width: 14, height: 14 }} foregroundStyle="systemBlue" /> */}
              {/* <Text font="body" foregroundStyle="systemBlue">复制路径</Text> */}
            {/* </HStack> */}
          </Button>
        </VStack>
      </Section>

      {/* 文件详情 */}
      <Section title="文件详情">
        <HStack spacing={12}>
          <Text font="body" foregroundStyle="secondaryLabel">类型</Text>
          <Spacer />
          <Text font="body">{file.isDirectory ? '文件夹' : file.extension || '无扩展名'}</Text>
        </HStack>
        {!file.isDirectory && (
          <HStack spacing={12}>
            <Text font="body" foregroundStyle="secondaryLabel">MIME类型</Text>
            <Spacer />
            <Text font="body">{file.mimeType || '未知'}</Text>
          </HStack>
        )}
        <HStack spacing={12}>
          <Text font="body" foregroundStyle="secondaryLabel">大小</Text>
          <Spacer />
          <Text font="body">{fmtSize(file.size)}（{file.size.toLocaleString()} 字节）</Text>
        </HStack>
        <HStack spacing={12}>
          <Text font="body" foregroundStyle="secondaryLabel">文件分类</Text>
          <Spacer />
          <Text font="body">{file.category}</Text>
        </HStack>
      </Section>

      {/* 日期信息 */}
      <Section title="日期信息">
        <HStack spacing={12}>
          <Text font="body" foregroundStyle="secondaryLabel">创建日期</Text>
          <Spacer />
          <Text font="body">{fmtDate(file.creationDate)}</Text>
        </HStack>
        <HStack spacing={12}>
          <Text font="body" foregroundStyle="secondaryLabel">修改日期</Text>
          <Spacer />
          <Text font="body">{fmtDate(file.modificationDate)}</Text>
        </HStack>
      </Section>

      {/* 文件属性 */}
      <Section title="文件属性">
        <HStack spacing={12}>
          <Text font="body" foregroundStyle="secondaryLabel">是否为目录</Text>
          <Spacer />
          <Text font="body">{file.isDirectory ? '是' : '否'}</Text>
        </HStack>
        <HStack spacing={12}>
          <Text font="body" foregroundStyle="secondaryLabel">是否为链接</Text>
          <Spacer />
          <Text font="body">{file.isLink ? '是' : '否'}</Text>
        </HStack>
      </Section>

      {/* Live Photo 图片 EXIF */}
      {liveImageItems.length > 0 && (
        <Section title="实况照片 - 图片信息">
          {liveImageItems.map((item) => (
            <HStack key={item.key} spacing={12}>
              <Text font="footnote" foregroundStyle="secondaryLabel">{item.label}</Text>
              <Spacer />
              <Text font="footnote">{item.value}</Text>
            </HStack>
          ))}
        </Section>
      )}

      {/* Live Photo 视频 EXIF */}
      {liveVideoItems.length > 0 && (
        <Section title="实况照片 - 视频信息">
          {liveVideoItems.map((item) => (
            <HStack key={item.key} spacing={12}>
              <Text font="footnote" foregroundStyle="secondaryLabel">{item.label}</Text>
              <Spacer />
              <Text font="footnote">{item.value}</Text>
            </HStack>
          ))}
        </Section>
      )}

      {/* 普通图片 EXIF */}
      {exifItems.length > 0 && (
        <Section title="图片 EXIF 信息">
          {exifItems.map((item) => (
            <HStack key={item.key} spacing={12}>
              <Text font="footnote" foregroundStyle="secondaryLabel">{item.label}</Text>
              <Spacer />
              <Text font="footnote">{item.value}</Text>
            </HStack>
          ))}
        </Section>
      )}
    </List>
    </Wrapper>
  )
}

/**
 * 供 NavigationStack push 使用的简介页面
 * 根据文件路径异步加载 FileInfo 后显示 FileInfoDialog
 */
export function FileInfoPage({ filePath: fp }: { filePath: string }) {
  const [file, setFile] = useState<FileInfo | null>(null)
  useEffect(() => {
    (async () => {
      try {
        const info = await getFileInfo(fp)
        setFile(info)
      } catch (e) {
        console.log('读取文件信息失败:', e)
      }
    })()
  }, [fp])
  if (!file) return <VStack />
  return <FileInfoDialog file={file} nested />
}

/**
 * 根据文件路径创建拖拽配置（ItemProvider + 预览视图）
 * 供 FileListItem 和 GeneralBrowser 的行组件使用
 */
export function makeDragConfig(filePath: string): {
  data: () => ItemProvider
  preview: VirtualNode
} {
  return {
    data: () => {
      setDragSourcePath(filePath)
      try {
        return ItemProvider.fromFilePath(filePath)
      } catch (e) {
        console.log('创建拖拽ItemProvider失败:', e)
        return ItemProvider.fromText('')
      }
    },
    preview: (
      <HStack spacing={8} padding={12} background="systemGray">
        <Image systemName="doc.fill" foregroundStyle="white" frame={{ width: 20, height: 20 }} />
        <Text font="headline" foregroundStyle="white">
          {Path.basename(filePath)}
        </Text>
      </HStack>
    ),
  }
}
