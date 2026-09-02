// File: i18n/index.ts
import { i18nEN } from "./en"
import { i18nZH } from "./zh"

/**
 * 自动根据系统语言选择中/英文文案
 */
export const i18n = (() => {
  try {
    const locale = Device.systemLocale?.toLowerCase?.() ?? "en"
    if (locale.startsWith("zh")) {
      return i18nZH
    }
    return i18nEN
  } catch {
    // 安全降级
    return i18nEN
  }
})()