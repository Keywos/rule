// 使用枚举表示压力等级，便于多语言与样式映射
export enum StressLevel {
  Excellent = "excellent",
  Good = "good",
  Warning = "warning",
  Overload = "overload",
}

/** 阈值常量（单位：ms），便于后续按用户偏好或人群定制 */
export const STRESS_THRESHOLDS = {
  excellent: 56, // Excellent
  good: 34,      //  Good
  warning: 28,   //  Warning
  // <30 → Overload
} as const;

/**
 * 根据 HRV（ms）计算压力等级
 * @param hrvMs HRV（毫秒），为空或 NaN 时返回 null
 * @returns StressLevel | null
 */
export function analyzeStress(hrvMs: number | null): StressLevel | null {
  if (hrvMs == null || isNaN(hrvMs)) return null;

  if (hrvMs >= STRESS_THRESHOLDS.excellent) return StressLevel.Excellent;
  if (hrvMs >= STRESS_THRESHOLDS.good) return StressLevel.Good;
  if (hrvMs >= STRESS_THRESHOLDS.warning) return StressLevel.Warning;
  return StressLevel.Overload;
}
