// 全局 Toast 状态管理
// 任何组件都可以通过 showToast() 触发提示弹窗

// ── 内部状态 ──
type ToastListener = (msg: string) => void
let listener: ToastListener | null = null

// ── 注册监听（由 ToastOverlay 调用） ──
export function setToastListener(fn: ToastListener) {
  listener = fn
  return () => { listener = null }
}

// ── 全局调用入口 ──
export function showToast(msg: string) {
  listener?.(msg)
}