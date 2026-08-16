// 全局 Toast 状态管理
// 任何组件都可以通过 showToast() 触发提示弹窗

// ── 内部状态 ──
type ToastListener = (msg: string) => void;
let listener: ToastListener | null = null;

// ── 注册监听（由 ToastOverlay 调用） ──
export function setToastListener(fn: ToastListener) {
  listener = fn;
  return () => {
    listener = null;
  };
}

// ── 全局调用入口 ──
export function showToast(msg: string) {
  listener?.(msg);
}

// ── 软件更新后书签失效的统一提醒 ──
export const REMOUNT_WARNING_TEXT = "软件更新导致路径变化，无法访问，请重新挂载";

/** 弹 Toast 提醒书签失效需重新挂载；name 可选（收藏名/目录名） */
export function showRemountWarning(name?: string) {
  showToast(name ? `⚠ ${name}：${REMOUNT_WARNING_TEXT}` : `⚠ ${REMOUNT_WARNING_TEXT}`);
}
