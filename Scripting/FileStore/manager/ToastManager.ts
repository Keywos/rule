// 全局 Toast 状态管理
// 任何组件都可以通过 showToast() 触发提示弹窗

// ── 内部状态 ──
type ToastListener = (msg: string) => void;
const listeners: ToastListener[] = [];

// ── 注册监听（由 ToastOverlay 调用） ──
export function setToastListener(fn: ToastListener) {
  // 使用监听栈而不是单一 listener：pagesheet 内的 ToastOverlay 注册后位于最上层，
  // 弹窗关闭时只移除自己的监听，不影响主页 ToastOverlay。
  listeners.push(fn);
  return () => {
    const index = listeners.lastIndexOf(fn);
    if (index >= 0) listeners.splice(index, 1);
  };
}

// ── 全局调用入口 ──
export function showToast(msg: string) {
  const listener = listeners[listeners.length - 1];
  listener?.(msg);
}

// ── 软件更新后书签失效的统一提醒 ──
export const REMOUNT_WARNING_TEXT = "软件更新导致路径变化，无法访问，请重新挂载";

/** 弹 Toast 提醒书签失效需重新挂载；name 可选（收藏名/目录名） */
export function showRemountWarning(name?: string) {
  showToast(name ? `⚠ ${name}：${REMOUNT_WARNING_TEXT}` : `⚠ ${REMOUNT_WARNING_TEXT}`);
}
