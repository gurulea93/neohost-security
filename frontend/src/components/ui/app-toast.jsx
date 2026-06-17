import Icon from "../../Icons";

const TYPE_STYLES = {
  success: { bg: "rgba(16,185,129,0.95)", icon: "check" },
  error: { bg: "rgba(239,68,68,0.95)", icon: "close" },
  warning: { bg: "rgba(245,158,11,0.95)", icon: "info" },
  info: { bg: "rgba(147,51,234,0.95)", icon: "info" },
};

export function AppToast({ toast }) {
  if (!toast) return null;
  const type = toast.type || "success";
  const style = TYPE_STYLES[type] || TYPE_STYLES.success;
  const bg = toast.color || style.bg;

  return (
    <div className="app-toast" style={{ background: bg }} role="status">
      <Icon name={style.icon} size={16} />
      <span>{toast.text}</span>
    </div>
  );
}
