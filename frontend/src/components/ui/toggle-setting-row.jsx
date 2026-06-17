import { Switch } from "./material-design-3-switch";

export function ToggleSettingRow({
  label,
  description,
  checked,
  disabled,
  pending,
  onCheckedChange,
  variant = "primary",
  size = "sm",
}) {
  return (
    <div className={`flex items-center justify-between gap-4 rounded-xl border border-border/40 bg-card/60 px-4 py-3 ${pending ? "opacity-60" : ""}`}>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-foreground">{label}</div>
        {description && (
          <div className="text-xs text-muted-foreground mt-0.5 truncate">{description}</div>
        )}
      </div>
      <Switch
        size={size}
        variant={variant}
        showIcons
        haptic="light"
        checked={!!checked}
        disabled={disabled || pending}
        onCheckedChange={onCheckedChange}
      />
    </div>
  );
}
