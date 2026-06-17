import Icon from "../../Icons";
import { useI18n } from "../../i18n";

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  cancelLabel,
  danger = false,
  onConfirm,
  onCancel,
}) {
  const { t } = useI18n();
  if (!open) return null;

  const titleText = title ?? t("common.confirmTitle");
  const confirmText = confirmLabel ?? t("common.confirm");
  const cancelText = cancelLabel ?? t("common.cancel");

  return (
    <div className="modal-overlay" onClick={onCancel} role="dialog" aria-modal="true">
      <div className="modal confirm-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <h3 className="text-lg font-semibold text-foreground">{titleText}</h3>
          <button type="button" className="icon-btn shrink-0" onClick={onCancel} aria-label={t("common.close")}>
            <Icon name="close" size={16} />
          </button>
        </div>
        <p className="text-sm text-muted-foreground mb-6 leading-relaxed">{message}</p>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-sm" onClick={onCancel}>
            {cancelText}
          </button>
          <button
            type="button"
            className={`btn btn-sm ${danger ? "btn-danger" : "btn-primary-sm"}`}
            onClick={onConfirm}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
