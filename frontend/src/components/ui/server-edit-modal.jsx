import { useState } from "react";

export function ServerEditModal({ server, onClose, onSave, t }) {
  const [form, setForm] = useState(() => ({
    name: server?.name || "",
    hostname: server?.hostname || "",
    description: server?.description || "",
    latitude: server?.latitude ?? "",
    longitude: server?.longitude ?? "",
    location_label: server?.location_label || "",
  }));

  if (!server) return null;

  const set = (k, v) => setForm((p) => ({ ...p, [k]: v }));

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <h3 className="card-title mb-4">{t("servers.edit")}</h3>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground">{t("servers.name")}</label>
            <input className="form-input w-full" value={form.name} onChange={(e) => set("name", e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">{t("servers.hostname")}</label>
            <input className="form-input w-full" value={form.hostname} onChange={(e) => set("hostname", e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted-foreground">{t("servers.latitude")}</label>
              <input className="form-input w-full" type="number" step="any" placeholder="44.4268" value={form.latitude} onChange={(e) => set("latitude", e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-muted-foreground">{t("servers.longitude")}</label>
              <input className="form-input w-full" type="number" step="any" placeholder="26.1025" value={form.longitude} onChange={(e) => set("longitude", e.target.value)} />
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">{t("servers.location")}</label>
            <input className="form-input w-full" placeholder="București, RO" value={form.location_label} onChange={(e) => set("location_label", e.target.value)} />
          </div>
          <p className="text-xs text-muted-foreground">{t("servers.coordsHint")}</p>
        </div>
        <div className="flex gap-2 mt-6 justify-end">
          <button type="button" className="btn btn-sm" onClick={onClose}>{t("common.cancel")}</button>
          <button
            type="button"
            className="btn btn-primary-sm"
            onClick={() => onSave({
              ...form,
              latitude: form.latitude === "" ? null : parseFloat(form.latitude),
              longitude: form.longitude === "" ? null : parseFloat(form.longitude),
            })}
          >
            {t("common.save")}
          </button>
        </div>
      </div>
    </div>
  );
}
