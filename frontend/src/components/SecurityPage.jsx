import { useState, useEffect, useCallback } from "react";
import Icon from "../Icons";
import { useTheme } from "../context/ThemeContext";
import { uiTheme } from "../theme";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormSelect } from "./ui/form-select";
import { FormPanel, FormPanelGrid } from "./ui/form-panel";

import { useI18n } from "../i18n";

const PAGE_TABS = [
  { id: "audit", labelKey: "security.tabAudit", icon: "activity" },
  { id: "f2b", labelKey: "security.tabF2b", icon: "shield" },
  { id: "csf", labelKey: "security.tabCsf", icon: "lock" },
  { id: "nft", labelKey: "security.tabNft", icon: "shield" },
  { id: "custom", labelKey: "security.tabCustom", icon: "plus" },
];

const SEVERITY_STYLE = {
  critical: { bg: "rgba(239,68,68,0.15)", border: "rgba(239,68,68,0.4)", text: "#f87171" },
  high: { bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.35)", text: "#fb923c" },
  medium: { bg: "rgba(234,179,8,0.12)", border: "rgba(234,179,8,0.35)", text: "#facc15" },
};

const KIND_OPTIONS = [
  { value: "fail2ban_jail", label: "Fail2Ban — jail nou" },
  { value: "csf_preset", label: "CSF — preset" },
  { value: "nftables_preset", label: "nftables — preset" },
];

const PAYLOAD_TEMPLATES = {
  fail2ban_jail: {
    jail_name: "my-jail",
    enabled: "true",
    filter: "sshd",
    port: "ssh",
    logpath: "/var/log/auth.log",
    maxretry: 5,
    bantime: "1h",
    findtime: "10m",
  },
  csf_preset: {
    toggles: {
      TESTING: false,
      LF_SSHD: true,
      SYNFLOOD: true,
      CONNLIMIT: true,
      PORTFLOOD: true,
    },
    ports: { TCP_IN: ["22", "80", "443"] },
    enable_firewall: true,
    restart: true,
  },
  nftables_preset: {
    chain_policies: { input: "drop", forward: "drop", output: "accept" },
    open_ports: ["22", "80", "443"],
    allow: [],
    deny: [],
    enable: true,
    reload: true,
  },
};

function payloadJsonForKind(kind) {
  const tpl = PAYLOAD_TEMPLATES[kind] ?? PAYLOAD_TEMPLATES.fail2ban_jail;
  return JSON.stringify(tpl, null, 2);
}

const EMPTY_CUSTOM = {
  kind: "fail2ban_jail",
  name: "",
  description: "",
  instructions: "",
  critical: false,
  payloadJson: payloadJsonForKind("fail2ban_jail"),
};

async function parseApiJson(r) {
  const text = await r.text();
  try {
    return { ok: r.ok, data: JSON.parse(text), status: r.status };
  } catch {
    const hint = r.status === 404
      ? "Endpoint negăsit — reporniți backend-ul."
      : "Backend indisponibil — verificați fereastra NeoHost Backend.";
    throw new Error(hint);
  }
}

function TemplateFormFields({ form, setForm, layout = "stack" }) {
  const handleKindChange = (kind) => {
    setForm((p) => ({
      ...p,
      kind,
      payloadJson: payloadJsonForKind(kind),
    }));
  };

  const metaFields = (
    <>
      <div>
        <label className="text-xs text-muted-foreground mb-1 block">Tip șablon</label>
        <FormSelect
          value={form.kind}
          onChange={handleKindChange}
          options={KIND_OPTIONS}
          disabled={!!form.editId}
        />
      </div>
      <input
        className="form-input"
        placeholder="Nume șablon"
        value={form.name}
        onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
      />
      <input
        className="form-input"
        placeholder="Descriere scurtă"
        value={form.description}
        onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
      />
      <textarea
        className="form-input min-h-[100px]"
        placeholder="Instrucțiuni (pași, verificări înainte de aplicare…)"
        value={form.instructions}
        onChange={(e) => setForm((p) => ({ ...p, instructions: e.target.value }))}
      />
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={form.critical}
          onChange={(e) => setForm((p) => ({ ...p, critical: e.target.checked }))}
        />
        Zonă critică
      </label>
    </>
  );

  const jsonField = (
    <div className="h-full flex flex-col min-h-[280px]">
      <label className="text-xs text-muted-foreground mb-1 block">Payload JSON</label>
      <textarea
        className="form-input mono text-xs flex-1 min-h-[280px] lg:min-h-[420px]"
        value={form.payloadJson}
        onChange={(e) => setForm((p) => ({ ...p, payloadJson: e.target.value }))}
      />
    </div>
  );

  if (layout === "split") {
    return (
      <FormPanelGrid split>
        <div className="space-y-3">{metaFields}</div>
        <div>{jsonField}</div>
      </FormPanelGrid>
    );
  }

  return (
    <div className="space-y-3">
      {metaFields}
      {jsonField}
    </div>
  );
}

function TemplateCard({ tpl, onApply, onApplyBulk, onEdit, onDuplicate, onDelete, theme }) {
  const [open, setOpen] = useState(false);
  const sev = tpl.critical ? SEVERITY_STYLE.high : null;

  return (
    <div
      className="rounded-xl border border-border/40 bg-muted/20 p-4"
      style={sev ? { borderColor: sev.border } : undefined}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div>
          <div className="font-medium text-foreground flex items-center gap-2 flex-wrap">
            {tpl.name}
            {tpl.critical && <span className="badge badge-warning text-[10px]">Critic</span>}
            {tpl.is_builtin && <span className="badge badge-info text-[10px]">Predefinit</span>}
          </div>
          <p className="text-xs text-muted-foreground mt-1">{tpl.description}</p>
        </div>
      </div>
      {tpl.instructions && (
        <button type="button" className="text-xs text-purple-400 mb-2 hover:underline" onClick={() => setOpen(!open)}>
          {open ? "Ascunde instrucțiuni" : "Vezi instrucțiuni & pași"}
        </button>
      )}
      {open && (
        <pre className="text-xs text-muted-foreground whitespace-pre-wrap mb-3 p-3 rounded-lg bg-background/50 border border-border/30 max-h-48 overflow-y-auto">
          {tpl.instructions}
        </pre>
      )}
      <div className="flex flex-wrap gap-2">
        <button type="button" className="btn btn-sm btn-primary-sm" onClick={() => onApply(tpl)}>
          Aplică pe server
        </button>
        <button type="button" className="btn btn-sm" onClick={() => onApplyBulk(tpl)}>
          Aplică pe mai multe servere
        </button>
        {tpl.is_builtin ? (
          <button type="button" className="btn btn-sm" onClick={() => onDuplicate(tpl)} title="Creează o copie editabilă">
            <Icon name="copy" size={12} className="inline mr-1" />
            Duplică
          </button>
        ) : (
          <button type="button" className="btn btn-sm" onClick={() => onEdit(tpl)}>
            <Icon name="edit" size={12} className="inline mr-1" />
            Editează
          </button>
        )}
        {!tpl.is_builtin && (
          <button type="button" className="btn btn-sm btn-danger" onClick={() => onDelete(tpl)}>
            Șterge
          </button>
        )}
      </div>
    </div>
  );
}

export default function SecurityPage({ authFetch, serverId, server, servers, showToast }) {
  const { theme: colorTheme } = useTheme();
  const { t } = useI18n();
  const theme = uiTheme(colorTheme === "dark");
  const [tab, setTab] = useState("audit");
  const [audit, setAudit] = useState(null);
  const [templates, setTemplates] = useState([]);
  const [jails, setJails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [bulkTpl, setBulkTpl] = useState(null);
  const [bulkServers, setBulkServers] = useState([]);
  const [confirmDlg, setConfirmDlg] = useState(null);
  const [editForm, setEditForm] = useState(null);
  const [custom, setCustom] = useState(EMPTY_CUSTOM);

  const qs = serverId ? `?server_id=${serverId}` : "";

  const load = useCallback(async () => {
    if (!serverId) return;
    setLoading(true);
    try {
      const [auditR, tplR, f2bR] = await Promise.all([
        authFetch(`/api/security/audit${qs}`),
        authFetch("/api/security/templates"),
        server?.mod_fail2ban ? authFetch(`/api/fail2ban${qs}`) : Promise.resolve({ text: () => '{"fail2ban":{"jails":[]}}' }),
      ]);
      const auditP = await parseApiJson(auditR);
      const tplP = await parseApiJson(tplR);
      if (!auditP.ok) throw new Error(auditP.data.error || "Eroare audit");
      if (!tplP.ok) throw new Error(tplP.data.error || "Eroare șabloane");
      setAudit(auditP.data);
      setTemplates(tplP.data.templates || []);
      const f2bP = await parseApiJson(f2bR);
      setJails(f2bP.data.fail2ban?.jails || f2bP.data.jails || []);
    } catch (e) {
      showToast(e.message || t("security.loadError"), theme.error);
    } finally {
      setLoading(false);
    }
  }, [authFetch, qs, serverId, server, showToast, theme.error]);

  useEffect(() => { load(); }, [load]);

  const applyTemplate = async (tpl, targetIds = null) => {
    try {
      if (targetIds?.length) {
        const r = await authFetch(`/api/security/templates/${tpl.id}/apply-bulk`, {
          method: "POST",
          body: JSON.stringify({ server_ids: targetIds }),
        });
        const { ok, data } = await parseApiJson(r);
        if (!ok) throw new Error(data.error);
        showToast(t("security.templateApplied", { count: data.queued }));
        setBulkTpl(null);
        setBulkServers([]);
      } else {
        const r = await authFetch(`/api/security/templates/${tpl.id}/apply${qs}`, { method: "POST" });
        const { ok, data } = await parseApiJson(r);
        if (!ok) throw new Error(data.error);
        showToast(t("security.cmdSent", { name: tpl.name }));
      }
      setTimeout(load, 2500);
    } catch (e) {
      showToast(e.message || t("common.error"), theme.error);
    }
  };

  const deleteJail = (jail) => {
    setConfirmDlg({
      title: "Șterge jail",
      message: `Ștergeți jailul «${jail}»? Se elimină doar fișierul creat din panou (neohost-${jail}.conf).`,
      onConfirm: async () => {
        setConfirmDlg(null);
        await authFetch(`/api/fail2ban/jail/${encodeURIComponent(jail)}${qs}`, { method: "DELETE" });
        showToast(t("security.jailDeleted"));
        setTimeout(load, 2500);
      },
    });
  };

  const tplToForm = (tpl, { asCopy = false } = {}) => ({
    editId: asCopy ? null : (tpl.is_builtin ? null : tpl.id),
    kind: tpl.kind,
    name: asCopy ? `${tpl.name} (copie)` : tpl.name,
    description: tpl.description || "",
    instructions: tpl.instructions || "",
    critical: !!tpl.critical,
    payloadJson: JSON.stringify(tpl.payload || {}, null, 2),
  });

  const openEdit = (tpl) => setEditForm(tplToForm(tpl));

  const duplicateTpl = (tpl) => {
    setCustom(tplToForm(tpl, { asCopy: true }));
    setTab("custom");
    showToast(t("security.copyReady"));
  };

  const saveForm = async (form, { isEdit }) => {
    const payload = JSON.parse(form.payloadJson);
    const body = {
      kind: form.kind,
      name: form.name,
      description: form.description,
      instructions: form.instructions,
      critical: form.critical,
      payload,
    };
    const r = isEdit
      ? await authFetch(`/api/security/templates/${form.editId}`, { method: "PUT", body: JSON.stringify(body) })
      : await authFetch("/api/security/templates", { method: "POST", body: JSON.stringify(body) });
    const { ok, data } = await parseApiJson(r);
    if (!ok) throw new Error(data.error);
    return data.template;
  };

  const saveCustom = async () => {
    try {
      await saveForm(custom, { isEdit: false });
      showToast(t("security.templateSaved"));
      setCustom(EMPTY_CUSTOM);
      load();
      setTab(custom.kind === "fail2ban_jail" ? "f2b" : custom.kind === "nftables_preset" ? "nft" : "csf");
    } catch (e) {
      showToast(e.message || t("security.jsonError"), theme.error);
    }
  };

  const saveEdit = async () => {
    try {
      await saveForm(editForm, { isEdit: true });
      showToast(t("security.templateUpdated"));
      setEditForm(null);
      load();
    } catch (e) {
      showToast(e.message || "Eroare la salvare", theme.error);
    }
  };

  const f2bTemplates = templates.filter((t) => t.kind === "fail2ban_jail");
  const csfTemplates = templates.filter((t) => t.kind === "csf_preset");
  const nftTemplates = templates.filter((t) => t.kind === "nftables_preset");

  const templateCardProps = {
    theme,
    onApply: applyTemplate,
    onApplyBulk: (tplItem) => { setBulkTpl(tplItem); setBulkServers(serverId ? [serverId] : []); },
    onEdit: openEdit,
    onDuplicate: duplicateTpl,
    onDelete: (tplItem) => {
      setConfirmDlg({
        title: t("common.delete"),
        message: `${tplItem.name}?`,
        onConfirm: async () => {
          setConfirmDlg(null);
          const r = await authFetch(`/api/security/templates/${tplItem.id}`, { method: "DELETE" });
          const { ok, data } = await parseApiJson(r);
          if (!ok) { showToast(data.error || t("common.error"), theme.error); return; }
          showToast(t("security.templateDeleted"));
          load();
        },
      });
    },
  };

  if (!serverId) {
    return <div className="card empty-state"><p>Selectați un server.</p></div>;
  }

  if (loading && !audit) {
    return <div className="card empty-state"><p>{t("security.loading")}</p></div>;
  }

  const gradeColor = audit?.score >= 85 ? theme.success : audit?.score >= 50 ? theme.warning : theme.error;

  return (
    <>
      <div className="profile-tabs mb-5">
        {PAGE_TABS.map((tabDef) => (
          <button
            key={tabDef.id}
            type="button"
            className={`profile-tab ${tab === tabDef.id ? "profile-tab-active" : ""}`}
            onClick={() => setTab(tabDef.id)}
          >
            <Icon name={tabDef.icon} size={15} />
            <span>{t(tabDef.labelKey)}</span>
          </button>
        ))}
      </div>

      <div className="card mb-5 p-4 text-sm text-muted-foreground border border-border/40 form-panel">
        <strong className="text-foreground">Șabloane vs. configurație aplicată</strong>
        <ul className="mt-2 space-y-1 list-disc list-inside text-xs">
          <li><strong>Predefinite</strong> — nu se editează; folosiți <em>Duplică</em> pentru o variantă proprie.</li>
          <li><strong>Personalizate</strong> — buton <em>Editează</em>; modificarea nu actualizează automat serverele.</li>
          <li>După editare, apăsați din nou <em>Aplică pe server</em> (sau pe mai multe servere).</li>
          <li>Pentru Fail2Ban, jailurile deja create rămân până le ștergeți din lista de mai sus.</li>
        </ul>
      </div>

      <ConfirmDialog
        open={!!confirmDlg}
        title={confirmDlg?.title}
        message={confirmDlg?.message}
        confirmLabel="Confirmă"
        danger
        onConfirm={confirmDlg?.onConfirm}
        onCancel={() => setConfirmDlg(null)}
      />

      {editForm && (
        <div className="modal-overlay" onClick={() => setEditForm(null)}>
          <div className="modal max-w-5xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-semibold mb-2">Editează șablon</h3>
            <p className="text-xs text-muted-foreground mb-4">
              Salvați modificările, apoi re-aplicați șablonul pe serverele dorite.
            </p>
            <TemplateFormFields form={editForm} setForm={setEditForm} layout="split" />
            <div className="flex justify-end gap-2 mt-4">
              <button type="button" className="btn btn-sm" onClick={() => setEditForm(null)}>{t("common.cancel")}</button>
              <button type="button" className="btn btn-sm btn-primary-sm" onClick={saveEdit} disabled={!editForm.name.trim()}>
                Salvează modificările
              </button>
            </div>
          </div>
        </div>
      )}

      {bulkTpl && (
        <div className="modal-overlay" onClick={() => setBulkTpl(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-semibold mb-2">Aplică: {bulkTpl.name}</h3>
            <p className="text-sm text-muted-foreground mb-4">Selectați serverele țintă:</p>
            <div className="space-y-2 max-h-60 overflow-y-auto mb-4">
              {servers.map((s) => (
                <label key={s.id} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={bulkServers.includes(s.id)}
                    onChange={(e) => setBulkServers((prev) =>
                      e.target.checked ? [...prev, s.id] : prev.filter((id) => id !== s.id)
                    )}
                  />
                  {s.name} {s.online ? "(online)" : "(offline)"}
                </label>
              ))}
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" className="btn btn-sm" onClick={() => setBulkTpl(null)}>{t("common.cancel")}</button>
              <button
                type="button"
                className="btn btn-sm btn-primary-sm"
                disabled={!bulkServers.length}
                onClick={() => applyTemplate(bulkTpl, bulkServers)}
              >
                Aplică ({bulkServers.length})
              </button>
            </div>
          </div>
        </div>
      )}

      {tab === "audit" && audit && (
        <div className="space-y-5">
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">{t("security.score", { name: server?.name })}</h3>
              <span className="badge" style={{ background: gradeColor, color: "#fff" }}>
                {audit.grade} · {audit.score}/100
              </span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
              <div className="metric-card"><label>Jailuri</label><div className="value text-sm">{audit.summary?.jails_active}/{audit.summary?.jails_total}</div></div>
              <div className="metric-card"><label>Amenințare</label><div className="value text-sm">{audit.summary?.threat_level}</div></div>
              <div className="metric-card"><label>CSF test</label><div className="value text-sm">{audit.summary?.csf_testing ? "DA" : "NU"}</div></div>
            </div>
            {audit.findings?.length === 0 ? (
              <p className="text-sm text-green-400">Nicio problemă majoră detectată. Continuați monitorizarea.</p>
            ) : (
              <div className="space-y-2">
                {audit.findings.map((f) => {
                  const st = SEVERITY_STYLE[f.severity] || SEVERITY_STYLE.medium;
                  const tpl = templates.find((t) => t.slug === f.template_slug);
                  return (
                    <div key={f.id} className="rounded-lg border p-3 flex flex-wrap items-center justify-between gap-2" style={{ borderColor: st.border, background: st.bg }}>
                      <div>
                        <div className="text-sm font-medium" style={{ color: st.text }}>{f.title}</div>
                        <div className="text-xs text-muted-foreground">{f.detail}</div>
                      </div>
                      {tpl && (
                        <button type="button" className="btn btn-sm btn-primary-sm" onClick={() => applyTemplate(tpl)}>
                          Aplică: {tpl.name}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "f2b" && (
        <div className="space-y-5">
          {server?.mod_fail2ban && (
            <div className="card">
              <h3 className="card-title mb-3">{t("security.activeJails")}</h3>
              {jails.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("security.noJails")}</p>
              ) : (
                <table className="data-table">
                  <thead><tr><th>Jail</th><th>Status</th><th>Banate</th><th></th></tr></thead>
                  <tbody>
                    {jails.map((j) => (
                      <tr key={j.name}>
                        <td className="font-medium">{j.name}</td>
                        <td>{j.active ? <span className="badge badge-success">ON</span> : <span className="badge">OFF</span>}</td>
                        <td>{j.currently_banned ?? 0}</td>
                        <td>
                          <button type="button" className="btn btn-sm btn-danger" onClick={() => deleteJail(j.name)} title="Șterge config panou">
                            <Icon name="trash" size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p className="text-xs text-muted-foreground mt-3">
                Ștergerea elimină fișierele create din panou (<code>jail.d/neohost-*.conf</code>). Jailurile sistem rămân neschimbate.
              </p>
            </div>
          )}
          <div className="grid gap-4 md:grid-cols-2">
            {f2bTemplates.map((tpl) => (
              <TemplateCard key={tpl.id} tpl={tpl} {...templateCardProps} />
            ))}
          </div>
        </div>
      )}

      {tab === "csf" && (
        <div className="grid gap-4 md:grid-cols-2">
          {!server?.mod_csf && (
            <div className="card col-span-full empty-state"><p>CSF dezactivat pentru acest server.</p></div>
          )}
          {csfTemplates.map((tpl) => (
            <TemplateCard key={tpl.id} tpl={tpl} {...templateCardProps} />
          ))}
        </div>
      )}

      {tab === "nft" && (
        <div className="grid gap-4 md:grid-cols-2">
          {!server?.mod_nftables && (
            <div className="card col-span-full empty-state"><p>{t("nft.moduleDisabled")}</p></div>
          )}
          {nftTemplates.map((tpl) => (
            <TemplateCard key={tpl.id} tpl={tpl} {...templateCardProps} />
          ))}
        </div>
      )}

      {tab === "custom" && (
        <div className="card form-panel">
          <h3 className="card-title mb-4">{t("security.createTemplate")}</h3>
          <p className="text-sm text-muted-foreground mb-6">
            Salvați configurații proprii și aplicați-le pe orice server ulterior.
            Puteți porni de la un șablon predefinit cu butonul <em>Duplică</em>.
          </p>
          <TemplateFormFields form={custom} setForm={setCustom} layout="split" />
          <div className="mt-6 flex justify-end">
            <button type="button" className="btn btn-primary-sm" onClick={saveCustom} disabled={!custom.name.trim()}>
              Salvează șablon
            </button>
          </div>
        </div>
      )}
    </>
  );
}
