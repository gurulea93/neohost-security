import { useState, useEffect, useCallback } from "react";
import Icon from "../Icons";
import { useTheme } from "../context/ThemeContext";
import { uiTheme } from "../theme";
import { PasswordInput } from "./ui/password-input";
import { FormSelect } from "./ui/form-select";
import { FormStack, FormInset, FormPanelGrid, FormSpanFull } from "./ui/form-panel";
import { ProfileTabs } from "./ui/profile-tabs";
import { useBranding } from "../context/BrandingContext";
import { useI18n } from "../i18n";
import { PanelBrand } from "./PanelBrand";

export default function ProfilePage({ authFetch, showToast }) {
  const { theme: colorTheme } = useTheme();
  const theme = uiTheme(colorTheme === "dark");
  const { branding, applyBranding } = useBranding();
  const { t } = useI18n();
  const [profileTab, setProfileTab] = useState(
    () => localStorage.getItem("neohost_profile_tab") || "account"
  );
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [linkCode, setLinkCode] = useState(null);
  const [newIp, setNewIp] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [tgToken, setTgToken] = useState("");
  const [tgWebapp, setTgWebapp] = useState("");
  const [savingTg, setSavingTg] = useState(false);
  const [whitelistOn, setWhitelistOn] = useState(false);
  const [acctUser, setAcctUser] = useState("");
  const [curPass, setCurPass] = useState("");
  const [newUser, setNewUser] = useState("");
  const [newPass, setNewPass] = useState("");
  const [confirmPass, setConfirmPass] = useState("");
  const [savingAcct, setSavingAcct] = useState(false);
  const [twoFaMethod, setTwoFaMethod] = useState("none");
  const [totpUri, setTotpUri] = useState("");
  const [totpSecret, setTotpSecret] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [twoFaPass, setTwoFaPass] = useState("");
  const [tg2faUserId, setTg2faUserId] = useState("");
  const [tg2faChallenge, setTg2faChallenge] = useState(null);
  const [tg2faCode, setTg2faCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [disablePass, setDisablePass] = useState("");
  const [disableChallenge, setDisableChallenge] = useState(null);
  const [brandName, setBrandName] = useState("");
  const [brandTagline, setBrandTagline] = useState("");
  const [brandLogoMode, setBrandLogoMode] = useState("both");
  const [brandLogo, setBrandLogo] = useState("");
  const [brandFavicon, setBrandFavicon] = useState("");
  const [brandAccent, setBrandAccent] = useState("#9333ea");
  const [brandPreset, setBrandPreset] = useState("purple");
  const [brandHistory, setBrandHistory] = useState([]);
  const [notifySettings, setNotifySettings] = useState({
    notify_bans_enabled: true,
    notify_threat_enabled: true,
    notify_offline_enabled: true,
    notify_min_interval_sec: 60,
  });
  const [sessions, setSessions] = useState([]);
  const [savingBrand, setSavingBrand] = useState(false);
  const [savingNotify, setSavingNotify] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await authFetch("/api/profile");
      const d = await r.json();
      setProfile(d);
      setWhitelistOn(!!d.settings?.ip_whitelist_enabled);
      setTgWebapp(d.settings?.telegram_webapp_url || "");
      setAcctUser(d.account?.username || "");
      setNewUser(d.account?.username || "");
      setTwoFaMethod(d.account?.two_fa_method || "none");
    } catch {
      showToast(t("profile.loadError"), theme.error);
    } finally {
      setLoading(false);
    }
  }, [authFetch, showToast]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    setBrandName(branding.panel_name || "");
    setBrandTagline(branding.panel_tagline || "");
    setBrandLogoMode(branding.logo_mode || "both");
    setBrandLogo(branding.logo_data || "");
    setBrandFavicon(branding.favicon_data || "");
    setBrandAccent(branding.accent_color || "#9333ea");
    setBrandPreset(branding.accent_preset || "purple");
  }, [branding]);

  const loadBrandHistory = useCallback(async () => {
    try {
      const r = await authFetch("/api/profile/branding/history?limit=30");
      const d = await r.json();
      setBrandHistory(d.history || []);
    } catch { /* ignore */ }
  }, [authFetch]);

  const loadNotifySettings = useCallback(async () => {
    try {
      const r = await authFetch("/api/profile/notifications");
      const d = await r.json();
      if (d.settings) setNotifySettings(d.settings);
    } catch { /* ignore */ }
  }, [authFetch]);

  const loadSessions = useCallback(async () => {
    try {
      const r = await authFetch("/api/profile/sessions");
      const d = await r.json();
      setSessions(d.sessions || []);
    } catch { /* ignore */ }
  }, [authFetch]);

  useEffect(() => {
    if (profileTab === "branding") loadBrandHistory();
    if (profileTab === "notifications") loadNotifySettings();
    if (profileTab === "sessions") loadSessions();
  }, [profileTab, loadBrandHistory, loadNotifySettings, loadSessions]);

  const generateCode = async () => {
    const r = await authFetch("/api/profile/telegram/code", { method: "POST" });
    const d = await r.json();
    setLinkCode(d);
    showToast(t("profile.codeGenerated"));
  };

  const toggleWhitelist = async () => {
    const next = !whitelistOn;
    if (next && !(profile?.whitelist || []).length) {
      showToast(t("profile.whitelistNeedIp"), theme.error);
      return;
    }
    const r = await authFetch("/api/profile/settings", {
      method: "PUT",
      body: JSON.stringify({ ip_whitelist_enabled: next }),
    });
    const d = await r.json();
    if (!r.ok) {
      showToast(d.error || t("common.error"), theme.error);
      return;
    }
    setWhitelistOn(next);
    showToast(next ? t("profile.whitelistOn") : t("profile.whitelistOff"));
  };

  const addIp = async () => {
    const ip = newIp.trim() || profile?.client_ip;
    if (!ip) return;
    const r = await authFetch("/api/profile/whitelist", {
      method: "POST",
      body: JSON.stringify({ ip, label: newLabel.trim() }),
    });
    if (!r.ok) {
      const d = await r.json();
      showToast(d.error || t("common.error"), theme.error);
      return;
    }
    setNewIp("");
    setNewLabel("");
    load();
    showToast(t("profile.ipAdded"));
  };

  const removeIp = async (id) => {
    await authFetch(`/api/profile/whitelist/${id}`, { method: "DELETE" });
    load();
    showToast(t("profile.ipRemoved"));
  };

  const unlinkTelegram = async (id) => {
    await authFetch(`/api/profile/telegram/${id}`, { method: "DELETE" });
    load();
    showToast(t("profile.telegramUnlinked"));
  };

  const saveAccount = async () => {
    setSavingAcct(true);
    try {
      const body = { current_password: curPass };
      if (newUser.trim() && newUser.trim() !== profile?.account?.username) {
        body.new_username = newUser.trim();
      }
      if (newPass) {
        body.new_password = newPass;
        body.confirm_password = confirmPass;
      }
      const r = await authFetch("/api/profile/account", {
        method: "PUT",
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      setCurPass("");
      setNewPass("");
      setConfirmPass("");
      if (d.username) {
        localStorage.setItem("neohost_username", d.username);
        setAcctUser(d.username);
      }
      showToast(t("profile.accountUpdated"));
      load();
    } catch (e) {
      showToast(e.message || t("common.error"), theme.error);
    } finally {
      setSavingAcct(false);
    }
  };

  const setupTotp = async () => {
    if (!twoFaPass) {
      showToast(t("profile.passwordRequiredWarn"), theme.warning);
      return;
    }
    try {
      const r = await authFetch("/api/profile/2fa/totp/setup", {
        method: "POST",
        body: JSON.stringify({ current_password: twoFaPass }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      setTotpUri(d.uri);
      setTotpSecret(d.secret);
      showToast(t("profile.scanQr"));
    } catch (e) {
      showToast(e.message || t("common.error"), theme.error);
    }
  };

  const enableTotp = async () => {
    try {
      const r = await authFetch("/api/profile/2fa/totp/enable", {
        method: "POST",
        body: JSON.stringify({ code: totpCode }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      setTotpCode("");
      setTotpUri("");
      setTotpSecret("");
      setTwoFaPass("");
      showToast(t("profile.totpEnabled"));
      load();
    } catch (e) {
      showToast(e.message || t("profile.invalidCode"), theme.error);
    }
  };

  const sendTelegram2fa = async () => {
    if (!twoFaPass || !tg2faUserId) {
      showToast(t("profile.telegramPassRequired"), theme.warning);
      return;
    }
    try {
      const r = await authFetch("/api/profile/2fa/telegram/send", {
        method: "POST",
        body: JSON.stringify({ current_password: twoFaPass, telegram_user_id: parseInt(tg2faUserId, 10) }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      setTg2faChallenge(d);
      showToast(t("profile.codeSentTelegram"));
    } catch (e) {
      showToast(e.message || t("common.error"), theme.error);
    }
  };

  const enableTelegram2fa = async () => {
    if (!tg2faChallenge || !tg2faCode) return;
    try {
      const r = await authFetch("/api/profile/2fa/telegram/enable", {
        method: "POST",
        body: JSON.stringify({
          challenge_token: tg2faChallenge.challenge_token,
          telegram_user_id: tg2faChallenge.telegram_user_id,
          code: tg2faCode,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      setTg2faCode("");
      setTg2faChallenge(null);
      setTwoFaPass("");
      showToast(t("profile.telegram2faEnabled"));
      load();
    } catch (e) {
      showToast(e.message || t("profile.invalidCode"), theme.error);
    }
  };

  const disable2fa = async () => {
    if (!disablePass) {
      showToast(t("profile.passwordRequiredWarn"), theme.warning);
      return;
    }
    try {
      const body = { current_password: disablePass, code: disableCode };
      if (disableChallenge) body.challenge_token = disableChallenge;
      const r = await authFetch("/api/profile/2fa/disable", {
        method: "POST",
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (d.requires_code) {
        setDisableChallenge(d.challenge_token);
        showToast(d.message || t("profile.codeSentTelegram"));
        return;
      }
      if (!r.ok) throw new Error(d.error || "Eroare");
      setDisableCode("");
      setDisablePass("");
      setDisableChallenge(null);
      showToast(t("profile.2faDisabled"));
      load();
    } catch (e) {
      showToast(e.message || t("common.error"), theme.error);
    }
  };

  const fileToDataUrl = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });

  const pickImage = async (file, maxKb, onSet) => {
    if (!file) return;
    if (file.size > maxKb * 1024) {
      showToast(t("profile.fileTooBig", { kb: maxKb }), theme.error);
      return;
    }
    if (!file.type.startsWith("image/")) {
      showToast(t("profile.invalidImage"), theme.error);
      return;
    }
    onSet(await fileToDataUrl(file));
  };

  const saveBranding = async () => {
    setSavingBrand(true);
    try {
      const body = {
        panel_name: brandName.trim(),
        panel_tagline: brandTagline.trim(),
        logo_mode: brandLogoMode,
        logo_data: brandLogo,
        favicon_data: brandFavicon,
        accent_preset: brandPreset,
        accent_color: brandAccent,
      };
      const r = await authFetch("/api/profile/branding", {
        method: "PUT",
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      applyBranding(d.branding);
      loadBrandHistory();
      showToast(t("profile.saveBranding"));
    } catch (e) {
      showToast(e.message || t("common.error"), theme.error);
    } finally {
      setSavingBrand(false);
    }
  };

  const saveNotifications = async () => {
    setSavingNotify(true);
    try {
      const r = await authFetch("/api/profile/notifications", {
        method: "PUT",
        body: JSON.stringify(notifySettings),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      setNotifySettings(d.settings);
      showToast(t("common.save"));
    } catch (e) {
      showToast(e.message || t("common.error"), theme.error);
    } finally {
      setSavingNotify(false);
    }
  };

  const revokeSession = async (tokenId) => {
    await authFetch(`/api/profile/sessions/${tokenId}`, { method: "DELETE" });
    loadSessions();
    showToast(t("profile.revoke"));
  };

  const revokeOtherSessions = async () => {
    await authFetch("/api/profile/sessions/revoke-others", { method: "POST" });
    loadSessions();
    showToast(t("profile.revokeOthers"));
  };

  const saveTelegramConfig = async () => {
    setSavingTg(true);
    try {
      const body = { webapp_url: tgWebapp };
      if (tgToken.trim()) body.bot_token = tgToken.trim();
      const r = await authFetch("/api/profile/telegram/config", {
        method: "PUT",
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Eroare");
      setTgToken("");
      showToast(d.telegram_bot_username ? t("profile.botActive", { name: d.telegram_bot_username }) : t("profile.configSaved"));
      load();
    } catch (e) {
      showToast(e.message || t("profile.invalidToken"), theme.error);
    } finally {
      setSavingTg(false);
    }
  };

  if (loading && !profile) {
    return <div className="card empty-state"><p>{t("profile.loading")}</p></div>;
  }

  const botUser = profile?.settings?.telegram_bot_username;
  const tgConfigured = profile?.settings?.telegram_configured;
  const active2fa = profile?.account?.two_fa_method || "none";

  return (
    <>
      <ProfileTabs
        active={profileTab}
        onChange={(id) => {
          setProfileTab(id);
          localStorage.setItem("neohost_profile_tab", id);
        }}
      />

      {profileTab === "account" && profile?.account && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("profile.account")}</h3>
            <span className="badge badge-info">{acctUser}</span>
          </div>
          <p className="text-sm text-muted-foreground mb-5">{t("profile.accountDesc")}</p>
          <FormStack>
            <FormPanelGrid split>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.username")}</label>
                  <input className="form-input w-full" value={newUser} onChange={(e) => setNewUser(e.target.value)} />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.currentPassword")}</label>
                  <PasswordInput value={curPass} onChange={(e) => setCurPass(e.target.value)} placeholder={t("profile.passwordRequired")} autoComplete="current-password" />
                </div>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.newPassword")}</label>
                  <PasswordInput value={newPass} onChange={(e) => setNewPass(e.target.value)} placeholder={t("profile.passwordOptional")} autoComplete="new-password" />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.confirmPassword")}</label>
                  <PasswordInput value={confirmPass} onChange={(e) => setConfirmPass(e.target.value)} autoComplete="new-password" />
                </div>
              </div>
              <FormSpanFull>
                <button type="button" className="btn btn-primary-sm" disabled={savingAcct || !curPass} onClick={saveAccount}>
                  {savingAcct ? t("common.loading") : t("profile.saveAccount")}
                </button>
              </FormSpanFull>
            </FormPanelGrid>
          </FormStack>
        </div>
      )}

      {profileTab === "branding" && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("profile.branding")}</h3>
          </div>
          <p className="text-sm text-muted-foreground mb-5">{t("profile.brandingDesc")}</p>
          <FormStack>
            <FormPanelGrid split>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.panelName")}</label>
                  <input
                    className="form-input w-full"
                    value={brandName}
                    onChange={(e) => setBrandName(e.target.value)}
                    placeholder="NeoHost"
                    maxLength={80}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.subtitle")}</label>
                  <input
                    className="form-input w-full"
                    value={brandTagline}
                    onChange={(e) => setBrandTagline(e.target.value)}
                    placeholder="Security Monitor"
                    maxLength={120}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.logoMode")}</label>
                  <FormSelect
                    value={brandLogoMode}
                    onChange={(v) => setBrandLogoMode(v)}
                    options={[
                      { value: "both", label: t("profile.logoBoth") },
                      { value: "logo", label: t("profile.logoOnly") },
                      { value: "text", label: t("profile.textOnly") },
                    ]}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.accent")}</label>
                  <FormSelect
                    value={brandPreset}
                    onChange={(v) => {
                      setBrandPreset(v);
                      const presets = branding.accent_presets || {};
                      if (presets[v]) setBrandAccent(presets[v]);
                    }}
                    options={[
                      ...Object.keys(branding.accent_presets || { purple: "#9333ea" }).map((k) => ({
                        value: k,
                        label: k.charAt(0).toUpperCase() + k.slice(1),
                      })),
                      { value: "custom", label: t("profile.accentCustom") },
                    ]}
                  />
                  {brandPreset === "custom" && (
                    <div className="flex items-center gap-2 mt-2">
                      <input
                        type="color"
                        value={brandAccent}
                        onChange={(e) => setBrandAccent(e.target.value)}
                        className="h-9 w-12 rounded border border-border cursor-pointer"
                      />
                      <input
                        className="form-input flex-1"
                        value={brandAccent}
                        onChange={(e) => setBrandAccent(e.target.value)}
                        placeholder="#9333ea"
                      />
                    </div>
                  )}
                </div>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.logoUpload")}</label>
                  <div className="branding-upload-row">
                    <input
                      type="file"
                      accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml"
                      className="form-input w-full"
                      onChange={(e) => pickImage(e.target.files?.[0], 5120, setBrandLogo)}
                    />
                    {brandLogo && (
                      <button type="button" className="btn btn-sm" onClick={() => setBrandLogo("")}>{t("common.remove")}</button>
                    )}
                  </div>
                  {brandLogo && (
                    <div className="branding-preview mt-2">
                      <img src={brandLogo} alt="Previzualizare logo" />
                    </div>
                  )}
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">{t("profile.faviconUpload")}</label>
                  <div className="branding-upload-row">
                    <input
                      type="file"
                      accept="image/png,image/x-icon,image/vnd.microsoft.icon,image/gif"
                      className="form-input w-full"
                      onChange={(e) => pickImage(e.target.files?.[0], 1024, setBrandFavicon)}
                    />
                    {brandFavicon && (
                      <button type="button" className="btn btn-sm" onClick={() => setBrandFavicon("")}>{t("common.remove")}</button>
                    )}
                  </div>
                  {brandFavicon && (
                    <div className="branding-preview branding-preview-favicon mt-2">
                      <img src={brandFavicon} alt="Previzualizare favicon" />
                    </div>
                  )}
                </div>
              </div>
              <FormSpanFull>
                <div className="branding-live-preview">
                  <span className="text-xs text-muted-foreground">{t("profile.sidebarPreview")}</span>
                  <div className="branding-preview-sidebar">
                    <PanelBrand branding={{ panel_name: brandName, logo_mode: brandLogoMode, logo_data: brandLogo }} />
                  </div>
                </div>
              </FormSpanFull>
              <FormSpanFull>
                <button type="button" className="btn btn-primary-sm" disabled={savingBrand || !brandName.trim()} onClick={saveBranding}>
                  {savingBrand ? t("common.loading") : t("profile.saveBranding")}
                </button>
              </FormSpanFull>
            </FormPanelGrid>
          </FormStack>
          <div className="mt-8 border-t border-border/40 pt-6">
            <h4 className="text-sm font-semibold mb-3">{t("profile.brandingHistory")}</h4>
            {brandHistory.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t("profile.noHistory")}</p>
            ) : (
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {brandHistory.map((row) => (
                  <div key={row.id} className="text-xs p-3 rounded-lg border border-border/40 bg-muted/30">
                    <div className="flex justify-between gap-2 mb-1">
                      <span className="font-medium">{row.username}</span>
                      <span className="text-muted-foreground">{row.created_at?.replace("T", " ").slice(0, 19)}</span>
                    </div>
                    <div className="text-muted-foreground">
                      {Object.keys(row.changes || {}).join(", ")}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {profileTab === "notifications" && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("profile.notifications")}</h3>
          </div>
          <p className="text-sm text-muted-foreground mb-5">{t("profile.notifyHint")}</p>
          <FormStack>
            <div className="space-y-4 max-w-lg">
              {[
                ["notify_bans_enabled", t("profile.notifyBans")],
                ["notify_threat_enabled", t("profile.notifyThreat")],
                ["notify_offline_enabled", t("profile.notifyOffline")],
              ].map(([key, label]) => (
                <label key={key} className="flex items-center justify-between gap-4 text-sm">
                  <span>{label}</span>
                  <input
                    type="checkbox"
                    checked={!!notifySettings[key]}
                    onChange={(e) => setNotifySettings((p) => ({ ...p, [key]: e.target.checked }))}
                    className="w-4 h-4 accent-purple-500"
                  />
                </label>
              ))}
              <div>
                <label className="text-xs text-muted-foreground">{t("profile.notifyInterval")}</label>
                <input
                  type="number"
                  min={15}
                  max={3600}
                  className="form-input w-full mt-1"
                  value={notifySettings.notify_min_interval_sec}
                  onChange={(e) => setNotifySettings((p) => ({
                    ...p,
                    notify_min_interval_sec: parseInt(e.target.value, 10) || 60,
                  }))}
                />
              </div>
              <button type="button" className="btn btn-primary-sm" disabled={savingNotify} onClick={saveNotifications}>
                {savingNotify ? t("common.loading") : t("common.save")}
              </button>
            </div>
          </FormStack>
        </div>
      )}

      {profileTab === "sessions" && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("profile.sessions")}</h3>
            <button type="button" className="btn btn-sm btn-danger" onClick={revokeOtherSessions}>
              {t("profile.revokeOthers")}
            </button>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>{t("profile.sessionDevice")}</th>
                <th>{t("profile.sessionStarted")}</th>
                <th>{t("profile.sessionExpires")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.token_id}>
                  <td className="text-sm">
                    <div className="mono text-xs">{s.ip_address || "—"}</div>
                    <div className="text-muted-foreground text-[11px] truncate max-w-[240px]" title={s.user_agent}>
                      {s.user_agent || "—"}
                    </div>
                    {s.current && <span className="badge badge-info text-[10px] mt-1">{t("profile.sessionCurrent")}</span>}
                  </td>
                  <td className="text-sm whitespace-nowrap">{s.created_at?.replace("T", " ").slice(0, 19)}</td>
                  <td className="text-sm whitespace-nowrap">{s.expires_at?.replace("T", " ").slice(0, 19)}</td>
                  <td>
                    {!s.current && (
                      <button type="button" className="btn btn-sm" onClick={() => revokeSession(s.token_id)}>
                        {t("profile.revoke")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {profileTab === "whitelist" && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("profile.whitelistTitle")}</h3>
            <button
              type="button"
              className={`btn btn-sm ${whitelistOn ? "btn-success" : ""}`}
              onClick={toggleWhitelist}
            >
              {whitelistOn ? t("profile.whitelistActive") : t("profile.whitelistInactive")}
            </button>
          </div>
          <p className="text-sm text-muted-foreground mb-4">{t("profile.whitelistDesc")}</p>
          {!whitelistOn && (
            <p className="text-sm text-amber-400/90 mb-4">{t("profile.whitelistHint")}</p>
          )}
          <div className="flex items-center gap-2 mb-4 flex-wrap">
            <span className="text-sm text-muted-foreground">{t("profile.yourIp")}</span>
            <span className="mono font-semibold text-purple-400">{profile?.client_ip || "—"}</span>
            <button type="button" className="btn btn-sm" onClick={() => setNewIp(profile?.client_ip || "")}>
              {t("profile.useCurrentIp")}
            </button>
          </div>
          <div className="flex gap-2 flex-wrap mb-4">
            <input className="form-input w-44" placeholder={t("profile.ipCidr")} value={newIp} onChange={(e) => setNewIp(e.target.value)} />
            <input className="form-input w-40" placeholder={t("profile.label")} value={newLabel} onChange={(e) => setNewLabel(e.target.value)} />
            <button type="button" className="btn btn-primary-sm" onClick={addIp}><Icon name="plus" size={14} /> {t("common.add")}</button>
          </div>
          <table className="data-table">
            <thead><tr><th>{t("common.ip")}</th><th>{t("profile.label")}</th><th></th></tr></thead>
            <tbody>
              {(profile?.whitelist || []).map((w) => (
                <tr key={w.id}>
                  <td className="mono">{w.ip}</td>
                  <td>{w.label || "—"}</td>
                  <td>
                    <button type="button" className="btn btn-sm btn-danger" onClick={() => removeIp(w.id)}>
                      <Icon name="close" size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {(profile?.whitelist || []).length === 0 && (
            <p className="text-sm text-muted-foreground mt-3">
              {whitelistOn ? t("profile.whitelistEmptyBlocked") : t("profile.whitelistEmptyInactive")}
            </p>
          )}
        </div>
      )}

      {profileTab === "2fa" && profile?.account && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">{t("profile.2faTitle")}</h3>
            <span className={`badge ${active2fa !== "none" ? "badge-success" : "badge-warning"}`}>
              {active2fa === "totp" ? t("profile.2faTotp") : active2fa === "telegram" ? t("profile.2faTelegram") : t("profile.2faDisabledLabel")}
            </span>
          </div>
          <p className="text-sm text-muted-foreground mb-5">
            Protejați contul cu un cod suplimentar la login — prin Google Authenticator sau Telegram.
          </p>

          {active2fa === "none" && twoFaMethod === "none" && (
            <FormInset className="space-y-3">
              <p className="text-sm font-medium">Alegeți metoda de activare</p>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn btn-sm btn-primary-sm" onClick={() => setTwoFaMethod("totp")}>
                  Google Authenticator
                </button>
                <button type="button" className="btn btn-sm" onClick={() => setTwoFaMethod("telegram")}>
                  Telegram
                </button>
              </div>
            </FormInset>
          )}

          {twoFaMethod === "totp" && active2fa !== "totp" && (
            <FormInset className="space-y-3 border-purple-500/30">
              <h4 className="text-sm font-medium text-purple-300">Configurare Google Authenticator</h4>
              <PasswordInput value={twoFaPass} onChange={(e) => setTwoFaPass(e.target.value)} placeholder="Parola curentă" />
              {!totpUri ? (
                <button type="button" className="btn btn-sm btn-primary-sm" onClick={setupTotp}>{t("profile.generateQr")}</button>
              ) : (
                <>
                  <img
                    alt="QR TOTP"
                    className="mx-auto rounded-lg border border-border/40 bg-white p-2"
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(totpUri)}`}
                  />
                  <p className="text-xs mono text-center text-muted-foreground break-all">{totpSecret}</p>
                  <input className="form-input mono text-center" placeholder="Cod 6 cifre" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} />
                  <button type="button" className="btn btn-sm btn-success" onClick={enableTotp}>{t("profile.enable2faBtn")}</button>
                </>
              )}
              <button type="button" className="btn btn-sm" onClick={() => { setTwoFaMethod("none"); setTotpUri(""); }}>{t("common.cancel")}</button>
            </FormInset>
          )}

          {twoFaMethod === "telegram" && active2fa !== "telegram" && (
            <FormInset className="space-y-3 border-emerald-500/30">
              <h4 className="text-sm font-medium text-emerald-300">Configurare 2FA Telegram</h4>
              <p className="text-xs text-muted-foreground">Conectați mai întâi un cont în tab-ul Telegram.</p>
              <PasswordInput value={twoFaPass} onChange={(e) => setTwoFaPass(e.target.value)} placeholder="Parola curentă" />
              <FormSelect
                value={tg2faUserId}
                onChange={setTg2faUserId}
                placeholder="Cont Telegram…"
                options={[
                  { value: "", label: "Cont Telegram…" },
                  ...(profile.telegram_users || []).map((u) => ({
                    value: String(u.id),
                    label: u.first_name || u.username || String(u.telegram_id),
                  })),
                ]}
              />
              {!tg2faChallenge ? (
                <button type="button" className="btn btn-sm btn-primary-sm" onClick={sendTelegram2fa} disabled={!profile.telegram_users?.length}>
                  Trimite cod verificare
                </button>
              ) : (
                <>
                  <input className="form-input mono text-center" placeholder="Cod din Telegram" value={tg2faCode} onChange={(e) => setTg2faCode(e.target.value)} />
                  <button type="button" className="btn btn-sm btn-success" onClick={enableTelegram2fa}>{t("profile.enable2faTgBtn")}</button>
                </>
              )}
              <button type="button" className="btn btn-sm" onClick={() => { setTwoFaMethod("none"); setTg2faChallenge(null); }}>{t("common.cancel")}</button>
            </FormInset>
          )}

          {active2fa !== "none" && (
            <FormInset className="space-y-3 border-red-500/20 mt-4">
              <h4 className="text-sm font-medium">Dezactivare 2FA</h4>
              <p className="text-xs text-muted-foreground">
                {active2fa === "telegram" ? t("profile.disable2faHintTg") : t("profile.disable2faHint")}
              </p>
              <PasswordInput value={disablePass} onChange={(e) => setDisablePass(e.target.value)} placeholder="Parola curentă" />
              <input className="form-input mono text-center" placeholder="Cod 2FA" value={disableCode} onChange={(e) => setDisableCode(e.target.value)} />
              <button type="button" className="btn btn-sm btn-danger" onClick={disable2fa}>{t("profile.disable2fa")}</button>
            </FormInset>
          )}
        </div>
      )}

      {profileTab === "telegram" && (
        <>
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">{t("profile.telegramTitle")}</h3>
              {tgConfigured ? (
                <span className="badge badge-success">Bot activ</span>
              ) : (
                <span className="badge badge-warning">Neconfigurat</span>
              )}
            </div>
            <p className="text-sm text-muted-foreground mb-4">
              Configurează botul, conectează conturi și controlează serverele din Telegram.
            </p>

            <FormInset className="space-y-3 mb-4">
              <h4 className="text-sm font-medium">Configurare bot</h4>
              <p className="text-xs text-muted-foreground">
                {t("profile.tokenHint")} <a href="https://t.me/BotFather" target="_blank" rel="noreferrer">@BotFather</a>.
                {profile?.settings?.telegram_token_hint && (
                  <> Activ: <code className="text-purple-400">{profile.settings.telegram_token_hint}</code></>
                )}
              </p>
              <PasswordInput
                className="w-full"
                value={tgToken}
                onChange={(e) => setTgToken(e.target.value)}
                placeholder={t("profile.botToken")}
              />
              <input
                className="form-input w-full"
                type="url"
                placeholder={t("profile.webappUrl")}
                value={tgWebapp}
                onChange={(e) => setTgWebapp(e.target.value)}
              />
              <button type="button" className="btn btn-primary-sm" disabled={savingTg} onClick={saveTelegramConfig}>
                <Icon name="key" size={14} /> {savingTg ? "Se salvează…" : "Salvează & pornește bot"}
              </button>
            </FormInset>

            {!tgConfigured && !profile?.settings?.telegram_token_hint && (
              <div className="form-stack rounded-lg p-3 mb-4 text-xs bg-amber-500/10 text-amber-200 border border-amber-500/20">
                Introduceți tokenul bot mai sus sau setați <code>TELEGRAM_BOT_TOKEN</code> în .env.
              </div>
            )}

            {tgConfigured && (
              <>
                <button className="btn btn-primary-sm" onClick={generateCode}>
                  <Icon name="link" size={14} /> {t("profile.linkCodeBtn")}
                </button>
                <p className="text-xs text-muted-foreground mt-3 form-stack">
                  În bot: butoane inline + Mini App. URL: <code>/telegram.html</code> (HTTPS în producție).
                </p>
                {linkCode && (
                  <FormInset className="mt-4">
                    <div className="text-xs text-muted-foreground mb-2">Trimite în Telegram:</div>
                    <div className="mono text-lg font-semibold text-purple-400">/link {linkCode.code}</div>
                    {botUser && (
                      <div className="mt-2 text-sm">
                        Bot: <a href={`https://t.me/${botUser}`} target="_blank" rel="noreferrer" className="text-purple-400">@{botUser}</a>
                      </div>
                    )}
                    <div className="text-xs text-muted-foreground mt-2">
                      Expiră: {new Date(linkCode.expires_at).toLocaleString("ro-RO")}
                    </div>
                  </FormInset>
                )}
              </>
            )}

            <h4 className="text-sm font-medium mt-6 mb-3">Conturi conectate</h4>
            {(profile?.telegram_users || []).length === 0 ? (
              <p className="text-sm text-muted-foreground">{t("profile.noTelegram")}</p>
            ) : (
              <table className="data-table">
                <thead><tr><th>Utilizator</th><th>ID</th><th>Conectat</th><th></th></tr></thead>
                <tbody>
                  {profile.telegram_users.map((u) => (
                    <tr key={u.id}>
                      <td>{u.first_name || "—"} {u.username && <span className="text-muted-foreground">@{u.username}</span>}</td>
                      <td className="mono">{u.telegram_id}</td>
                      <td className="text-sm text-muted-foreground">
                        {u.linked_at ? new Date(u.linked_at).toLocaleDateString("ro-RO") : "—"}
                      </td>
                      <td>
                        <button className="btn btn-sm btn-danger" onClick={() => unlinkTelegram(u.id)}>Deconectează</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="card mt-5">
            <h3 className="card-title mb-4">{t("profile.botCommands")}</h3>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 text-sm">
              {[
                ["/servers", "Lista servere"],
                ["/status [id]", "Nivel amenințare"],
                ["/jails [id]", "Jailuri Fail2Ban"],
                ["/ban IP [jail]", "Ban IP"],
                ["/unban IP", "Debanează IP"],
                ["/csf [id]", "Status CSF"],
                ["/csfdeny IP", "CSF deny"],
                ["/csfallow IP", "CSF allow"],
                ["/nft [id]", "Status nftables"],
                ["/nftdeny IP", "nftables deny"],
                ["/nftallow IP", "nftables allow"],
                ["/connections [id]", "Conexiuni active"],
              ].map(([cmd, desc]) => (
                <div key={cmd} className="p-3 rounded-lg border border-border/40">
                  <div className="mono text-purple-400 mb-1">{cmd}</div>
                  <div className="text-muted-foreground text-xs">{desc}</div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </>
  );
}
