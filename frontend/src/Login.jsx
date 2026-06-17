import { useState } from "react";
import Icon from "./Icons";
import { useTheme } from "./context/ThemeContext";
import { useBranding } from "./context/BrandingContext";
import { useI18n } from "./i18n";
import { PanelBrand } from "./components/PanelBrand";
import { PasswordInput } from "./components/ui/password-input";

export default function Login({ onLogin, defaultApiUrl }) {
  const { theme, toggleTheme } = useTheme();
  const { branding } = useBranding();
  const { t } = useI18n();
  const [apiUrl, setApiUrl] = useState(
    () => localStorage.getItem("neohost_api_url") || defaultApiUrl || ""
  );
  const [username, setUsername] = useState(
    () => localStorage.getItem("neohost_username") || "admin"
  );
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [step2fa, setStep2fa] = useState(null);
  const [otpCode, setOtpCode] = useState("");
  const [useLegacy, setUseLegacy] = useState(false);
  const [legacyToken, setLegacyToken] = useState("");

  const baseUrl = () => apiUrl.replace(/\/$/, "");

  const handleLoginSuccess = (token, user) => {
    localStorage.setItem("neohost_token", token);
    localStorage.setItem("neohost_api_url", baseUrl());
    if (user?.username) localStorage.setItem("neohost_username", user.username);
    onLogin(token, baseUrl(), user?.username);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!password.trim()) {
      setError("Introduceți parola.");
      return;
    }
    setLoading(true);
    try {
      const r = await fetch(`${baseUrl()}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const d = await r.json();
      if (r.status === 403 && d.code === "ip_not_whitelisted") {
        throw new Error(
          `IP-ul ${d.client_ip || "dvs."} nu este în whitelist. Contactați administratorul.`
        );
      }
      if (!r.ok) throw new Error(d.error || t("login.loginFailed"));
      if (d.requires_2fa) {
        setStep2fa({
          challenge_token: d.challenge_token,
          method: d.method,
          message: d.message,
        });
        setOtpCode("");
        return;
      }
      handleLoginSuccess(d.access_token, d.user);
    } catch (err) {
      setError(err.message || t("login.loginFailed"));
    } finally {
      setLoading(false);
    }
  };

  const handleResend2fa = async () => {
    if (!password.trim()) {
      setError("Introduceți parola pentru retrimitere.");
      return;
    }
    setResending(true);
    setError("");
    try {
      const r = await fetch(`${baseUrl()}/api/auth/resend-2fa`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || t("login.resendFailed"));
      setStep2fa({
        challenge_token: d.challenge_token,
        method: d.method,
        message: d.message,
      });
      setOtpCode("");
    } catch (err) {
      setError(err.message || t("login.resendFailed"));
    } finally {
      setResending(false);
    }
  };

  const handleVerify2fa = async (e) => {
    e.preventDefault();
    if (!otpCode.trim()) {
      setError("Introduceți codul 2FA.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const r = await fetch(`${baseUrl()}/api/auth/verify-2fa`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge_token: step2fa.challenge_token,
          method: step2fa.method,
          code: otpCode.trim(),
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Cod 2FA invalid");
      handleLoginSuccess(d.access_token, d.user);
    } catch (err) {
      setError(err.message || "Cod 2FA invalid");
    } finally {
      setLoading(false);
    }
  };

  const handleLegacySubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!legacyToken.trim()) {
      setError("Introduceți token-ul API.");
      return;
    }
    setLoading(true);
    try {
      const r = await fetch(`${baseUrl()}/api/servers`, {
        headers: { Authorization: `Bearer ${legacyToken.trim()}` },
      });
      if (r.status === 403) {
        const d = await r.json().catch(() => ({}));
        if (d.code === "ip_not_whitelisted") {
          throw new Error(`IP-ul ${d.client_ip || "dvs."} nu este în whitelist.`);
        }
      }
      if (!r.ok) throw new Error("Token invalid sau server indisponibil");
      localStorage.setItem("neohost_token", legacyToken.trim());
      localStorage.setItem("neohost_api_url", baseUrl());
      onLogin(legacyToken.trim(), baseUrl());
    } catch (err) {
      setError(err.message || t("login.loginFailed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <button
        type="button"
        className="login-theme-toggle icon-btn"
        onClick={toggleTheme}
        title={theme === "dark" ? t("layout.themeLight") : t("layout.themeDark")}
      >
        <Icon name={theme === "dark" ? "sun" : "moon"} size={16} />
      </button>
      <div className="login-card">
        <div className="login-logo login-logo-brand">
          <PanelBrand branding={branding} iconSize={26} className="login-brand" />
        </div>
        <h1>{t("login.title")}</h1>
        <p className="subtitle">
          {t("login.subtitle", { name: branding.panel_name || "NeoHost" })}
        </p>
        {error && <div className="login-error">{error}</div>}

        {!useLegacy && !step2fa && (
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>{t("login.apiUrl")}</label>
              <input
                className="form-input"
                type="url"
                placeholder="https://security.domeniu.md"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label>{t("login.username")}</label>
              <input
                className="form-input"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
              />
            </div>
            <div className="form-group">
              <label>{t("login.password")}</label>
              <PasswordInput
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("login.passwordPlaceholder")}
              />
            </div>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? t("login.submitting") : t("login.submit")}
            </button>
          </form>
        )}

        {step2fa && (
          <form onSubmit={handleVerify2fa}>
            <p className="text-sm text-muted-foreground mb-4">
              {step2fa.message}
              {step2fa.method === "telegram" && t("login.2faTelegramHint")}
              {step2fa.method === "totp" && t("login.2faTotpHint")}
            </p>
            <div className="form-group">
              <label>{t("login.otp")}</label>
              <input
                className="form-input mono text-center tracking-widest"
                type="text"
                inputMode="numeric"
                maxLength={8}
                placeholder="000000"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\s/g, ""))}
                autoFocus
              />
            </div>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? t("login.submitting") : t("login.confirm")}
            </button>
            {step2fa.method === "telegram" && (
              <button
                type="button"
                className="btn btn-sm w-full mt-2"
                disabled={resending || loading}
                onClick={handleResend2fa}
              >
                {resending ? t("login.resending") : t("login.resend2fa")}
              </button>
            )}
            <button
              type="button"
              className="btn btn-sm w-full mt-2"
              onClick={() => { setStep2fa(null); setOtpCode(""); setError(""); }}
            >
              {t("login.back")}
            </button>
          </form>
        )}

        {useLegacy && (
          <form onSubmit={handleLegacySubmit}>
            <div className="form-group">
              <label>{t("login.legacyToken")}</label>
              <PasswordInput
                value={legacyToken}
                onChange={(e) => setLegacyToken(e.target.value)}
                placeholder="Token API"
              />
            </div>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? t("login.submitting") : t("login.legacyLogin")}
            </button>
            <button type="button" className="btn btn-sm w-full mt-2" onClick={() => setUseLegacy(false)}>
              {t("login.useNormal")}
            </button>
          </form>
        )}

        {!step2fa && (
          <button
            type="button"
            className="text-xs text-muted-foreground hover:text-purple-400 mt-4 w-full text-center"
            onClick={() => { setUseLegacy((v) => !v); setError(""); }}
          >
            {useLegacy ? t("login.usePassword") : t("login.advancedToken")}
          </button>
        )}

        <p className="login-hint">
          Implicit: utilizator <code>admin</code> — schimbați parola din Profil după prima conectare.
        </p>
      </div>
    </div>
  );
}
