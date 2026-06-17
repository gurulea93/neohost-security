import { useState, useEffect } from "react";
import Login from "./Login";
import Dashboard from "./Dashboard";
import { ThemeProvider } from "./context/ThemeContext";
import { BrandingProvider } from "./context/BrandingContext";
import { LanguageProvider } from "./i18n";
import "./berry.css";

export default function App() {
  const [auth, setAuth] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem("neohost_token");
    const apiUrl = localStorage.getItem("neohost_api_url") || import.meta.env.VITE_API_URL || "";
    const username = localStorage.getItem("neohost_username") || "";
    if (token) setAuth({ token, apiUrl, username });
  }, []);

  const handleLogin = (token, apiUrl, username) => setAuth({ token, apiUrl, username });

  const handleLogout = async () => {
    const tok = localStorage.getItem("neohost_token");
    const api = localStorage.getItem("neohost_api_url") || import.meta.env.VITE_API_URL || "";
    try {
      if (tok && api) {
        await fetch(`${api}/api/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${tok}` },
        });
      }
    } catch { /* ignore */ }
    localStorage.removeItem("neohost_token");
    localStorage.removeItem("neohost_username");
    setAuth(null);
  };

  const apiUrl =
    auth?.apiUrl ||
    localStorage.getItem("neohost_api_url") ||
    import.meta.env.VITE_API_URL ||
    "";

  return (
    <ThemeProvider>
      <LanguageProvider>
        <BrandingProvider apiUrl={apiUrl}>
        {!auth ? (
          <Login
            onLogin={handleLogin}
            defaultApiUrl={import.meta.env.VITE_API_URL || ""}
          />
        ) : (
          <Dashboard
            token={auth.token}
            apiUrl={auth.apiUrl}
            onLogout={handleLogout}
          />
        )}
        </BrandingProvider>
      </LanguageProvider>
    </ThemeProvider>
  );
}
