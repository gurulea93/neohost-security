import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import ro from "./locales/ro.json";
import en from "./locales/en.json";
import ru from "./locales/ru.json";

const PACKS = { ro, en, ru };
const STORAGE_KEY = "neohost_lang";

function deepGet(obj, path) {
  return path.split(".").reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), obj);
}

function interpolate(str, vars) {
  if (!vars || typeof str !== "string") return str;
  return str.replace(/\{\{(\w+)\}\}/g, (_, k) => (vars[k] !== undefined ? String(vars[k]) : ""));
}

const LanguageContext = createContext({
  lang: "ro",
  setLang: () => {},
  t: (k) => k,
});

export function LanguageProvider({ children }) {
  const [lang, setLangState] = useState(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    return PACKS[saved] ? saved : "ro";
  });

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, lang);
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = useCallback((l) => {
    if (PACKS[l]) setLangState(l);
  }, []);

  const t = useCallback(
    (key, vars) => {
      const val = deepGet(PACKS[lang], key) ?? deepGet(PACKS.ro, key);
      if (val === undefined) return key;
      return interpolate(val, vars);
    },
    [lang],
  );

  const value = useMemo(
    () => ({ lang, setLang, t, languages: Object.keys(PACKS) }),
    [lang, setLang, t],
  );

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useI18n() {
  return useContext(LanguageContext);
}
