function asDate(v) {
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function computeThreatLevel(banTimes) {
  const now = Date.now();
  const hour = 3600 * 1000;
  const minute = 60 * 1000;
  const bansHr = banTimes.filter((t) => {
    const d = asDate(t);
    return d && now - d.getTime() < hour;
  }).length;
  const lastMin = banTimes.filter((t) => {
    const d = asDate(t);
    return d && now - d.getTime() < minute;
  }).length;

  if (bansHr === 0) return { level: "LOW", bans_hr: 0, bans_last_min: 0, recommendation: "Trafic normal. Nicio acțiune necesară." };
  if (bansHr < 10) return { level: "LOW", bans_hr: bansHr, bans_last_min: lastMin, recommendation: "Activitate normală de scanare. Monitorizare standard." };
  if (bansHr < 50) return { level: "MEDIUM", bans_hr: bansHr, bans_last_min: lastMin, recommendation: "Activitate suspectă detectată. Verificați jailurile active." };
  if (bansHr < 200) return { level: "HIGH", bans_hr: bansHr, bans_last_min: lastMin, recommendation: "Atac în desfășurare! Considerați blocarea /24 sau CSF." };
  return { level: "CRITICAL", bans_hr: bansHr, bans_last_min: lastMin, recommendation: "Atac DDoS masiv! Activați modul CSFDENY sau contactați datacenter." };
}

export function computeTopAttackers(bans, limit = 10) {
  const m = new Map();
  for (const b of bans) {
    const key = b.ip;
    if (!m.has(key)) m.set(key, { count: 0, jails: new Set(), country: "", country_code: "", isp: "" });
    const e = m.get(key);
    e.count += 1;
    e.jails.add(b.jail);
    if (b.country) {
      e.country = b.country;
      e.country_code = b.country_code || "";
      e.isp = b.isp || "";
    }
  }
  return [...m.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, limit).map(([ip, d]) => ({
    ip,
    count: d.count,
    jails: [...d.jails],
    country: d.country,
    country_code: d.country_code,
    isp: d.isp
  }));
}

export function computeJailStats(bans) {
  const m = new Map();
  for (const b of bans) m.set(b.jail, (m.get(b.jail) || 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([jail, count]) => ({ jail, count }));
}

export function computeCountryStats(bans) {
  const m = new Map();
  for (const b of bans) {
    const code = b.country_code || "XX";
    if (!m.has(code)) m.set(code, { count: 0, country: "", lat: 0, lon: 0, ip: new Map(), jail: new Map(), isp: new Map() });
    const e = m.get(code);
    e.count += 1;
    e.country = b.country || e.country;
    if (b.lat) {
      e.lat = b.lat;
      e.lon = b.lon;
    }
    if (b.ip) e.ip.set(b.ip, (e.ip.get(b.ip) || 0) + 1);
    if (b.jail) e.jail.set(b.jail, (e.jail.get(b.jail) || 0) + 1);
    if (b.isp) e.isp.set(b.isp, (e.isp.get(b.isp) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1].count - a[1].count).map(([code, d]) => ({
    code,
    country: d.country,
    count: d.count,
    lat: d.lat,
    lon: d.lon,
    unique_ips: d.ip.size,
    ips: [...d.ip.entries()].sort((a, b) => b[1] - a[1]).slice(0, 30).map(([ip, count]) => ({ ip, count })),
    jails: [...d.jail.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count })),
    isps: [...d.isp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count }))
  }));
}

export function computeBanTimeline(bans) {
  const now = new Date();
  const buckets = new Map();
  for (const b of bans) {
    const d = asDate(b.ts);
    if (!d) continue;
    if (now.getTime() - d.getTime() <= 24 * 3600 * 1000) {
      const h = `${String(d.getHours()).padStart(2, "0")}:00`;
      buckets.set(h, (buckets.get(h) || 0) + 1);
    }
  }
  const out = [];
  for (let i = 23; i >= 0; i -= 1) {
    const t = new Date(now.getTime() - i * 3600 * 1000);
    const h = `${String(t.getHours()).padStart(2, "0")}:00`;
    out.push({ hour: h, count: buckets.get(h) || 0 });
  }
  return out;
}
