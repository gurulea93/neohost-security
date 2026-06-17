import dns from "node:dns/promises";

const ipGeoCache = new Map();

function isIp(host) {
  const h = String(host || "").trim();
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || (h.includes(":") && /^[0-9a-f:.]+$/i.test(h));
}

export async function lookupIpGeo(ip) {
  const key = String(ip || "").trim();
  if (!key) return null;
  if (ipGeoCache.has(key)) return ipGeoCache.get(key);

  try {
    const url = `http://ip-api.com/json/${encodeURIComponent(key)}?fields=status,country,countryCode,regionName,city,isp,lat,lon`;
    const data = await (await fetch(url, { signal: AbortSignal.timeout(4000) })).json();
    if (data.status === "success") {
      const geo = {
        country: data.country || "Unknown",
        country_code: data.countryCode || "",
        region: data.regionName || "",
        city: data.city || "",
        isp: data.isp || "",
        lat: data.lat ?? null,
        lon: data.lon ?? null
      };
      ipGeoCache.set(key, geo);
      return geo;
    }
  } catch {
    // ignore
  }
  ipGeoCache.set(key, null);
  return null;
}

export async function hostToIp(host) {
  const h = String(host || "").trim();
  if (!h) return "";
  if (isIp(h)) return h;
  try {
    const { address } = await dns.lookup(h, { family: 4 });
    return address || "";
  } catch {
    return "";
  }
}

export async function resolveServerLocation({ hostname = "", latitude = null, longitude = null, location_label = "", ip = "" } = {}) {
  const lat = latitude != null && latitude !== "" ? Number(latitude) : null;
  const lon = longitude != null && longitude !== "" ? Number(longitude) : null;
  if (lat != null && lon != null && !Number.isNaN(lat) && !Number.isNaN(lon)) {
    return { latitude: lat, longitude: lon, location_label: String(location_label || "").trim() };
  }

  const ipTarget = String(ip || "").trim() || await hostToIp(hostname);
  if (!ipTarget) {
    return { latitude: null, longitude: null, location_label: String(location_label || "").trim() };
  }

  const geo = await lookupIpGeo(ipTarget);
  if (!geo?.lat && geo?.lat !== 0) {
    return { latitude: null, longitude: null, location_label: String(location_label || "").trim() };
  }

  const label = String(location_label || "").trim()
    || [geo.city, geo.country_code || geo.country].filter(Boolean).join(", ");

  return {
    latitude: geo.lat,
    longitude: geo.lon,
    location_label: label.slice(0, 128)
  };
}
