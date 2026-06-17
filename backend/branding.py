"""Branding panou — denumire, logo, favicon, accent, istoric."""

import base64
import json
import re

from models import BrandingHistory, utcnow
from security import get_setting, set_setting

LOGO_MODES = frozenset({"text", "logo", "both"})
ACCENT_PRESETS = {
    "purple": "#9333ea",
    "blue": "#3758F9",
    "green": "#22AD5C",
    "orange": "#f97316",
    "red": "#ef4444",
    "cyan": "#06b6d4",
    "pink": "#ec4899",
}
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
IMAGE_DATA_RE = re.compile(
    r"^data:image/(png|jpeg|jpg|gif|webp|x-icon|vnd\.microsoft\.icon|svg\+xml);base64,",
    re.I,
)
MAX_IMAGE_BYTES = 350_000

KEYS = {
    "panel_name": "NeoHost",
    "panel_tagline": "Security Monitor",
    "logo_mode": "both",
    "logo_data": "",
    "favicon_data": "",
    "accent_color": "#9333ea",
    "accent_preset": "purple",
}


def _validate_image_data(value, label):
    if not value:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{label} invalid")
    if not IMAGE_DATA_RE.match(value):
        raise ValueError(f"{label}: format imagine neacceptat (PNG, JPG, GIF, WebP, ICO, SVG)")
    try:
        raw = base64.b64decode(value.split(",", 1)[1], validate=True)
    except Exception as exc:
        raise ValueError(f"{label}: date corupte") from exc
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError(f"{label}: maxim {MAX_IMAGE_BYTES // 1024} KB")
    return value


def _resolve_accent(db):
    preset = get_setting(db, "branding_accent_preset", KEYS["accent_preset"])
    custom = get_setting(db, "branding_accent_color", "")
    if custom and HEX_RE.match(custom):
        return custom, preset if preset in ACCENT_PRESETS else "custom"
    if preset in ACCENT_PRESETS:
        return ACCENT_PRESETS[preset], preset
    return KEYS["accent_color"], "purple"


def _snapshot_for_history(branding):
    snap = dict(branding)
    snap["has_logo"] = bool(branding.get("logo_data"))
    snap["has_favicon"] = bool(branding.get("favicon_data"))
    snap.pop("logo_data", None)
    snap.pop("favicon_data", None)
    return snap


def get_branding(db):
    logo_mode = get_setting(db, "branding_logo_mode", KEYS["logo_mode"])
    if logo_mode not in LOGO_MODES:
        logo_mode = KEYS["logo_mode"]
    accent, preset = _resolve_accent(db)
    return {
        "panel_name": get_setting(db, "branding_panel_name", KEYS["panel_name"]) or KEYS["panel_name"],
        "panel_tagline": get_setting(db, "branding_panel_tagline", KEYS["panel_tagline"]) or KEYS["panel_tagline"],
        "logo_mode": logo_mode,
        "logo_data": get_setting(db, "branding_logo_data", ""),
        "favicon_data": get_setting(db, "branding_favicon_data", ""),
        "accent_color": accent,
        "accent_preset": preset,
        "accent_presets": ACCENT_PRESETS,
    }


def _history_value(key, val):
    if key in ("logo_data", "favicon_data"):
        return "uploaded" if val else "cleared"
    return val


def _record_history(db, user, before, after, changed_fields):
    if not changed_fields:
        return
    row = BrandingHistory(
        user_id=user.id if user else None,
        username=user.username if user else "system",
        changes=json.dumps({
            k: {"from": _history_value(k, before.get(k)), "to": _history_value(k, after.get(k))}
            for k in changed_fields
        }),
        snapshot=json.dumps(_snapshot_for_history(after)),
        created_at=utcnow(),
    )
    db.add(row)
    db.commit()


def list_branding_history(db, limit=50):
    rows = (
        db.query(BrandingHistory)
        .order_by(BrandingHistory.created_at.desc())
        .limit(min(limit, 100))
        .all()
    )
    return [r.to_dict() for r in rows]


def update_branding(db, data, user=None):
    before = get_branding(db)
    out = dict(before)
    changed = []

    if "panel_name" in data:
        name = (data.get("panel_name") or "").strip()
        if not name or len(name) > 80:
            raise ValueError("Denumirea panoului trebuie să aibă 1–80 caractere")
        set_setting(db, "branding_panel_name", name)
        out["panel_name"] = name
        changed.append("panel_name")
    if "panel_tagline" in data:
        tag = (data.get("panel_tagline") or "").strip()
        if len(tag) > 120:
            raise ValueError("Subtitlul poate avea maxim 120 caractere")
        set_setting(db, "branding_panel_tagline", tag)
        out["panel_tagline"] = tag
        changed.append("panel_tagline")
    if "logo_mode" in data:
        mode = (data.get("logo_mode") or "").strip()
        if mode not in LOGO_MODES:
            raise ValueError("Mod logo invalid (text, logo, both)")
        set_setting(db, "branding_logo_mode", mode)
        out["logo_mode"] = mode
        changed.append("logo_mode")
    if "logo_data" in data:
        val = data.get("logo_data")
        if val is None:
            val = ""
        logo = _validate_image_data(val, "Logo")
        set_setting(db, "branding_logo_data", logo)
        out["logo_data"] = logo
        changed.append("logo_data")
    if "favicon_data" in data:
        val = data.get("favicon_data")
        if val is None:
            val = ""
        fav = _validate_image_data(val, "Favicon")
        set_setting(db, "branding_favicon_data", fav)
        out["favicon_data"] = fav
        changed.append("favicon_data")
    if "clear_logo" in data and data["clear_logo"]:
        set_setting(db, "branding_logo_data", "")
        out["logo_data"] = ""
        changed.append("logo_data")
    if "clear_favicon" in data and data["clear_favicon"]:
        set_setting(db, "branding_favicon_data", "")
        out["favicon_data"] = ""
        changed.append("favicon_data")
    if "accent_preset" in data:
        preset = (data.get("accent_preset") or "").strip()
        if preset not in ACCENT_PRESETS and preset != "custom":
            raise ValueError("Preset accent invalid")
        set_setting(db, "branding_accent_preset", preset)
        if preset in ACCENT_PRESETS:
            set_setting(db, "branding_accent_color", ACCENT_PRESETS[preset])
            out["accent_color"] = ACCENT_PRESETS[preset]
        out["accent_preset"] = preset
        changed.append("accent_color")
    if "accent_color" in data:
        color = (data.get("accent_color") or "").strip()
        if color and not HEX_RE.match(color):
            raise ValueError("Culoare accent invalidă (#RRGGBB)")
        if color:
            set_setting(db, "branding_accent_color", color)
            set_setting(db, "branding_accent_preset", "custom")
            out["accent_color"] = color
            out["accent_preset"] = "custom"
            changed.append("accent_color")

    if changed:
        hist_before = _snapshot_for_history(before)
        hist_after = _snapshot_for_history(out)
        _record_history(
            db, user, hist_before, hist_after,
            list(dict.fromkeys(changed)),
        )
    return out
