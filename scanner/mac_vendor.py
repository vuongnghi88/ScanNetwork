"""
MAC Vendor Lookup Module
Supports offline OUI lookup + online API fallback.
"""
import json
import os
import re
import requests
from config import Config

# In-memory cache: mac_prefix -> vendor name
_vendor_cache: dict[str, str] = {}
_oui_db: dict[str, str] = {}
_db_loaded = False


def _load_oui_db():
    global _oui_db, _db_loaded
    if _db_loaded:
        return
    if os.path.exists(Config.MAC_VENDOR_DB):
        try:
            with open(Config.MAC_VENDOR_DB, "r", encoding="utf-8") as f:
                _oui_db = json.load(f)
        except Exception:
            _oui_db = {}
    _db_loaded = True


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to uppercase colon-separated, return first 3 octets."""
    mac = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(mac) < 6:
        return ""
    return f"{mac[0:2]}:{mac[2:4]}:{mac[4:6]}"


def lookup(mac: str) -> str:
    """Return vendor name for a MAC address. Returns 'Unknown' if not found."""
    if not mac or mac in ("", "00:00:00:00:00:00"):
        return "Unknown"

    prefix = _normalize_mac(mac)
    if not prefix:
        return "Unknown"

    # Check in-memory cache first
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]

    # Check offline OUI database
    _load_oui_db()
    if prefix in _oui_db:
        vendor = _oui_db[prefix]
        _vendor_cache[prefix] = vendor
        return vendor

    # Fallback: online API (rate-limited, best-effort)
    try:
        resp = requests.get(
            f"https://api.macvendors.com/{prefix}",
            timeout=3
        )
        if resp.status_code == 200:
            vendor = resp.text.strip()
            _vendor_cache[prefix] = vendor
            # Persist to the OUI db file
            _oui_db[prefix] = vendor
            _save_oui_entry(prefix, vendor)
            return vendor
    except Exception:
        pass

    _vendor_cache[prefix] = "Unknown"
    return "Unknown"


def _save_oui_entry(prefix: str, vendor: str):
    """Append a new OUI entry to the local JSON file."""
    try:
        db = {}
        if os.path.exists(Config.MAC_VENDOR_DB):
            with open(Config.MAC_VENDOR_DB, "r", encoding="utf-8") as f:
                db = json.load(f)
        db[prefix] = vendor
        with open(Config.MAC_VENDOR_DB, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=None, separators=(",", ":"))
    except Exception:
        pass


def build_starter_db():
    """Build a starter OUI database with the most common vendors."""
    starter = {
        # Cameras
        "EC:71:DB": "Hikvision",
        "C8:02:8F": "Hikvision",
        "68:BD:AB": "Hikvision",
        "28:57:BE": "Hikvision",
        "BC:AD:28": "Hikvision",
        "00:26:B9": "Dahua Technology",
        "3C:EF:8C": "Dahua Technology",
        "A0:AC:22": "Dahua Technology",
        "E0:50:8B": "Hanwha (Samsung Techwin)",
        # Network gear
        "00:1A:A1": "Cisco Systems",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:25:90": "Cisco Systems",
        "00:1B:2A": "Cisco Systems",
        "B4:FB:E4": "Cisco Systems",
        "70:DB:98": "Cisco Systems",
        "E8:BA:70": "Cisco Systems",
        "CC:46:D6": "Cisco Systems",
        "58:97:BD": "Juniper Networks",
        "00:05:85": "Juniper Networks",
        "00:22:83": "MikroTik",
        "4C:5E:0C": "MikroTik",
        "DC:2C:6E": "MikroTik",
        "2C:C8:1B": "MikroTik",
        # Smart TVs / Media
        "50:A4:D0": "Google (Chromecast)",
        "F4:F5:D8": "Google",
        "54:60:09": "Google",
        "94:EB:2C": "Google",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Foundation",
        "78:BD:BC": "Samsung Electronics",
        "50:85:69": "Samsung Electronics",
        "D0:22:BE": "Samsung Electronics",
        "34:03:DE": "Samsung Electronics",
        # Printers / IoT
        "00:00:44": "Cisco Systems",
        "08:00:20": "Oracle/Sun",
        "00:80:77": "Brother Industries",
        "00:1B:A9": "Brother Industries",
        "00:0E:4B": "HP",
        "3C:D9:2B": "HP",
        "98:E7:F4": "HP",
        # Apple
        "AC:DE:48": "Apple",
        "A4:C3:F0": "Apple",
        "98:01:A7": "Apple",
        # Windows/Dell/Lenovo
        "00:14:22": "Dell",
        "B8:AC:6F": "Dell",
        "08:9E:01": "Dell",
        "8C:EC:4B": "Lenovo",
        "54:EE:75": "Lenovo",
    }
    os.makedirs(os.path.dirname(Config.MAC_VENDOR_DB), exist_ok=True)
    with open(Config.MAC_VENDOR_DB, "w", encoding="utf-8") as f:
        json.dump(starter, f, ensure_ascii=False, indent=None, separators=(",", ":"))
    global _oui_db, _db_loaded
    _oui_db = starter
    _db_loaded = True
