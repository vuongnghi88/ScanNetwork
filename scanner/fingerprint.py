"""
Device Fingerprinting Rules
Assigns device_type, icon, and risk level based on vendor + open ports + OS.
"""

# ── Rule sets ──────────────────────────────────────────────────────────────────

# (keyword_in_vendor, device_type, icon, risk)
VENDOR_RULES: list[tuple] = [
    ("hikvision",       "IP Camera",        "📷", "high"),
    ("dahua",           "IP Camera",        "📷", "high"),
    ("hanwha",          "IP Camera",        "📷", "high"),
    ("samsung techwin", "IP Camera",        "📷", "high"),
    ("axis",            "IP Camera",        "📷", "high"),
    ("uniview",         "IP Camera",        "📷", "high"),
    ("cisco",           "Network Device",   "🔌", "high"),
    ("juniper",         "Network Device",   "🔌", "high"),
    ("mikrotik",        "Network Device",   "🔌", "high"),
    ("ubiquiti",        "Network Device",   "🔌", "high"),
    ("raspberry pi",    "IoT Device",       "🍓", "medium"),
    ("google",          "Smart Device",     "📺", "low"),
    ("chromecast",      "Smart TV",         "📺", "low"),
    ("apple",           "Apple Device",     "🍎", "low"),
    ("samsung",         "Smart Device",     "📱", "low"),
    ("dell",            "Workstation",      "💻", "medium"),
    ("lenovo",          "Workstation",      "💻", "medium"),
    ("hp",              "Workstation/Printer","🖨️","medium"),
    ("brother",         "Printer",          "🖨️", "medium"),
    ("vmware",          "Virtual Machine",  "☁️", "medium"),
    ("oracle",          "Server",           "🗄️", "high"),
]

# (port, device_type, icon, risk)   — checked if no vendor rule matched first
PORT_RULES: list[tuple] = [
    (554,   "IP Camera (RTSP)",      "📷", "high"),
    (8554,  "IP Camera (RTSP)",      "📷", "high"),
    (37777, "Dahua Camera",          "📷", "high"),
    (34567, "Dahua DVR/NVR",         "📷", "high"),
    (8000,  "Hikvision Camera",      "📷", "high"),
    (8008,  "Smart TV",              "📺", "low"),
    (8009,  "Chromecast",            "📺", "low"),
    (3389,  "Windows PC (RDP)",      "💻", "critical"),
    (5900,  "Remote Desktop (VNC)",  "💻", "critical"),
    (22,    "Linux Server (SSH)",    "🖥️", "high"),
    (23,    "Telnet Device",         "⚠️", "critical"),
    (3306,  "MySQL Database",        "🗄️", "critical"),
    (5432,  "PostgreSQL Database",   "🗄️", "critical"),
    (1433,  "MSSQL Database",        "🗄️", "critical"),
    (27017, "MongoDB",               "🗄️", "critical"),
    (6379,  "Redis Cache",           "🗄️", "critical"),
    (9200,  "Elasticsearch",         "🗄️", "critical"),
    (445,   "Windows File Share (SMB)", "💻","critical"),
    (139,   "NetBIOS",               "💻", "high"),
    (80,    "Web Server",            "🌐", "medium"),
    (443,   "Web Server (HTTPS)",    "🌐", "medium"),
    (8080,  "Web Server (Alt)",      "🌐", "medium"),
    (8443,  "Web Server (HTTPS Alt)","🌐", "medium"),
    (21,    "FTP Server",            "📁", "high"),
    (25,    "Mail Server (SMTP)",    "✉️", "medium"),
    (53,    "DNS Server",            "🔍", "medium"),
    (1521,  "Oracle Database",       "🗄️", "critical"),
    (161,   "SNMP Device",           "🔌", "high"),
    (135,   "Windows RPC",           "💻", "high"),
]

# OS keyword → device type refinement
OS_RULES: list[tuple] = [
    ("windows",  "Windows PC",   "💻", "medium"),
    ("linux",    "Linux Server", "🖥️", "medium"),
    ("ios",      "Apple Mobile", "📱", "low"),
    ("android",  "Android Device","📱","low"),
    ("embedded", "IoT/Embedded", "⚙️", "medium"),
    ("bsd",      "BSD Server",   "🖥️", "medium"),
]

RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def fingerprint(vendor: str, open_ports: list[int], os_info: str) -> dict:
    """
    Given vendor string, list of open ports, and OS info, return:
      { device_type, icon, risk, confidence }
    """
    vendor_l = (vendor or "").lower()
    os_l = (os_info or "").lower()
    results = []

    # Step 1: vendor-based
    for keyword, dtype, icon, risk in VENDOR_RULES:
        if keyword in vendor_l:
            results.append({"device_type": dtype, "icon": icon, "risk": risk,
                             "confidence": "high", "source": "vendor"})
            break

    # Step 2: port-based
    for port, dtype, icon, risk in PORT_RULES:
        if port in open_ports:
            results.append({"device_type": dtype, "icon": icon, "risk": risk,
                             "confidence": "medium", "source": f"port:{port}"})

    # Step 3: OS-based
    for keyword, dtype, icon, risk in OS_RULES:
        if keyword in os_l:
            results.append({"device_type": dtype, "icon": icon, "risk": risk,
                             "confidence": "medium", "source": "os"})
            break

    if not results:
        return {
            "device_type": "Unknown Device",
            "icon": "❓",
            "risk": "unknown",
            "confidence": "low",
        }

    # Choose the result with the highest risk
    best = max(results, key=lambda r: RISK_ORDER.get(r["risk"], 0))
    return best


def get_risk_badge(risk: str) -> str:
    """Return a Bootstrap badge class for a risk level."""
    return {
        "critical": "danger",
        "high":     "warning",
        "medium":   "info",
        "low":      "success",
        "unknown":  "secondary",
    }.get(risk, "secondary")
