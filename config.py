import os
import platform

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "scannet-dev-secret-2026")
    DATABASE_PATH = os.path.join(DATA_DIR, "scanner.db")
    MAC_VENDOR_DB = os.path.join(DATA_DIR, "mac_vendors.json")
    DEBUG = True
    HOST = "127.0.0.1"
    PORT = 5000
    MAX_CONCURRENT_SCANS = 3
    TIMEZONE = 'Asia/Ho_Chi_Minh'

    # ── Nmap ─────────────────────────────────────────────────────────────────
    NMAP_PATH = "nmap"
    if platform.system() == "Windows":
        _possible_nmap_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"D:\Nmap\nmap.exe",
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Nmap\\nmap.exe"),
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Nmap\\nmap.exe"),
        ]
        for _path in _possible_nmap_paths:
            if os.path.exists(_path):
                NMAP_PATH = _path
                break
    else:
        NMAP_PATH = "nmap"

    # Scan timing: T1=paranoid, T2=sneaky, T3=normal, T4=aggressive
    SCAN_TIMING = "-T3"

    # Ports to scan (common attack surface)
    COMMON_PORTS = (
        "21,22,23,25,53,80,110,135,137,138,139,143,443,445,"
        "554,1433,1521,3306,3389,5432,5900,6379,8008,8009,"
        "8080,8443,8888,9200,27017"
    )

    # ── Network Segment Lists ────────────────────────────────────────────────
    # Chỉnh các dải IP theo hạ tầng thực tế của bạn.
    # Hỗ trợ: CIDR (192.168.1.0/24), wildcard (192.168.1.*),
    #          range (192.168.1.1-50), single IP (192.168.1.1)

    NETWORK_LISTS = {
        "guest": {
            "label": "🏠 Guest Network",
            "description": "Mạng Wi-Fi khách — nơi kẻ tấn công đứng",
            "targets": [
                "192.168.1.*",     # → 192.168.1.1–254
            ],
        },
        "server": {
            "label": "🖥️ Server Network",
            "description": "Dải IP của các máy chủ nội bộ",
            "targets": [
                "10.10.10.0/24",
                "10.10.20.0/24",
            ],
        },
        "local": {
            "label": "🔒 Local / Internal",
            "description": "Dải mạng nội bộ / VLAN admin cần thăm dò",
            "targets": [
                "172.16.0.0/24",
                "192.168.10.*",   # → 192.168.10.1–254
            ],
        },
    }
