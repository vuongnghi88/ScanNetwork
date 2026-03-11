"""
Nmap Scanner Module
Wraps python-nmap and subprocess to provide structured scan results.
Includes input validation to prevent Command Injection.
"""
import re
import nmap
import platform
import subprocess
from datetime import datetime
from config import Config
from scanner import mac_vendor, fingerprint
from database import get_db


# ── Input Validation ──────────────────────────────────────────────────────────

def expand_wildcard(target: str) -> str:
    """
    Convert wildcard notation to Nmap-compatible format.
      192.168.1.*    → 192.168.1.0/24  (single octet wildcard)
      192.168.*.*    → 192.168.0.0/16  (two octet wildcard)
      192.*.*.*      → 192.0.0.0/8     (three octet wildcard)
    Non-wildcard targets (CIDR, ranges, plain IPs) are returned unchanged.
    Multiple targets separated by commas/spaces are each expanded individually.
    """
    def _expand_one(t: str) -> str:
        t = t.strip()
        if '*' not in t:
            return t
        parts = t.split('.')
        if len(parts) != 4:
            return t  # malformed, leave as-is
        # Count trailing wildcards
        wildcard_count = sum(1 for p in parts if p == '*')
        # Replace wildcards with 0 and compute CIDR prefix
        prefix_bits = (4 - wildcard_count) * 8
        fixed_parts = [p if p != '*' else '0' for p in parts]
        return f"{'.'.join(fixed_parts)}/{prefix_bits}"

    # Support comma or space separated list of targets
    separators = re.split(r'[,\s]+', target.strip())
    expanded = [_expand_one(t) for t in separators if t]
    return ' '.join(expanded)


_VALID_TARGET_RE = re.compile(
    r'^[\d./,\s\-a-zA-Z:*_]+$'  # allow IP, CIDR, ranges, hostnames, wildcard *, and underscore
)
_DANGEROUS_RE = re.compile(r'[;&|$<>!`\'\"\\]')


def validate_target(target: str) -> tuple[bool, str]:
    """Return (is_valid, error_message)."""
    t = target.strip()
    if not t:
        return False, "Target cannot be empty."
    if len(t) > 200:
        return False, "Target string too long."
    if _DANGEROUS_RE.search(t):
        return False, "Invalid characters detected in target."
    if not _VALID_TARGET_RE.match(t):
        return False, "Target contains invalid characters."
    return True, ""


# ── Nmap Scanner Class ────────────────────────────────────────────────────────

class NmapScanner:
    def __init__(self):
        # Lazy init — do NOT call nmap.PortScanner() here.
        # That would crash Flask startup if Nmap binary is missing.
        pass

    def _get_nm(self):
        """Create a new PortScanner instance; raises clear error if Nmap is missing."""
        try:
            # Explicitly tell python-nmap where to look for the binary
            return nmap.PortScanner(nmap_search_path=(Config.NMAP_PATH, "nmap"))
        except (nmap.PortScannerError, Exception) as e:
            raise RuntimeError(
                f"Nmap error: {e}. "
                "Please ensure Nmap is installed and added to PATH, or check config.py. "
                f"(Attempted path: {Config.NMAP_PATH})"
            )

    def host_discovery(self, target: str, callback=None) -> list[dict]:
        """
        Fast ping scan (-sn). Returns list of alive hosts with MAC + vendor.
        """
        nm = self._get_nm()
        target = expand_wildcard(target)
        args = f"-sn {Config.SCAN_TIMING}"
        try:
            nm.scan(hosts=target, arguments=args)
        except Exception as e:
            raise RuntimeError(f"Nmap host discovery failed: {e}")

        hosts = []
        all_hosts = nm.all_hosts()
        for i, ip in enumerate(all_hosts):
            host = nm[ip]
            mac = ""
            vendor_name = "Unknown"

            if "addresses" in host:
                mac = host["addresses"].get("mac", "")
            if "vendor" in host and mac:
                vendor_name = list(host["vendor"].values())[0] if host["vendor"] else "Unknown"
            if (not vendor_name or vendor_name == "Unknown") and mac:
                vendor_name = mac_vendor.lookup(mac)

            hostname = ""
            if host.hostnames():
                hostname = host.hostnames()[0].get("name", "")

            status = host.state()
            entry = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor_name,
                "status": status,
                "device_type": "Unknown Device",
                "icon": "❓",
                "risk": "unknown",
                "os_info": "",
                "ports": [],
            }

            if callback:
                callback(entry, i + 1, len(all_hosts))
            hosts.append(entry)

        return hosts

    def port_scan(self, target: str, ports: str = None,
                  service_version: bool = True,
                  os_detect: bool = False,
                  callback=None) -> list[dict]:
        """
        Full scan: host discovery + port scan + optional OS detect.
        """
        nm = self._get_nm()
        ports_arg = ports or Config.COMMON_PORTS
        args = f"{Config.SCAN_TIMING} -p {ports_arg}"
        if service_version:
            args += " -sV"
        if os_detect:
            args += " -O"

        target = expand_wildcard(target)
        try:
            nm.scan(hosts=target, arguments=args)
        except Exception as e:
            raise RuntimeError(f"Nmap port scan failed: {e}")

        hosts = []
        all_hosts = nm.all_hosts()
        for i, ip in enumerate(all_hosts):
            host = nm[ip]
            if host.state() != "up":
                continue

            mac = host["addresses"].get("mac", "")
            vendor_name = "Unknown"
            if "vendor" in host and mac and host["vendor"]:
                vendor_name = list(host["vendor"].values())[0]
            if (not vendor_name or vendor_name == "Unknown") and mac:
                vendor_name = mac_vendor.lookup(mac)

            hostname = ""
            if host.hostnames():
                hostname = host.hostnames()[0].get("name", "")

            # OS detection
            os_info = ""
            if os_detect and "osmatch" in host and host["osmatch"]:
                top_match = host["osmatch"][0]
                os_info = f"{top_match['name']} ({top_match['accuracy']}%)"

            # Ports
            open_ports_list = []
            port_details = []
            if "tcp" in host:
                for port_num, port_data in host["tcp"].items():
                    if port_data["state"] == "open":
                        open_ports_list.append(port_num)
                        port_details.append({
                            "port": port_num,
                            "protocol": "tcp",
                            "state": port_data["state"],
                            "service": port_data.get("name", ""),
                            "version": (
                                f"{port_data.get('product','')} "
                                f"{port_data.get('version','')} "
                                f"{port_data.get('extrainfo','')}".strip()
                            ),
                        })
            if "udp" in host:
                for port_num, port_data in host["udp"].items():
                    if port_data["state"] in ("open", "open|filtered"):
                        open_ports_list.append(port_num)
                        port_details.append({
                            "port": port_num,
                            "protocol": "udp",
                            "state": port_data["state"],
                            "service": port_data.get("name", ""),
                            "version": "",
                        })

            # Fingerprint
            fp = fingerprint.fingerprint(vendor_name, open_ports_list, os_info)

            entry = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor_name,
                "status": "up",
                "device_type": fp["device_type"],
                "icon": fp["icon"],
                "risk": fp["risk"],
                "os_info": os_info,
                "ports": port_details,
            }

            if callback:
                callback(entry, i + 1, len(all_hosts))
            hosts.append(entry)

        return hosts

    def live_scan(self, target: str, arguments: str, set_process_cb=None):
        """
        Execute nmap via subprocess.Popen with grepable output (-oG -).
        Yields host result dicts as they are parsed.
        """
        full_target = expand_wildcard(target)
        nmap_bin = Config.NMAP_PATH if Config.NMAP_PATH else "nmap"
        
        # Build command: [bin, -oG, -, args..., targets...]
        cmd = [nmap_bin, "-oG", "-"] + arguments.split() + full_target.split()
        
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                startupinfo=startupinfo
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start Nmap: {e}")

        if set_process_cb:
            set_process_cb(proc)

        for line in proc.stdout:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "Host:" in line and ("Status: Up" in line or "Ports:" in line):
                res = self._parse_grepable_line(line)
                if res:
                    yield res

        proc.wait()

    def _parse_grepable_line(self, line: str) -> dict:
        """
        Parse a single line of Nmap grepable output.
        Example: Host: 192.168.1.1 (myhost)	Status: Up
        Example: Host: 192.168.1.1 (myhost)	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
        """
        # Host: 192.168.1.1 (hostname)	Ports: ...
        match = re.search(r"Host: ([\d.]+) \((.*?)\)\t(.*)", line)
        if not match:
            return None
        
        ip = match.group(1)
        hostname = match.group(2)
        rest = match.group(3)
        
        entry = {
            "ip": ip,
            "hostname": hostname,
            "mac": "",
            "vendor": "Unknown",
            "status": "up",
            "os_info": "",
            "ports": [],
            "device_type": "Unknown Device",
            "icon": "❓",
            "risk": "unknown"
        }

        # Status: Up / Down
        if "Status: " in rest:
            s_match = re.search(r"Status: (\w+)", rest)
            if s_match:
                entry["status"] = s_match.group(1).lower()

        # Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
        if "Ports: " in rest:
            p_match = re.search(r"Ports: (.*)", rest)
            if p_match:
                port_str = p_match.group(1).split("\t")[0] # Stop before next field
                for p_item in port_str.split(", "):
                    parts = p_item.split("/")
                    if len(parts) >= 7 and parts[1] == "open":
                        entry["ports"].append({
                            "port": int(parts[0]),
                            "protocol": parts[2],
                            "state": parts[1],
                            "service": parts[4],
                            "version": f"{parts[5]} {parts[6]}".strip()
                        })

        # Note: -oG doesn't include MAC or OS info by default for some reason?
        # Actually it does if run as root/admin, but let's be safe.
        # We might need to run another quick scan for MAC if missing, but for now we focus on "Stop".
        
        # Enrichment (Vendor/Fingerprint)
        # We can still do this per-host here
        fp = fingerprint.fingerprint(entry["vendor"], [p["port"] for p in entry["ports"]], entry["os_info"])
        entry["device_type"] = fp["device_type"]
        entry["icon"] = fp["icon"]
        entry["risk"] = fp["risk"]

        return entry


# Lazy singleton — created once, no Nmap required at import time
_scanner_instance = None

def get_scanner() -> NmapScanner:
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = NmapScanner()
    return _scanner_instance

# Convenience alias used by task_manager
scanner = None  # will be replaced by get_scanner() on first use
