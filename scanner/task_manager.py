"""
Background Task Manager
Uses threading + queue to run Nmap scans without blocking Flask.
"""
import threading
import queue
import time
import json
from datetime import datetime
import pytz
from config import Config
from database import get_db

# ── Task state store (in-memory) ──────────────────────────────────────────────
# { task_id: { status, progress, scan_id, error, created_at } }
_tasks: dict[str, dict] = {}
_tasks_lock = threading.Lock()
_cancelled_tasks: set[str] = set()
_cancelled_lock = threading.Lock()

_active_processes: dict[str, object] = {} # task_id -> subprocess.Popen
_processes_lock = threading.Lock()

_work_queue: queue.Queue = queue.Queue()
_workers_started = False
MAX_WORKERS = 3


def _generate_task_id() -> str:
    import uuid
    return str(uuid.uuid4())


def get_task(task_id: str) -> dict | None:
    with _tasks_lock:
        return dict(_tasks.get(task_id, {}))


def get_all_tasks() -> list[dict]:
    with _tasks_lock:
        return [dict(v) | {"task_id": k} for k, v in _tasks.items()]


def _update_task(task_id: str, **kwargs):
    with _tasks_lock:
        if task_id in _tasks:
            _tasks[task_id].update(kwargs)


def cancel_task(task_id: str):
    with _cancelled_lock:
        _cancelled_tasks.add(task_id)
    
    with _processes_lock:
        proc = _active_processes.get(task_id)
        if proc:
            try:
                proc.terminate()
                print(f"Terminated process for task {task_id}")
            except Exception as e:
                print(f"Error terminating process: {e}")

    _update_task(task_id, status="error", error="Lượt quét đã bị dừng bởi người dùng.")


def _worker_loop():
    while True:
        payload = _work_queue.get()
        if payload is None:
            break
        _execute_scan(payload)
        _work_queue.task_done()


def start_workers():
    global _workers_started
    if _workers_started:
        return
    for _ in range(MAX_WORKERS):
        t = threading.Thread(target=_worker_loop, daemon=True)
        t.start()
    _workers_started = True


# ── Main public API ───────────────────────────────────────────────────────────

def submit_scan(scan_options: dict) -> str:
    """
    Submit a scan job. Returns task_id immediately.
    scan_options keys:
        target, scan_type (discovery|ports|full|segment),
        ports, service_version, os_detect,
        name (optional label)
    """
    start_workers()
    task_id = _generate_task_id()

    # Create scan record in DB
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO scans (name, target, scan_type, status, options) VALUES (?,?,?,?,?)",
        (
            scan_options.get("name") or f"Scan {datetime.now().strftime('%H:%M:%S')}",
            scan_options["target"],
            scan_options.get("scan_type", "full"),
            "pending",
            json.dumps(scan_options),
        )
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    with _tasks_lock:
        tz = pytz.timezone(Config.TIMEZONE)
        now_local = datetime.now(tz).isoformat()
        
        _tasks[task_id] = {
            "task_id": task_id,
            "scan_id": scan_id,
            "status": "pending",
            "progress": 0,
            "hosts_found": 0,
            "error": None,
            "created_at": now_local,
        }

    _work_queue.put({"task_id": task_id, "scan_id": scan_id, **scan_options})
    return task_id


def _execute_scan(payload: dict):
    task_id = payload["task_id"]
    scan_id = payload["scan_id"]
    target = payload["target"]
    scan_type = payload.get("scan_type", "full")

    # Resolve target if it's the fixed monitored list
    if target == "monitored_list":
        conn = get_db()
        devices = conn.execute("SELECT ip FROM monitored_devices").fetchall()
        conn.close()
        if not devices:
            _update_task(task_id, status="error", error="Danh sách thiết bị giám sát trống. Hãy thêm thiết bị trước.")
            return
        # Join IPs into a space-separated string for Nmap
        target = " ".join([d["ip"] for d in devices])

    _update_task(task_id, status="running", progress=5)
    _set_scan_status(scan_id, "running")

    try:
        from scanner.nmap_scanner import get_scanner, validate_target

        valid, err = validate_target(target)
        if not valid:
            raise ValueError(err)

        scanner = get_scanner()
        hosts_found = [0]

        def set_proc(proc):
            with _processes_lock:
                _active_processes[task_id] = proc

        # Determine nmap arguments based on scan_type
        timing = payload.get("timing") or Config.SCAN_TIMING
        args = f"{timing}"

        if scan_type == "discovery":
            args += " -sn"
        elif scan_type == "segment":
            # Segment probe still uses blocking scan for simplicity
            internal = payload.get("internal_subnets", [])
            result = scanner.segment_probe([target], internal)
            for item in result["reachable"]:
                _create_alert(
                    scan_id=scan_id, 
                    severity="critical", 
                    title="VLAN Hop Detected!", 
                    message=item["message"], 
                    ip=item["ip"],
                    tags="vlan,network,security"
                )
            _update_task(task_id, status="done", progress=100)
            _set_scan_status(scan_id, "done")
            return
        else:
            ports_arg = payload.get("ports") or Config.COMMON_PORTS
            args += f" -p {ports_arg}"
            if payload.get("service_version", True):
                args += " -sV"
            if payload.get("os_detect", False):
                args += " -O"
            
        # Advanced options
        if payload.get("stealth_mode"):
            # -f: fragment packets, -Pn: skip ping, --randomize-hosts: avoid sequential patterns
            args += " -f -Pn --randomize-hosts"
        
        if payload.get("vuln_check"):
            # Use NSE vuln scripts
            args += " --script vuln"
        
        print(f"DEBUG: Starting Nmap scan for {target} with args: {args}")

        # Run streaming scan
        for host_data in scanner.live_scan(target, args, set_process_cb=set_proc):
            # Check for manual cancellation (in case terminate didn't work instantly)
            with _cancelled_lock:
                if task_id in _cancelled_tasks:
                    raise InterruptedError("Task cancelled by user")

            hosts_found[0] += 1
            # Progress is tricky without total, let's just increment or use a capped value
            progress = min(95, 10 + (hosts_found[0] * 2)) 
            _update_task(task_id, progress=progress, hosts_found=hosts_found[0])
            _save_host(scan_id, host_data)
            _generate_alerts(scan_id, host_data)

        _update_task(task_id, status="done", progress=100)
        _set_scan_status(scan_id, "done")

    except InterruptedError:
        _update_task(task_id, status="error", error="Lượt quét đã bị dừng", progress=0)
        _set_scan_status(scan_id, "error", error="Bị dừng bởi người dùng")
    except Exception as e:
        # If it was terminated, it might raise a 'BrokenPipeError' or similar, 
        # but we check if it was cancelled
        with _cancelled_lock:
            cancelled = task_id in _cancelled_tasks
        
        if cancelled:
            _update_task(task_id, status="error", error="Đã dừng", progress=0)
            _set_scan_status(scan_id, "error", error="Bị dừng bởi người dùng")
        else:
            _update_task(task_id, status="error", error=str(e), progress=0)
            _set_scan_status(scan_id, "error", error=str(e))
    finally:
        with _processes_lock:
            if task_id in _active_processes:
                del _active_processes[task_id]
        with _cancelled_lock:
            if task_id in _cancelled_tasks:
                _cancelled_tasks.remove(task_id)


def _set_scan_status(scan_id: int, status: str, error: str = None):
    conn = get_db()
    if status in ("done", "error"):
        conn.execute(
            "UPDATE scans SET status=?, end_time=CURRENT_TIMESTAMP, error=? WHERE id=?",
            (status, error, scan_id)
        )
    else:
        conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
    conn.commit()
    conn.close()


def _save_host(scan_id: int, host_data: dict) -> int:
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO hosts (scan_id, ip, mac, hostname, vendor, device_type, os_info, status)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            scan_id,
            host_data["ip"],
            host_data.get("mac", ""),
            host_data.get("hostname", ""),
            host_data.get("vendor", "Unknown"),
            host_data.get("device_type", "Unknown Device"),
            host_data.get("os_info", ""),
            host_data.get("status", "up"),
        )
    )
    host_id = cur.lastrowid
    for p in host_data.get("ports", []):
        conn.execute(
            "INSERT INTO ports (host_id, port, protocol, state, service, version) VALUES (?,?,?,?,?,?)",
            (host_id, p["port"], p["protocol"], p["state"], p["service"], p["version"])
        )
    conn.commit()
    conn.close()
    return host_id


def _generate_alerts(scan_id: int, host_data: dict):
    """Auto-generate alerts based on risky ports/device types."""
    critical_ports = {23: "Telnet", 21: "FTP", 3389: "RDP", 5900: "VNC",
                      3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                      27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
    
    # New Device Alert
    # (Future logic: check against baseline)
    
    for p in host_data.get("ports", []):
        port_num = p["port"]
        if port_num in critical_ports:
            service_name = critical_ports[port_num]
            _create_alert(
                scan_id=scan_id,
                severity="critical" if port_num in (3389, 5900, 23) else "high",
                title=f"Dịch vụ nguy hiểm: {service_name}",
                message=(
                    f"Thiết bị {host_data['ip']} mở cổng {service_name} "
                    f"(port {port_num}) — {p.get('version','')}".strip()
                ),
                ip=host_data["ip"],
                port=port_num,
                tags=f"port,service,{service_name.lower()}"
            )

def _create_alert(scan_id, severity, title, message, ip=None, port=None, tags=None):
    conn = get_db()
    # Ensure timestamp is local with offset (ISO 8601)
    tz = pytz.timezone(Config.TIMEZONE)
    now_iso = datetime.now(tz).isoformat()
    
    conn.execute(
        "INSERT INTO alerts (severity, title, message, ip, port, scan_id, tags, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (severity, title, message, ip, port, scan_id, tags, now_iso)
    )
    conn.commit()
    conn.close()
