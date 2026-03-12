"""
REST API Routes for Network Scanner
All endpoints return JSON.
"""
import os
import platform
import ctypes
from flask import Blueprint, request, jsonify
from config import Config
from database import get_db, row_to_dict, rows_to_list
from scanner import task_manager
from scanner.nmap_scanner import validate_target

api = Blueprint("api", __name__, url_prefix="/api")


# ── Scans ──────────────────────────────────────────────────────────────────────

@api.route("/scans", methods=["GET"])
def list_scans():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY start_time DESC LIMIT 50"
    ).fetchall()
    conn.close()
    
    scans = rows_to_list(rows)
    # Enrich with active task_id if exists
    active_tasks = {t["scan_id"]: t["task_id"] for t in task_manager.get_all_tasks()}
    for s in scans:
        if s["id"] in active_tasks:
            s["task_id"] = active_tasks[s["id"]]
    
    return jsonify(scans)


@api.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    conn = get_db()
    scan = row_to_dict(conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
    if not scan:
        conn.close()
        return jsonify({"error": "Scan not found"}), 404
    
    # Check for active task
    active_tasks = {t["scan_id"]: t["task_id"] for t in task_manager.get_all_tasks()}
    if scan_id in active_tasks:
        scan["task_id"] = active_tasks[scan_id]

    hosts = rows_to_list(conn.execute(
        "SELECT * FROM hosts WHERE scan_id=?", (scan_id,)
    ).fetchall())
    for h in hosts:
        h["ports"] = rows_to_list(conn.execute(
            "SELECT * FROM ports WHERE host_id=?", (h["id"],)
        ).fetchall())
    conn.close()
    scan["hosts"] = hosts
    return jsonify(scan)


@api.route("/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    try:
        # Check if there's an active task for this scan and cancel it
        active_tasks = task_manager.get_all_tasks()
        for t in active_tasks:
            if t.get("scan_id") == scan_id:
                task_manager.cancel_task(t["task_id"])
        
        conn = get_db()
        # Delete related records
        conn.execute("DELETE FROM alerts WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM baselines WHERE scan_id=?", (scan_id,))
        # Note: hosts and ports have ON DELETE CASCADE
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error deleting scan {scan_id}: {e}")
        return jsonify({"error": str(e)}), 500


# ── Scan Control ──────────────────────────────────────────────────────────────

@api.route("/scan/start", methods=["POST"])
def start_scan():
    data = request.get_json(force=True) or {}
    target = (data.get("target") or "").strip()

    valid, err = validate_target(target)
    if not valid:
        return jsonify({"error": err}), 400

    scan_type = data.get("scan_type", "full")
    if scan_type not in ("discovery", "ports", "full", "segment"):
        return jsonify({"error": "Invalid scan_type"}), 400

    options = {
        "target": target,
        "scan_type": scan_type,
        "name": data.get("name", ""),
        "ports": data.get("ports", ""),
        "service_version": bool(data.get("service_version", True)),
        "os_detect": bool(data.get("os_detect", False)),
        "internal_subnets": data.get("internal_subnets", []),
    }
    task_id = task_manager.submit_scan(options)
    return jsonify({"task_id": task_id, "status": "pending"}), 202


@api.route("/scan/status/<task_id>", methods=["GET"])
def scan_status(task_id):
    task = task_manager.get_task(task_id)
    if task is None:
        return jsonify({"error": "Task not found"}), 404

    # Enrich with live host count if scan is running
    if task.get("scan_id"):
        conn = get_db()
        count = conn.execute(
            "SELECT COUNT(*) as c FROM hosts WHERE scan_id=?",
            (task["scan_id"],)
        ).fetchone()["c"]
        conn.close()
        task["hosts_found"] = count
    return jsonify(task)


@api.route("/scan/stop/<task_id>", methods=["POST"])
def stop_scan(task_id):
    from scanner.task_manager import cancel_task
    cancel_task(task_id)
    return jsonify({"success": True})


# ── Devices ───────────────────────────────────────────────────────────────────

@api.route("/devices", methods=["GET"])
def list_devices():
    """Return all unique hosts, latest occurrence per IP."""
    conn = get_db()
    # Latest scan's hosts, deduplicated by IP
    rows = conn.execute("""
        SELECT h.*, s.start_time as scan_time, s.name as scan_name
        FROM hosts h
        JOIN scans s ON s.id = h.scan_id
        WHERE h.status = 'up'
        ORDER BY h.scan_id DESC
    """).fetchall()
    hosts = rows_to_list(rows)
    seen_ips = set()
    unique = []
    for h in hosts:
        if h["ip"] not in seen_ips:
            seen_ips.add(h["ip"])
            h["ports"] = rows_to_list(conn.execute(
                "SELECT * FROM ports WHERE host_id=?", (h["id"],)
            ).fetchall())
            unique.append(h)
    conn.close()
    return jsonify(unique)


# ── Alerts ────────────────────────────────────────────────────────────────────

@api.route("/alerts", methods=["GET"])
def list_alerts():
    tag = request.args.get("tag")
    conn = get_db()
    if tag:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE tags LIKE ? ORDER BY created_at DESC LIMIT 200",
            (f"%{tag}%",)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    conn.close()
    return jsonify(rows_to_list(rows))


@api.route("/alerts/<int:alert_id>/read", methods=["POST"])
def mark_alert_read(alert_id):
    conn = get_db()
    conn.execute("UPDATE alerts SET is_read=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@api.route("/alerts/read-all", methods=["POST"])
def mark_all_read():
    conn = get_db()
    conn.execute("UPDATE alerts SET is_read=1")
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@api.route("/alerts/unread-count", methods=["GET"])
def unread_alert_count():
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE is_read=0"
    ).fetchone()["c"]
    conn.close()
    return jsonify({"count": count})


# ── Baseline ──────────────────────────────────────────────────────────────────

@api.route("/baselines", methods=["GET"])
def list_baselines():
    conn = get_db()
    rows = conn.execute(
        "SELECT b.*, s.target, s.scan_type FROM baselines b "
        "JOIN scans s ON s.id = b.scan_id ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify(rows_to_list(rows))


@api.route("/baseline/save", methods=["POST"])
def save_baseline():
    data = request.get_json(force=True) or {}
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400

    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "Scan not found"}), 404

    cur = conn.execute(
        "INSERT INTO baselines (name, description, scan_id) VALUES (?,?,?)",
        (
            data.get("name") or f"Baseline from scan #{scan_id}",
            data.get("description", ""),
            scan_id,
        )
    )
    baseline_id = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({"baseline_id": baseline_id, "success": True}), 201


@api.route("/baseline/<int:baseline_id>", methods=["DELETE"])
def delete_baseline(baseline_id):
    try:
        conn = get_db()
        conn.execute("DELETE FROM baselines WHERE id=?", (baseline_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/baseline/compare", methods=["GET"])
def compare_baseline():
    """
    Compare scan_id vs baseline_id. Returns added/removed/changed hosts and ports.
    """
    scan_id = request.args.get("scan_id", type=int)
    baseline_id = request.args.get("baseline_id", type=int)
    if not scan_id or not baseline_id:
        return jsonify({"error": "scan_id and baseline_id required"}), 400

    conn = get_db()
    baseline = conn.execute("SELECT * FROM baselines WHERE id=?", (baseline_id,)).fetchone()
    if not baseline:
        conn.close()
        return jsonify({"error": "Baseline not found"}), 404

    baseline_scan_id = baseline["scan_id"]

    def get_hosts_map(sid):
        rows = rows_to_list(conn.execute(
            "SELECT * FROM hosts WHERE scan_id=?", (sid,)
        ).fetchall())
        result = {}
        for h in rows:
            h["ports"] = rows_to_list(conn.execute(
                "SELECT port, protocol, service FROM ports WHERE host_id=?", (h["id"],)
            ).fetchall())
            result[h["ip"]] = h
        return result

    base_map = get_hosts_map(baseline_scan_id)
    new_map = get_hosts_map(scan_id)
    conn.close()

    added = [v for ip, v in new_map.items() if ip not in base_map]
    removed = [v for ip, v in base_map.items() if ip not in new_map]
    changed = []
    for ip in set(base_map) & set(new_map):
        b_ports = {p["port"] for p in base_map[ip]["ports"]}
        n_ports = {p["port"] for p in new_map[ip]["ports"]}
        new_ports = n_ports - b_ports
        closed_ports = b_ports - n_ports
        if new_ports or closed_ports:
            changed.append({
                "ip": ip,
                "host": new_map[ip],
                "new_ports": list(new_ports),
                "closed_ports": list(closed_ports),
            })

    return jsonify({
        "added_hosts": added,
        "removed_hosts": removed,
        "changed_hosts": changed,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        }
    })


# ── Network Segments ──────────────────────────────────────────────────────────

@api.route("/segment/probe", methods=["POST"])
def segment_probe():
    data = request.get_json(force=True) or {}
    internal_subnets = data.get("internal_subnets", [])
    guest_target = data.get("guest_target", "")

    if not internal_subnets:
        return jsonify({"error": "internal_subnets required"}), 400

    valid, err = validate_target(guest_target or "127.0.0.1")
    if not valid:
        return jsonify({"error": err}), 400

    from scanner.nmap_scanner import get_scanner
    sc = get_scanner()
    result = sc.segment_probe([guest_target], internal_subnets)
    return jsonify(result)


# ── Network Lists ─────────────────────────────────────────────────────────────

@api.route("/network-lists", methods=["GET"])
def get_network_lists():
    """Return configured Guest/Server/Local network segment lists."""
    from config import Config
    return jsonify(Config.NETWORK_LISTS)


# ── Monitored Devices ──────────────────────────────────────────────────────────

@api.route("/monitored", methods=["GET"])
def list_monitored():
    conn = get_db()
    rows = conn.execute("SELECT * FROM monitored_devices ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify(rows_to_list(rows))


@api.route("/monitored", methods=["POST"])
def add_monitored():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP is required"}), 400
    
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO monitored_devices (ip, name, vendor, model) VALUES (?,?,?,?)",
            (ip, data.get("name"), data.get("vendor"), data.get("model"))
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "IP already exists in monitored list"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/monitored/<int:device_id>", methods=["PUT"])
def update_monitored(device_id):
    data = request.get_json(force=True) or {}
    try:
        conn = get_db()
        conn.execute(
            "UPDATE monitored_devices SET ip=?, name=?, vendor=?, model=? WHERE id=?",
            (data.get("ip"), data.get("name"), data.get("vendor"), data.get("model"), device_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/monitored/<int:device_id>", methods=["DELETE"])
def delete_monitored(device_id):
    try:
        conn = get_db()
        conn.execute("DELETE FROM monitored_devices WHERE id=?", (device_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Dashboard Stats ───────────────────────────────────────────────────────────

@api.route("/stats", methods=["GET"])
def dashboard_stats():
    conn = get_db()
    total_scans = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    total_hosts = conn.execute(
        "SELECT COUNT(DISTINCT ip) as c FROM hosts WHERE status='up'"
    ).fetchone()["c"]
    total_ports = conn.execute(
        "SELECT COUNT(*) as c FROM ports WHERE state='open'"
    ).fetchone()["c"]
    critical_alerts = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE severity='critical' AND is_read=0"
    ).fetchone()["c"]
    unread_alerts = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE is_read=0"
    ).fetchone()["c"]
    last_scan = row_to_dict(conn.execute(
        "SELECT * FROM scans ORDER BY start_time DESC LIMIT 1"
    ).fetchone())

    # Device type distribution
    device_dist = rows_to_list(conn.execute(
        "SELECT device_type, COUNT(*) as count FROM hosts "
        "WHERE status='up' GROUP BY device_type ORDER BY count DESC"
    ).fetchall())

    conn.close()
    return jsonify({
        "total_scans": total_scans,
        "total_hosts": total_hosts,
        "total_open_ports": total_ports,
        "critical_alerts": critical_alerts,
        "unread_alerts": unread_alerts,
        "last_scan": last_scan,
        "device_distribution": device_dist,
    })
# ── System Info ───────────────────────────────────────────────────────────────

@api.route("/system/status", methods=["GET"])
def system_status():
    """Return application system status like admin privileges."""
    is_admin = False
    if platform.system() == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
    else:
        # Check for root on Linux/macOS
        is_admin = os.getuid() == 0

    return jsonify({
        "is_admin": is_admin,
        "platform": platform.system(),
        "nmap_path": Config.NMAP_PATH if 'Config' in globals() else "nmap"
    })
