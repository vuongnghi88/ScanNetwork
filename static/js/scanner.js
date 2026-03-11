/**
 * scanner.js — Scan form control, AJAX polling, live results rendering
 */

let currentTaskId = null;
let currentScanId = null;
let pollInterval  = null;

const CRITICAL_PORTS = new Set([23,21,3389,5900,3306,5432,1433,27017,6379,9200]);
const HIGH_PORTS     = new Set([22,554,445,8000,37777,135]);

// ── Network List Presets ──────────────────────────────────────────────────
let networkLists = {};

async function loadNetworkLists() {
    try {
        networkLists = await fetch('/api/network-lists').then(r => r.json());
        const container = document.getElementById('network-list-btns');
        if (!container) return;
        container.innerHTML = Object.entries(networkLists).map(([key, list]) => `
            <button class="btn btn-sm btn-outline-secondary" onclick="applyNetworkList('${key}')" title="${list.description}">
                ${list.label}
            </button>`).join('');
    } catch (_) {}
}

function applyNetworkList(key) {
    const list = networkLists[key];
    if (!list) return;
    document.getElementById('scan-target').value = list.targets.join(', ');
    showToast(`Đã áp dụng ${list.label} — ${list.targets.join(', ')}`, 'info');
}

// ── scan.html: Preset helper (from inline script) ─────────────────────────
function setPreset(target, type) {
    document.getElementById('scan-target').value = target;
    document.getElementById('scan-type').value   = type;
}

// ── Start scan ────────────────────────────────────────────────────────────
document.getElementById('scan-form')?.addEventListener('submit', async function(e) {
    e.preventDefault();

    const target = document.getElementById('scan-target').value.trim();
    if (!target) { showToast('Vui lòng nhập mục tiêu quét.', 'warning'); return; }

    const scanType = document.getElementById('scan-type').value;
    const payload = {
        target,
        scan_type: scanType,
        name:     document.getElementById('scan-name').value.trim(),
        ports:    document.getElementById('custom-ports')?.value.trim() || '',
        service_version: document.getElementById('opt-svc')?.checked ?? true,
        os_detect:       document.getElementById('opt-os')?.checked  ?? false,
    };

    if (scanType === 'segment') {
        const raw = document.getElementById('internal-subnets')?.value || '';
        payload.internal_subnets = raw.split('\n')
            .map(s => s.trim()).filter(Boolean);
    }

    // UI
    setBtnState(true);
    clearResults();
    document.getElementById('status-box').style.display = 'block';
    setStatus('pending', 0, 0, target);
    setSidebarStatus('Đang quét…', true);

    try {
        const res = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) { showToast(data.error || 'Khởi động quét thất bại', 'danger'); setBtnState(false); return; }
        currentTaskId = data.task_id;
        localStorage.setItem('currentTaskId', currentTaskId);
        startPolling();
    } catch (err) {
        showToast('Network error: ' + err.message, 'danger');
        setBtnState(false);
    }
});

// ── Polling ───────────────────────────────────────────────────────────────
function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollStatus, 2000);
}

async function pollStatus() {
    if (!currentTaskId) return;
    try {
        const data = await fetch(`/api/scan/status/${currentTaskId}`).then(r => r.json());
        setStatus(data.status, data.progress || 0, data.hosts_found || 0);

        if (data.scan_id) {
            currentScanId = data.scan_id;
            refreshLiveResults(data.scan_id);
        }

        if (data.status === 'done') {
            clearInterval(pollInterval);
            setBtnState(false);
            setSidebarStatus('Đang chờ', false);
            showToast(`Quét hoàn tất — tìm thấy ${data.hosts_found || 0} thiết bị`, 'success');
            document.getElementById('save-baseline-btn').style.display = 'inline-block';
            refreshHistory();
            refreshAlertBadge();
        } else if (data.status === 'error') {
            clearInterval(pollInterval);
            currentTaskId = null;
            localStorage.removeItem('currentTaskId');
            setBtnState(false);
            setSidebarStatus('Đang chờ', false);
            showToast('Lỗi quét: ' + (data.error || 'Lỗi không xác định'), 'danger');
        }

        if (data.status === 'done') {
            currentTaskId = null;
            localStorage.removeItem('currentTaskId');
        }
    } catch (_) {}
}


async function stopScan() {
    if (!currentTaskId) return;
    if (!confirm('Bạn có chắc chắn muốn dừng lượt quét này?')) return;
    
    try {
        const res = await fetch(`/api/scan/stop/${currentTaskId}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast('Đã gửi yêu cầu dừng lượt quét', 'info');
            // Immediate UI update
            clearInterval(pollInterval);
            currentTaskId = null;
            localStorage.removeItem('currentTaskId');
            
            setStatus('error', null, null, 'Đã dừng');
            setBtnState(false);
            setSidebarStatus('Đã dừng', false);
        } else {
            showToast('Lỗi khi dừng lượt quét', 'danger');
        }
    } catch (err) {
        showToast('Lỗi mạng khi dừng lượt quét', 'danger');
    }
    // Final check: poll one last time or refresh history
    setTimeout(refreshHistory, 1000);
}

// ── Load existing scan results (when ?view=<id>) ──────────────────────────
async function loadScanResults(scanId, status = 'done') {
    currentScanId = scanId;
    document.getElementById('status-box').style.display = 'block';
    
    try {
        const data = await fetch(`/api/scans/${scanId}`).then(r => r.json());
        
        // If this scan is currently active in the manager, link to it
        if (data.task_id) {
            currentTaskId = data.task_id;
            startPolling();
            setBtnState(true);
        } else {
            currentTaskId = null;
            setBtnState(false);
        }

        setStatus(status, data.progress || (status === 'done' ? 100 : 0), data.hosts?.length || 0, data.name);
        renderHosts(data.hosts || []);

        if (status === 'done') {
            document.getElementById('save-baseline-btn').style.display = 'inline-block';
        } else {
            document.getElementById('save-baseline-btn').style.display = 'none';
        }
    } catch (err) {
        showToast('Lỗi khi tải kết quả', 'danger');
    }
}

// ── Refresh results table from DB ─────────────────────────────────────────
let _lastHostCount = 0;

async function refreshLiveResults(scanId) {
    const data = await fetch(`/api/scans/${scanId}`).then(r => r.json()).catch(() => null);
    if (!data || !data.hosts) return;
    if (data.hosts.length === _lastHostCount) return; // no change
    renderHosts(data.hosts);
}

function renderHosts(hosts) {
    _lastHostCount = hosts.length;
    document.getElementById('result-count').textContent = `${hosts.length} thiết bị`;
    const tbody = document.getElementById('results-tbody');
    if (!tbody) return;

    if (hosts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">Đang quét hoặc không tìm thấy thiết bị…</td></tr>';
        return;
    }

    tbody.innerHTML = hosts.map(h => {
        const ports = h.ports || [];
        const portHtml = ports.length
            ? ports.map(p => portPill(p)).join('')
            : '<span class="text-muted" style="font-size:.75rem">—</span>';
        return `<tr class="scan-result-row">
            <td>
                <span style="font-size:1.1rem">${deviceIcon(h)}</span>
                <span style="font-size:.8rem;display:block;margin-top:2px">${h.device_type||'Chưa rõ'}</span>
            </td>
            <td class="ip-addr">${h.ip}</td>
            <td>
                <div class="mac-addr">${h.mac||'—'}</div>
                <div style="font-size:.72rem;color:var(--text-dim)">${h.vendor||''}</div>
            </td>
            <td style="font-size:.75rem;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                title="${h.os_info||''}">${h.os_info||'—'}</td>
            <td style="min-width:160px">${portHtml}</td>
            <td><span class="badge risk-${h.risk||'unknown'}">${{critical:'Nghiêm trọng',high:'Cao',medium:'Trung bình',low:'Thấp',unknown:'Chưa rõ'}[h.risk]||h.risk||'Chưa rõ'}</span></td>
        </tr>`;
    }).join('');
}

// ── Save baseline ─────────────────────────────────────────────────────────
async function saveBaseline() {
    if (!currentScanId) return;
    const name = await promptModal('Lưu Dữ liệu mẫu', 'Nhập tên cho bản mẫu này:', `Bản mẫu ${new Date().toLocaleDateString('vi-VN')}`);
    if (!name) return;
    const res = await fetch('/api/baseline/save', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({scan_id: currentScanId, name}),
    });
    const data = await res.json();
    if (data.success) showToast('Đã lưu bản mẫu!', 'success');
    else showToast(data.error || 'Lỗi khi lưu bản mẫu', 'danger');
}

// ── History ───────────────────────────────────────────────────────────────
async function refreshHistory() {
    const scans = await fetch('/api/scans').then(r => r.json()).catch(() => []);
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;
    if (!scans.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">Chưa có lượt quét nào.</td></tr>';
        return;
    }

    tbody.innerHTML = scans.slice(0, 20).map(s => `
        <tr>
            <td class="text-muted text-mono">#${s.id}</td>
            <td>${s.name || '—'}</td>
            <td class="ip-addr" style="font-size:.8rem">${s.target}</td>
            <td><span class="badge bg-secondary">${s.scan_type}</span></td>
            <td>${statusBadge(s.status)}</td>
            <td class="text-muted" style="font-size:.75rem">${fmtTime(s.start_time)}</td>
            <td class="text-mono" style="font-size:.8rem">—</td>
            <td class="d-flex gap-1">
                <button class="btn btn-sm btn-outline-secondary py-0 px-2"
                        onclick="loadScanResults(${s.id}, '${s.status}')">Xem</button>
                <button class="btn btn-sm btn-outline-danger py-0 px-2"
                        onclick="deleteScan(${s.id})">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`).join('');
}

async function deleteScan(id) {
    const ok = await confirmModal('Xác nhận xóa', `Bạn có chắc chắn muốn xóa lượt quét #${id}?`);
    if (!ok) return;
    try {
        const res = await fetch(`/api/scans/${id}`, {method: 'DELETE'});
        if (res.ok) {
            showToast(`Đã xóa lượt quét #${id}`, 'info');
            // Small delay to ensure DB commit
            setTimeout(refreshHistory, 200);
            if (currentScanId == id) {
                document.getElementById('status-box').style.display = 'none';
                document.getElementById('results-tbody').innerHTML = '<tr><td colspan="6" class="no-data-placeholder"><i class="bi bi-radar"></i>Hãy chọn một lượt quét từ lịch sử hoặc bắt đầu quét mới</td></tr>';
            }
        } else {
            const data = await res.json().catch(() => ({}));
            showToast(data.error || 'Lỗi khi xóa lượt quét', 'danger');
        }
    } catch (err) {
        showToast('Lỗi mạng khi xóa: ' + err.message, 'danger');
    }
}

async function deleteBaseline(id) {
    if (!confirm(`Xóa bản mẫu #${id}?`)) return;
    try {
        const res = await fetch(`/api/baseline/${id}`, {method: 'DELETE'});
        if (res.ok) {
            showToast(`Đã xóa bản mẫu #${id}`, 'info');
            if (typeof loadData === 'function') loadData();
        } else {
            const data = await res.json().catch(() => ({}));
            showToast(data.error || 'Lỗi khi xóa bản mẫu', 'danger');
        }
    } catch (err) {
        showToast('Lỗi mạng khi xóa', 'danger');
    }
}

// ── UI helpers ────────────────────────────────────────────────────────────
function setStatus(status, progress, hostsFound, label = '') {
    const el = document.getElementById('status-val');
    const bar = document.getElementById('scan-progress');
    const pct = document.getElementById('progress-pct');
    const hf  = document.getElementById('hosts-found-val');
    const lbl = document.getElementById('scan-target-label');

    const statusMap = {pending:'Đang chờ',running:'Đang quét',done:'Hoàn tất',error:'Lỗi'};
    if (el) { el.textContent = statusMap[status]||status; el.className = `scan-status-value ${status}`; }
    if (bar) { bar.style.width = progress + '%'; }
    if (pct) pct.textContent = progress + '%';
    if (hf)  hf.textContent  = hostsFound;
    if (lbl && label) lbl.textContent = label;
}

function setBtnState(scanning) {
    const start = document.getElementById('start-btn');
    const stop  = document.getElementById('stop-btn');
    if (start) {
        start.disabled = scanning;
        start.innerHTML = scanning ? '<i class="bi bi-hourglass-split me-1"></i> Đang chạy...' : '<i class="bi bi-play-circle me-1"></i> Bắt đầu';
    }
    if (stop) {
        stop.style.display = scanning ? 'block' : 'none';
    }
}

function clearResults() {
    _lastHostCount = 0;
    const tbody = document.getElementById('results-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">Đang quét…</td></tr>';
    document.getElementById('result-count').textContent = '0 thiết bị';
    document.getElementById('save-baseline-btn').style.display = 'none';
}

function portPill(p) {
    let cls = '';
    if (CRITICAL_PORTS.has(p.port)) cls = 'critical';
    else if (HIGH_PORTS.has(p.port)) cls = 'high';
    const tip = p.service ? `title="${p.service} ${p.version || ''}"`.trim() : '';
    return `<span class="port-pill ${cls}" ${tip}>${p.port}/${p.protocol}</span>`;
}

function deviceIcon(h) {
    const icons = { 'IP Camera':'📷','Network Device':'🔌','Windows PC':'💻',
        'Linux Server':'🖥️','Smart TV':'📺','IoT Device':'⚙️',
        'Apple Device':'🍎','Printer':'🖨️','Virtual Machine':'☁️',
        'Web Server':'🌐','MySQL Database':'🗄️','Unknown Device':'❓' };
    return icons[h.device_type] || '❓';
}

function statusBadge(s) {
    const map = {pending:'Đang chờ',running:'Đang quét',done:'Hoàn tất',error:'Lỗi'};
    const cls = {pending:'secondary',running:'primary',done:'success',error:'danger'};
    return `<span class="badge bg-${cls[s]||'secondary'}">${map[s]||s}</span>`;
}

function fmtTime(t) {
    if (!t) return '—';
    return new Date(t).toLocaleString('vi-VN', {dateStyle:'short', timeStyle:'short'});
}

// ── Multitasking Persistence ──────────────────────────────────────────────
async function checkActiveTask() {
    const savedId = localStorage.getItem('currentTaskId');
    if (savedId) {
        try {
            const data = await fetch(`/api/scan/status/${savedId}`).then(r => r.json());
            if (data.status === 'running' || data.status === 'pending') {
                currentTaskId = savedId;
                clearResults(); // Clear "Please configure..." placeholder
                setBtnState(true);
                document.getElementById('status-box').style.display = 'block';
                setSidebarStatus('Đang quét…', true);
                startPolling();
            } else {
                localStorage.removeItem('currentTaskId');
            }
        } catch (_) {
            localStorage.removeItem('currentTaskId');
        }
    }
}

// ── Init ──────────────────────────────────────────────────────────────────
loadNetworkLists();
refreshHistory();
checkActiveTask();
