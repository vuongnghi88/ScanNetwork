/**
 * app.js — Common utilities shared across all pages
 */

// ── Toast notifications ────────────────────────────────────────────────────
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const id = 'toast-' + Date.now();
    const icons = { success: '✅', danger: '🚨', warning: '⚠️', info: 'ℹ️' };
    const html = `
        <div id="${id}" class="toast align-items-center border-0" role="alert" aria-live="assertive" data-bs-autohide="true" data-bs-delay="4000">
            <div class="d-flex">
                <div class="toast-body d-flex align-items-center gap-2">
                    <span>${icons[type] || 'ℹ️'}</span>
                    <span>${message}</span>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>`;
    container.insertAdjacentHTML('beforeend', html);
    const toastEl = document.getElementById(id);
    const toast = new bootstrap.Toast(toastEl);
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

// ── Sidebar mobile toggle ──────────────────────────────────────────────────
document.getElementById('sidebarToggle')?.addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
});

// ── Alert badge in nav ────────────────────────────────────────────────────
async function refreshAlertBadge() {
    try {
        const { count } = await fetch('/api/alerts/unread-count').then(r => r.json());
        const badge = document.getElementById('nav-alert-count');
        if (!badge) return;
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }
    } catch (_) {}
}
refreshAlertBadge();
setInterval(refreshAlertBadge, 30000);

// ── Sidebar scan status ───────────────────────────────────────────────────
function setSidebarStatus(text, scanning = false) {
    const el = document.getElementById('sidebar-scan-status');
    const dot = document.querySelector('.status-dot');
    if (el) el.textContent = text;
    if (dot) {
        dot.classList.toggle('scanning', scanning);
        dot.classList.toggle('online', !scanning);
    }
}

// ── Last update time ──────────────────────────────────────────────────────
function updateTimestamp() {
    const el = document.getElementById('last-update-time');
    if (el) {
        const now = new Date();
        const formatter = new Intl.DateTimeFormat('vi-VN', {
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            timeZone: 'Asia/Ho_Chi_Minh'
        });
        el.textContent = 'Cập nhật lúc ' + formatter.format(now);
    }
}
setInterval(updateTimestamp, 10000);
updateTimestamp();

// ── Custom Modals (Promise-based) ───────────────────────────────────────────
function confirmModal(title, message) {
    return new Promise((resolve) => {
        const modalEl = document.getElementById('confirmModal');
        const modal = new bootstrap.Modal(modalEl);
        document.getElementById('confirmModalTitle').textContent = title;
        document.getElementById('confirmModalMessage').textContent = message;
        
        const confirmBtn = document.getElementById('confirmModalBtn');
        const onConfirm = () => {
            confirmBtn.removeEventListener('click', onConfirm);
            modal.hide();
            resolve(true);
        };
        
        confirmBtn.addEventListener('click', onConfirm);
        modalEl.addEventListener('hidden.bs.modal', () => {
            confirmBtn.removeEventListener('click', onConfirm);
            resolve(false);
        }, { once: true });
        
        modal.show();
    });
}

function promptModal(title, label, defaultValue = '') {
    return new Promise((resolve) => {
        const modalEl = document.getElementById('promptModal');
        const modal = new bootstrap.Modal(modalEl);
        document.getElementById('promptModalTitle').textContent = title;
        document.getElementById('promptModalLabel').textContent = label;
        const input = document.getElementById('promptModalInput');
        input.value = defaultValue;
        
        const saveBtn = document.getElementById('promptModalBtn');
        const onSave = () => {
            saveBtn.removeEventListener('click', onSave);
            const val = input.value;
            modal.hide();
            resolve(val);
        };
        
        saveBtn.addEventListener('click', onSave);
        modalEl.addEventListener('hidden.bs.modal', () => {
            saveBtn.removeEventListener('click', onSave);
            resolve(null);
        }, { once: true });
        
        modal.show();
        setTimeout(() => input.focus(), 500);
    });
}
