// NOTE: Audit log page handler for querying and exporting filtered logs.

let auditLogs = [];
const JSPDF_URL = 'https://cdn.jsdelivr.net/npm/jspdf@2.5.1/dist/jspdf.umd.min.js';
let jsPdfLoadPromise = null;

document.addEventListener('DOMContentLoaded', () => {
    initializeAuditLogs();
});

async function initializeAuditLogs() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }

    setupLogoutButton();
    setupAuditFilterEvents();
    await loadAuditLogs();
}

function setupAuditFilterEvents() {
    const applyButton = document.getElementById('audit-apply-filters');
    if (applyButton) {
        applyButton.addEventListener('click', () => loadAuditLogs());
    }

    const resetButton = document.getElementById('audit-reset-filters');
    if (resetButton) {
        resetButton.addEventListener('click', () => {
            resetFilters();
            loadAuditLogs();
        });
    }

    const exportButton = document.getElementById('export-audit-btn');
    if (exportButton) {
        exportButton.addEventListener('click', openAuditExportModal);
    }

    const closeButton = document.getElementById('audit-export-close');
    if (closeButton) {
        closeButton.addEventListener('click', closeAuditExportModal);
    }

    const cancelButton = document.getElementById('audit-export-cancel');
    if (cancelButton) {
        cancelButton.addEventListener('click', closeAuditExportModal);
    }

    const overlay = document.getElementById('audit-export-overlay');
    if (overlay) {
        overlay.addEventListener('click', closeAuditExportModal);
    }

    const csvButton = document.getElementById('audit-export-csv-btn');
    if (csvButton) {
        csvButton.addEventListener('click', () => {
            exportAuditLogs('csv');
        });
    }

    const jsonButton = document.getElementById('audit-export-json-btn');
    if (jsonButton) {
        jsonButton.addEventListener('click', () => {
            exportAuditLogs('json');
        });
    }

    const pdfButton = document.getElementById('audit-export-pdf-btn');
    if (pdfButton) {
        pdfButton.addEventListener('click', () => {
            exportAuditLogs('pdf');
        });
    }

    const filterInputs = ['audit-search', 'audit-action', 'audit-entity', 'audit-from', 'audit-to'];
    filterInputs.forEach((inputId) => {
        const inputEl = document.getElementById(inputId);
        if (inputEl) {
            inputEl.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    loadAuditLogs();
                }
            });
        }
    });
}

function buildAuditFilters() {
    const search = String(document.getElementById('audit-search')?.value || '').trim();
    const action = String(document.getElementById('audit-action')?.value || '').trim();
    const entityType = String(document.getElementById('audit-entity')?.value || '').trim();
    const from = String(document.getElementById('audit-from')?.value || '').trim();
    const to = String(document.getElementById('audit-to')?.value || '').trim();

    return {
        search,
        action,
        entityType,
        from,
        to,
        page: 1,
        limit: 100,
        scope: 'all',
    };
}

async function loadAuditLogs() {
    const tbody = document.getElementById('audit-logs-tbody');
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">Loading audit logs...</td></tr>';
    }

    try {
        const response = await apiClient.getAuditLogs(buildAuditFilters());
        auditLogs = Array.isArray(response?.logs) ? response.logs : [];
        renderAuditLogs(auditLogs);
    } catch (error) {
        console.error('Error loading audit logs:', error);
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Failed to load audit logs</td></tr>';
        }
        showNotification('Unable to load audit logs', 'error');
    }
}

function renderAuditLogs(logs) {
    const tbody = document.getElementById('audit-logs-tbody');
    if (!tbody) {
        return;
    }

    if (!Array.isArray(logs) || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">No audit logs found</td></tr>';
        return;
    }

    tbody.innerHTML = logs.map((log) => {
        const timestamp = formatDateTime(log.createdAt || new Date().toISOString());
        const action = escapeHtml(log.action || 'N/A');
        const entityType = escapeHtml(log.entityType || 'N/A');
        const entityId = escapeHtml(log.entityId || 'N/A');
        const ipAddress = escapeHtml(log.ipAddress || 'N/A');

        return `<tr><td data-label="Time">${timestamp}</td><td data-label="Action">${action}</td><td data-label="Entity">${entityType}</td><td data-label="Entity ID">${entityId}</td><td data-label="IP Address">${ipAddress}</td></tr>`;
    }).join('');
}

function openAuditExportModal() {
    if (!Array.isArray(auditLogs) || auditLogs.length === 0) {
        showNotification('No audit logs to export', 'warning');
        return;
    }

    showModal('audit-export-modal');
}

function closeAuditExportModal() {
    hideModal('audit-export-modal');
}

async function ensureJsPdfLoaded() {
    if (window.jspdf?.jsPDF) {
        return;
    }

    if (!jsPdfLoadPromise) {
        jsPdfLoadPromise = new Promise((resolve, reject) => {
            const existingScript = document.querySelector(`script[src="${JSPDF_URL}"]`);
            if (existingScript) {
                existingScript.addEventListener('load', () => resolve(), { once: true });
                existingScript.addEventListener('error', () => reject(new Error('Failed to load jsPDF')), { once: true });
                return;
            }

            const script = document.createElement('script');
            script.src = JSPDF_URL;
            script.defer = true;
            script.onload = () => resolve();
            script.onerror = () => reject(new Error('Failed to load jsPDF'));
            document.head.appendChild(script);
        });
    }

    await jsPdfLoadPromise;
}

function downloadBlob(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
}

async function exportAuditLogs(exportFormat = 'csv') {
    const format = String(exportFormat || 'csv').trim().toLowerCase();

    if (!Array.isArray(auditLogs) || auditLogs.length === 0) {
        showNotification('No audit logs to export', 'warning');
        return;
    }

    const data = auditLogs.map((log) => ({
        Timestamp: formatDateTime(log.createdAt || ''),
        Action: log.action || '',
        EntityType: log.entityType || '',
        EntityId: log.entityId || '',
        IpAddress: log.ipAddress || '',
    }));

    try {
        if (format === 'json') {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json;charset=utf-8' });
            downloadBlob(blob, 'audit-logs.json');
        } else if (format === 'pdf') {
            await ensureJsPdfLoaded();
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            let y = 20;

            doc.setFontSize(16);
            doc.text('Audit Logs Report', 14, y);
            y += 10;
            doc.setFontSize(11);

            data.forEach((log, index) => {
                if (y > 265) {
                    doc.addPage();
                    y = 20;
                }

                doc.text(`${index + 1}. ${log.Timestamp} | ${log.Action} | ${log.EntityType} | ${log.EntityId} | ${log.IpAddress}`, 14, y, { maxWidth: 180 });
                y += 7;
            });

            doc.save('audit-logs.pdf');
        } else {
            exportToCSV('audit-logs.csv', data);
        }

        closeAuditExportModal();
        showNotification('Audit logs exported successfully', 'success');
    } catch (error) {
        console.error('Audit log export failed:', error);
        showNotification('Failed to export audit logs', 'error');
    }
}

function resetFilters() {
    ['audit-search', 'audit-action', 'audit-entity', 'audit-from', 'audit-to'].forEach((id) => {
        const input = document.getElementById(id);
        if (input) {
            input.value = '';
        }
    });
}

function setupLogoutButton() {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.type = 'button';
    }
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
