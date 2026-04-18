// NOTE: Audit log page handler for querying and exporting filtered logs.

let auditLogs = [];
const JSPDF_URL = 'https://cdn.jsdelivr.net/npm/jspdf@2.5.1/dist/jspdf.umd.min.js';
let jsPdfLoadPromise = null;
let auditCurrentPage = 1;
let auditTotalPages = 1;
let auditTotalRecords = 0;
const AUDIT_ROWS_PER_PAGE = 25;

function getAuditPaginationControls() {
    return Array.from(document.querySelectorAll('[data-audit-pagination-container]')).map((container) => ({
        previousButton: container.querySelector('[data-audit-pagination-action="prev"]'),
        nextButton: container.querySelector('[data-audit-pagination-action="next"]'),
        pageList: container.querySelector('[data-audit-pagination-role="list"]'),
        infoEl: container.querySelector('[data-audit-pagination-role="info"]'),
    }));
}

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
        applyButton.addEventListener('click', () => {
            auditCurrentPage = 1;
            loadAuditLogs();
        });
    }

    const resetButton = document.getElementById('audit-reset-filters');
    if (resetButton) {
        resetButton.addEventListener('click', () => {
            resetFilters();
            auditCurrentPage = 1;
            loadAuditLogs();
        });
    }

    document.querySelectorAll('[data-audit-pagination-action="prev"]').forEach((previousPageButton) => {
        previousPageButton.addEventListener('click', () => {
            if (auditCurrentPage <= 1) {
                return;
            }

            auditCurrentPage -= 1;
            loadAuditLogs();
        });
    });

    document.querySelectorAll('[data-audit-pagination-action="next"]').forEach((nextPageButton) => {
        nextPageButton.addEventListener('click', () => {
            if (auditCurrentPage >= auditTotalPages) {
                return;
            }

            auditCurrentPage += 1;
            loadAuditLogs();
        });
    });

    document.querySelectorAll('[data-audit-pagination-role="list"]').forEach((pageList) => {
        pageList.addEventListener('click', (event) => {
            const pageButton = event.target.closest('[data-audit-page]');
            if (!pageButton) {
                return;
            }

            const requestedPage = Number.parseInt(pageButton.dataset.auditPage, 10);
            if (!Number.isInteger(requestedPage) || requestedPage < 1 || requestedPage > auditTotalPages) {
                return;
            }

            auditCurrentPage = requestedPage;
            loadAuditLogs();
        });
    });

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
                    auditCurrentPage = 1;
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
        page: auditCurrentPage,
        limit: AUDIT_ROWS_PER_PAGE,
        scope: 'me',
    };
}

async function loadAuditLogs() {
    const tbody = document.getElementById('audit-logs-tbody');
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">Loading audit logs...</td></tr>';
    }

    setAuditPaginationLoading();

    try {
        const response = await apiClient.getAuditLogs(buildAuditFilters());
        auditLogs = Array.isArray(response?.logs) ? response.logs : [];
        auditCurrentPage = Number(response?.page) || auditCurrentPage;
        auditTotalPages = Math.max(Number(response?.totalPages) || 1, 1);
        auditTotalRecords = Math.max(Number(response?.total) || 0, 0);
        renderAuditLogs(auditLogs);
        renderAuditPagination();
    } catch (error) {
        console.error('Error loading audit logs:', error);
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Failed to load audit logs</td></tr>';
        }
        auditLogs = [];
        auditTotalPages = 1;
        auditTotalRecords = 0;
        renderAuditPagination();
        showNotification('Unable to load audit logs', 'error');
    }
}

function renderAuditPagination() {
    const paginationControls = getAuditPaginationControls();

    const model = buildPaginationModel(auditCurrentPage, Math.max(auditTotalPages, 1));
    const pageMarkup = model.map((item) => {
        if (item === 'ellipsis') {
            return '<span class="table-pagination-ellipsis">...</span>';
        }

        const activeClass = item === auditCurrentPage ? ' is-active' : '';
        return `<button type="button" class="btn btn-secondary btn-sm table-pagination-number${activeClass}" data-audit-page="${item}" aria-label="Go to page ${item}" ${item === auditCurrentPage ? 'aria-current="page"' : ''}>${item}</button>`;
    }).join('');

    paginationControls.forEach(({ infoEl, previousButton, nextButton, pageList }) => {
        if (infoEl) {
            infoEl.classList.remove('table-pagination-info-skeleton');
            const totalPages = Math.max(auditTotalPages, 1);
            if (auditTotalRecords === 0) {
                infoEl.textContent = 'No records';
            } else {
                infoEl.textContent = `Page ${auditCurrentPage} of ${totalPages} (${auditTotalRecords} total)`;
            }
        }

        if (previousButton) {
            previousButton.disabled = auditCurrentPage <= 1;
        }

        if (nextButton) {
            nextButton.disabled = auditCurrentPage >= auditTotalPages || auditTotalRecords === 0;
        }

        if (pageList) {
            pageList.innerHTML = pageMarkup;
        }
    });
}

function setAuditPaginationLoading() {
    const paginationControls = getAuditPaginationControls();

    paginationControls.forEach(({ infoEl, previousButton, nextButton, pageList }) => {
        if (infoEl) {
            infoEl.textContent = '\u00A0';
            infoEl.classList.add('table-pagination-info-skeleton');
        }

        if (previousButton) {
            previousButton.disabled = true;
        }

        if (nextButton) {
            nextButton.disabled = true;
        }

        if (pageList) {
            pageList.innerHTML = [
                '<span class="table-pagination-number table-pagination-number-skeleton"></span>',
                '<span class="table-pagination-number table-pagination-number-skeleton"></span>',
                '<span class="table-pagination-number table-pagination-number-skeleton"></span>',
            ].join('');
        }
    });
}

function buildPaginationModel(currentPage, totalPages) {
    // Compact pagination keeps the control stable for large result sets while preserving
    // jump access to first/last pages.
    if (totalPages <= 7) {
        return Array.from({ length: totalPages }, (_, index) => index + 1);
    }

    if (currentPage <= 4) {
        return [1, 2, 3, 4, 5, 'ellipsis', totalPages];
    }

    if (currentPage >= totalPages - 3) {
        return [1, 'ellipsis', totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
    }

    return [1, 'ellipsis', currentPage - 1, currentPage, currentPage + 1, 'ellipsis', totalPages];
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
        // Escape all server-provided fields because audit values may include free-form text.
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
