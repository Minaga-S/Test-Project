/**
 * Incident Logs Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.

let incidents = [];
let selectedIncidentIds = new Set();
let pendingDeleteIncidentIds = [];

document.addEventListener('DOMContentLoaded', () => {
    initializeIncidentLogs();
});

async function initializeIncidentLogs() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }

    setupUserInfo();
    setupLogoutButton();
    setupEventListeners();
    await loadIncidents();

    await openIncidentFromNavigationHint();
}

async function openIncidentFromNavigationHint() {
    const query = new URLSearchParams(window.location.search);
    const queryTarget = {
        incidentDbId: query.get('id'),
        incidentPublicId: query.get('incidentId'),
    };

    const storedTarget = readStoredIncidentOpenTarget();
    const navigationTarget = {
        incidentDbId: queryTarget.incidentDbId || storedTarget?.incidentDbId || '',
        incidentPublicId: queryTarget.incidentPublicId || storedTarget?.incidentPublicId || '',
    };

    if (!navigationTarget.incidentDbId && !navigationTarget.incidentPublicId) {
        return;
    }

    const didOpenIncident = await openIncidentFromQuery(navigationTarget);

    if (!didOpenIncident) {
        return;
    }

    clearStoredIncidentOpenTarget();

    if (window.location.search) {
        window.history.replaceState({}, document.title, window.location.pathname);
    }
}
function readStoredIncidentOpenTarget() {
    try {
        const stored = sessionStorage.getItem('incidentLogs:openTarget');
        if (!stored) {
            return null;
        }

        const parsed = JSON.parse(stored);
        const isStale = Number(parsed?.createdAt || 0) < (Date.now() - 10 * 60 * 1000);
        if (isStale) {
            clearStoredIncidentOpenTarget();
            return null;
        }

        return parsed;
    } catch (error) {
        console.warn('Unable to read incident open target from session storage:', error);
        return null;
    }
}

function clearStoredIncidentOpenTarget() {
    try {
        sessionStorage.removeItem('incidentLogs:openTarget');
    } catch (error) {
        console.warn('Unable to clear incident open target from session storage:', error);
    }
}

async function openIncidentFromQuery(params = {}) {
    const normalizedDbId = String(params.incidentDbId || '').trim();
    const normalizedPublicId = String(params.incidentPublicId || '').trim();

    if (!normalizedDbId && !normalizedPublicId) {
        return false;
    }

    const targetIncident = incidents.find((incident) =>
        incident._id === normalizedDbId || incident.incidentId === normalizedPublicId || incident.incidentId === normalizedDbId
    );

    if (targetIncident?._id) {
        await viewIncidentDetails(targetIncident._id);
        return true;
    }

    if (normalizedPublicId) {
        try {
            const searchResponse = await apiClient.searchIncidents(normalizedPublicId);
            const matchedIncidents = Array.isArray(searchResponse?.incidents)
                ? searchResponse.incidents
                : (Array.isArray(searchResponse) ? searchResponse : []);
            const exactMatch = matchedIncidents.find((incident) => incident.incidentId === normalizedPublicId);
            if (exactMatch?._id) {
                await viewIncidentDetails(exactMatch._id);
                return true;
            }
        } catch (error) {
            console.warn('Unable to resolve incident by public id:', error);
        }
    }

    if (normalizedDbId) {
        try {
            await viewIncidentDetails(normalizedDbId);
            return true;
        } catch (error) {
            console.warn('Unable to open incident by DB id from navigation hint:', error);
        }
    }

    return false;
}
function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function normalizeRecommendationText(rawText) {
    const collapsedText = String(rawText || '').replace(/\s+/g, ' ').trim();
    if (!collapsedText) {
        return '';
    }

    if (/^\[[^\]]+\]\s+/.test(collapsedText)) {
        return collapsedText;
    }

    let normalizedText = collapsedText.replace(/\s+['"]no$/i, ' no critical findings reported');

    if (/['"]$/.test(normalizedText)) {
        normalizedText = normalizedText.slice(0, -1).trim();
    }

    if (!/[.!?]$/.test(normalizedText)) {
        normalizedText = `${normalizedText}.`;
    }

    return normalizedText;
}

function renderRecommendationWithSourceTag(recommendationText) {
    const normalizedText = normalizeRecommendationText(recommendationText);
    const tagMatch = normalizedText.match(/^\[([^\]]+)\]\s*(.*)$/);

    if (!tagMatch) {
        return `<div class="recommendation-item"><p class="recommendation-body">${escapeHtml(normalizedText)}</p></div>`;
    }

    const nistLabel = tagMatch[1].trim();
    const message = (tagMatch[2] || '').trim();

    return `<div class="recommendation-item"><div class="recommendation-label-row"><span class="nist-tag">${escapeHtml(nistLabel)}</span></div><p class="recommendation-body">${escapeHtml(message)}</p></div>`;
}

function getIncidentCveMatches(incident) {
    if (Array.isArray(incident?.cveMatches) && incident.cveMatches.length > 0) {
        return incident.cveMatches;
    }

    if (Array.isArray(incident?.securityContext?.cve?.matches) && incident.securityContext.cve.matches.length > 0) {
        return incident.securityContext.cve.matches;
    }

    return [];
}

const CVE_SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

function normalizeCveSeverity(entry) {
    const rawSeverity = String(entry?.severity || '').trim().toUpperCase();
    if (CVE_SEVERITY_ORDER.includes(rawSeverity)) {
        return rawSeverity;
    }

    const score = Number(entry?.cvssScore);
    if (!Number.isFinite(score)) {
        return 'UNKNOWN';
    }

    if (score >= 9.0) {
        return 'CRITICAL';
    }

    if (score >= 7.0) {
        return 'HIGH';
    }

    if (score >= 4.0) {
        return 'MEDIUM';
    }

    return 'LOW';
}

function buildCveCategories(cveMatches) {
    const grouped = cveMatches.reduce((accumulator, entry) => {
        const severity = normalizeCveSeverity(entry);
        if (!accumulator[severity]) {
            accumulator[severity] = [];
        }

        accumulator[severity].push(entry);
        return accumulator;
    }, {});

    return CVE_SEVERITY_ORDER
        .map((severity) => ({ severity, entries: grouped[severity] || [] }))
        .filter((group) => group.entries.length > 0);
}

function renderIncidentCveDetails(incident) {
    const securityContext = incident?.securityContext || {};
    const enrichment = securityContext?.enrichment || {};
    const cve = securityContext?.cve || {};
    const cveMatches = getIncidentCveMatches(incident);

    const sourceEl = document.getElementById('detail-enrichment-source');
    const confidenceEl = document.getElementById('detail-enrichment-confidence');
    const enrichedAtEl = document.getElementById('detail-enriched-at');
    const countEl = document.getElementById('detail-cve-count');
    const cvePanel = document.getElementById('detail-cve-panel');
    const listEl = document.getElementById('detail-cve-list');

    if (sourceEl) {
        sourceEl.textContent = enrichment.source || cve.source || 'NIST NVD API';
    }

    if (confidenceEl) {
        confidenceEl.textContent = enrichment.confidence || cve.confidence || 'N/A';
    }

    if (enrichedAtEl) {
        const enrichedAt = enrichment.lastEnrichedAt || cve.retrievedAt || '';
        enrichedAtEl.textContent = enrichedAt ? formatDateTime(enrichedAt) : 'N/A';
    }

    if (countEl) {
        countEl.textContent = String(cveMatches.length);
    }

    if (cvePanel) {
        cvePanel.open = false;
    }

    if (!listEl) {
        return;
    }

    if (cveMatches.length === 0) {
        listEl.innerHTML = '<div class="recommendation-item">No CVE matches were attached to this incident.</div>';
        return;
    }

    const categorizedMatches = buildCveCategories(cveMatches);

    listEl.innerHTML = categorizedMatches.map((group) => {
        const severityClass = group.severity.toLowerCase();
        const cveItems = group.entries.map((entry) => {
            const cveId = entry.cveId || entry.id || 'Unknown CVE';
            const normalizedSeverity = normalizeCveSeverity(entry);
            const score = entry.cvssScore !== undefined && entry.cvssScore !== null ? entry.cvssScore : 'N/A';
            const published = entry.published ? formatDate(entry.published) : 'N/A';
            const description = entry.description || entry.title || 'No additional description available.';

            return `<details class="recommendation-item cve-item"><summary><span class="cve-summary-id">${escapeHtml(cveId)}</span><span class="cve-summary-meta">Severity: ${escapeHtml(normalizedSeverity)} | CVSS: ${escapeHtml(score)} | Published: ${escapeHtml(published)}</span></summary><p>${escapeHtml(description)}</p></details>`;
        }).join('');

        return `<details class="cve-category cve-category-${severityClass}"><summary><span class="cve-category-header-main"><span class="cve-category-title">${escapeHtml(group.severity)}</span><span class="cve-category-count">${group.entries.length} ${group.entries.length === 1 ? 'CVE' : 'CVEs'}</span><span class="cve-category-toggle" aria-hidden="true"></span></span></summary><div class="cve-category-items">${cveItems}</div></details>`;
    }).join('');
}

function setupEventListeners() {
    const searchInput = document.getElementById('search-incidents');
    if (searchInput) {
        searchInput.addEventListener('input', filterIncidents);
    }

    const filterThreat = document.getElementById('filter-threat-type');
    if (filterThreat) {
        filterThreat.addEventListener('change', filterIncidents);
    }

    const filterStatus = document.getElementById('filter-status');
    if (filterStatus) {
        filterStatus.addEventListener('change', filterIncidents);
    }

    const filterRisk = document.getElementById('filter-risk-level');
    if (filterRisk) {
        filterRisk.addEventListener('change', filterIncidents);
    }

    const exportBtn = document.getElementById('export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportIncidents);
    }

    const selectAllIncidentsBtn = document.getElementById('select-all-incidents-btn');
    if (selectAllIncidentsBtn) {
        selectAllIncidentsBtn.addEventListener('click', handleSelectAllIncidentsClick);
    }

    const deleteAllIncidentsBtn = document.getElementById('delete-all-incidents-btn');
    if (deleteAllIncidentsBtn) {
        deleteAllIncidentsBtn.addEventListener('click', handleBulkDeleteIncidents);
    }

    const deleteConfirm = document.getElementById('delete-confirm');
    if (deleteConfirm) {
        deleteConfirm.addEventListener('click', confirmDeleteIncidents);
    }

    const deleteCancel = document.getElementById('delete-cancel');
    if (deleteCancel) {
        deleteCancel.addEventListener('click', closeDeleteModal);
    }

    const deleteOverlay = document.getElementById('delete-overlay');
    if (deleteOverlay) {
        deleteOverlay.addEventListener('click', closeDeleteModal);
    }

    const detailClose = document.getElementById('detail-close');
    if (detailClose) {
        detailClose.addEventListener('click', closeDetailModal);
    }

    const detailOverlay = document.getElementById('detail-overlay');
    if (detailOverlay) {
        detailOverlay.addEventListener('click', closeDetailModal);
    }

    const saveUpdateBtn = document.getElementById('save-update');
    if (saveUpdateBtn) {
        saveUpdateBtn.addEventListener('click', saveIncidentUpdate);
    }
}

async function loadIncidents() {
    renderTableSkeleton('incidents-tbody', 8, 4);

    try {
        incidents = await apiClient.getIncidents();
        displayIncidents(incidents);
    } catch (error) {
        console.error('Error loading incidents:', error);
        showNotification('Error loading incidents', 'error');
    }
}

function displayIncidents(incidentsToDisplay) {
    const tbody = document.getElementById('incidents-tbody');
    tbody.innerHTML = '';

    if (!incidentsToDisplay || incidentsToDisplay.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No incidents found</td></tr>';
        updateIncidentSelectionState();
        return;
    }

    incidentsToDisplay.forEach((incident) => {
        const row = document.createElement('tr');
        row.style.cursor = 'pointer';
        const isSelected = selectedIncidentIds.has(incident._id);
        const selectButtonLabel = isSelected ? 'Unselect' : 'Select';

        row.innerHTML = `
            <td data-label="Select"><button type="button" class="btn btn-sm incident-select-btn ${isSelected ? 'is-selected' : ''}" data-incident-id="${incident._id}" aria-label="Select ${incident.incidentId}" aria-pressed="${isSelected ? 'true' : 'false'}">${selectButtonLabel}</button></td>
            <td data-label="Incident ID">${incident.incidentId}</td>
            <td data-label="Asset">${incident.asset?.assetName || 'Unknown'}</td>
            <td data-label="Threat Type">${incident.threatType}</td>
            <td data-label="Risk Level"><span style="color: ${getRiskColor(incident.riskLevel)}; font-weight: 600;">${incident.riskLevel}</span></td>
            <td data-label="Status"><span class="status-badge status-${incident.status.toLowerCase()}">${incident.status}</span></td>
            <td data-label="Date">${formatDate(incident.createdAt)}</td>
            <td data-label="Actions">
                <div class="row-actions">
                    <button class="btn btn-sm btn-secondary" onclick="viewIncidentDetails('${incident._id}')">View</button>
                    <button class="btn btn-sm btn-danger" onclick="openDeleteIncidentModal('${incident._id}')">Delete</button>
                </div>
            </td>
        `;

        row.addEventListener('click', (event) => {
            if (event.target.closest('.incident-select-btn') || event.target.closest('button')) {
                return;
            }
            viewIncidentDetails(incident._id);
        });

        tbody.appendChild(row);
    });

    tbody.querySelectorAll('.incident-select-btn').forEach((selectButton) => {
        selectButton.addEventListener('click', (event) => {
            const incidentId = event.currentTarget.dataset.incidentId;
            const isSelected = selectedIncidentIds.has(incidentId);

            if (isSelected) {
                selectedIncidentIds.delete(incidentId);
            } else {
                selectedIncidentIds.add(incidentId);
            }

            updateIncidentSelectButtonState(event.currentTarget, !isSelected);
            updateIncidentSelectionState();
        });
    });

    updateIncidentSelectionState();
}

function updateIncidentSelectButtonState(selectButton, isSelected) {
    if (!selectButton) {
        return;
    }

    selectButton.classList.toggle('is-selected', isSelected);
    selectButton.textContent = isSelected ? 'Unselect' : 'Select';
    selectButton.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
}

function updateIncidentSelectionState() {
    const selectedCountEl = document.getElementById('selected-incidents-count');
    if (selectedCountEl) {
        selectedCountEl.textContent = `${selectedIncidentIds.size} selected`;
    }

    const selectAllBtn = document.getElementById('select-all-incidents-btn');
    if (selectAllBtn) {
        const visibleSelectButtons = Array.from(document.querySelectorAll('.incident-select-btn'));
        const allVisibleSelected = visibleSelectButtons.length > 0 && visibleSelectButtons.every((button) => selectedIncidentIds.has(button.dataset.incidentId));
        selectAllBtn.textContent = allVisibleSelected ? 'Unselect All' : 'Select All';
    }

    const deleteAllBtn = document.getElementById('delete-all-incidents-btn');
    if (deleteAllBtn) {
        deleteAllBtn.textContent = 'Delete';
    }
}

function handleSelectAllIncidentsClick() {
    const visibleSelectButtons = Array.from(document.querySelectorAll('.incident-select-btn'));
    const allVisibleSelected = visibleSelectButtons.length > 0 && visibleSelectButtons.every((button) => selectedIncidentIds.has(button.dataset.incidentId));
    const shouldSelectAll = !allVisibleSelected;

    visibleSelectButtons.forEach((button) => {
        const incidentId = button.dataset.incidentId;
        if (shouldSelectAll) {
            selectedIncidentIds.add(incidentId);
        } else {
            selectedIncidentIds.delete(incidentId);
        }

        updateIncidentSelectButtonState(button, shouldSelectAll);
    });

    updateIncidentSelectionState();
}

async function handleBulkDeleteIncidents() {
    if (selectedIncidentIds.size === 0) {
        showNotification('Select at least one incident to delete', 'warning');
        return;
    }

    pendingDeleteIncidentIds = Array.from(selectedIncidentIds);
    setDeleteConfirmationMessage(`Delete ${pendingDeleteIncidentIds.length} selected incidents? This action cannot be undone.`);
    showModal('delete-modal');
}

function filterIncidents() {
    const searchQuery = document.getElementById('search-incidents').value.toLowerCase();
    const threatFilter = document.getElementById('filter-threat-type').value;
    const statusFilter = document.getElementById('filter-status').value;
    const riskFilter = document.getElementById('filter-risk-level').value;

    const filtered = incidents.filter((incident) => {
        const matchesSearch = incident.incidentId.toLowerCase().includes(searchQuery) ||
            incident.threatType.toLowerCase().includes(searchQuery) ||
            incident.asset?.assetName.toLowerCase().includes(searchQuery);
        const matchesThreat = !threatFilter || incident.threatType === threatFilter;
        const matchesStatus = !statusFilter || incident.status === statusFilter;
        const matchesRisk = !riskFilter || incident.riskLevel === riskFilter;

        return matchesSearch && matchesThreat && matchesStatus && matchesRisk;
    });

    displayIncidents(filtered);
}

async function viewIncidentDetails(incidentId) {
    showLoading(true);

    try {
        const incident = await apiClient.getIncident(incidentId);
        displayIncidentDetails(incident);
        showModal('detail-modal');
    } catch (error) {
        console.error('Error loading incident details:', error);
        showNotification('Error loading incident details', 'error');
    } finally {
        showLoading(false);
    }
}

async function confirmDeleteIncidents() {
    showLoading(true);

    try {
        const incidentIds = Array.from(pendingDeleteIncidentIds);
        const deleteResults = await Promise.allSettled(incidentIds.map((incidentId) => apiClient.deleteIncident(incidentId)));
        const deletedCount = deleteResults.filter((result) => result.status === 'fulfilled').length;
        const failedCount = deleteResults.length - deletedCount;

        pendingDeleteIncidentIds.forEach((incidentId) => selectedIncidentIds.delete(incidentId));
        updateIncidentSelectionState();
        closeDeleteModal();
        await loadIncidents();

        if (failedCount > 0) {
            showNotification(`Deleted ${deletedCount} incidents, ${failedCount} failed`, 'warning');
        } else {
            showNotification(`Deleted ${deletedCount} incidents successfully`, 'success');
        }
    } catch (error) {
        console.error('Bulk delete incidents error:', error);
        showNotification('Bulk delete failed', 'error');
    } finally {
        showLoading(false);
    }
}

function openDeleteIncidentModal(incidentId) {
    pendingDeleteIncidentIds = [incidentId];
    setDeleteConfirmationMessage('Delete this incident? This action cannot be undone.');
    showModal('delete-modal');
}
function displayIncidentDetails(incident) {
    const securityContext = incident.securityContext || {};
    const liveScan = securityContext.liveScan || {};
    const clientReportedLiveScan = securityContext?.clientReported?.liveScan || {};
    const scanTarget = String(liveScan.target || incident.asset?.liveScan?.target || '').trim() || 'N/A';
    const openPorts = Array.isArray(liveScan.observedOpenPorts) && liveScan.observedOpenPorts.length > 0
        ? liveScan.observedOpenPorts
        : (Array.isArray(clientReportedLiveScan.observedOpenPorts) ? clientReportedLiveScan.observedOpenPorts : []);
    const openPortsText = openPorts.length > 0 ? openPorts.join(', ') : 'None identified';
    const cveQuery = securityContext?.cve?.query || {};
    const clientReportedCveQuery = securityContext?.clientReported?.cve?.query || {};
    const osInfo = String(liveScan.osInfo || clientReportedLiveScan.osInfo || cveQuery.osName || clientReportedCveQuery.osName || '').trim() || 'N/A';
    const cpeUri = String(cveQuery.cpeUri || clientReportedCveQuery.cpeUri || '').trim() || 'N/A';

    document.getElementById('detail-incident-id').textContent = incident.incidentId;
    document.getElementById('detail-status').textContent = incident.status;
    document.getElementById('detail-reporter').textContent = incident.reportedBy || 'System';
    document.getElementById('detail-date').textContent = formatDateTime(incident.createdAt);
    document.getElementById('detail-description').textContent = incident.description;

    document.getElementById('detail-threat-type').textContent = incident.threatType;
    document.getElementById('detail-threat-category').textContent = incident.threatCategory || 'N/A';
    document.getElementById('detail-affected-asset').textContent = incident.asset?.assetName || 'Unknown';
    document.getElementById('detail-confidence').textContent = (incident.confidence || 0) + '%';

    document.getElementById('detail-likelihood-fill').style.width = (incident.likelihood * 25) + '%';
    document.getElementById('detail-impact-fill').style.width = (incident.impact * 25) + '%';
    document.getElementById('detail-likelihood').textContent = incident.likelihood + '/4';
    document.getElementById('detail-impact').textContent = incident.impact + '/4';

    const riskScoreEl = document.getElementById('detail-risk-score');
    animateCountUp(riskScoreEl, incident.riskScore || 0, 800);
    riskScoreEl.style.color = getRiskColor(incident.riskLevel);

    document.getElementById('detail-risk-level').textContent = incident.riskLevel;
    document.getElementById('detail-risk-level').style.color = getRiskColor(incident.riskLevel);

    const nistFunctions = document.getElementById('detail-nist-functions');
    nistFunctions.innerHTML = (incident.nistFunctions || [])
        .map((f) => `<span class="nist-tag">${f}</span>`)
        .join('');

    const nistControls = document.getElementById('detail-nist-controls');
    nistControls.innerHTML = (incident.nistControls || [])
        .map((c) => `<span class="nist-tag">${c}</span>`)
        .join('');

    const recommendationsEl = document.getElementById('detail-recommendations');
    recommendationsEl.innerHTML = (incident.recommendations || [])
        .map((rec) => renderRecommendationWithSourceTag(rec))
        .join('');

    document.getElementById('detail-scanned-ip').textContent = scanTarget;
    document.getElementById('detail-open-ports').textContent = openPortsText;
    document.getElementById('detail-os-info').textContent = osInfo;
    document.getElementById('detail-cpe-uri').textContent = cpeUri;

    // Extract and display vendor, product, version, and services
    const vendor = String(cveQuery.vendor || clientReportedCveQuery.vendor || '').trim() || 'N/A';
    const product = String(cveQuery.product || clientReportedCveQuery.product || '').trim() || 'N/A';
    const productVersion = String(cveQuery.productVersion || clientReportedCveQuery.productVersion || '').trim() || 'N/A';
    const services = (liveScan.services || clientReportedLiveScan.services || []);
    const servicesText = services.length > 0
        ? [...new Set(services
            .map((service) => String(service?.service || '').trim())
            .filter(Boolean))].join(', ')
        : 'None identified';

    if (document.getElementById('detail-vendor')) {
        document.getElementById('detail-vendor').textContent = vendor;
    }
    if (document.getElementById('detail-product')) {
        document.getElementById('detail-product').textContent = product;
    }
    if (document.getElementById('detail-product-version')) {
        document.getElementById('detail-product-version').textContent = productVersion;
    }
    if (document.getElementById('detail-services')) {
        document.getElementById('detail-services').textContent = servicesText;
    }

    renderIncidentCveDetails(incident);

    document.getElementById('update-status').value = incident.status;
    document.getElementById('update-notes').value = '';

    window.currentIncidentId = incident._id;
}

async function saveIncidentUpdate() {
    const status = document.getElementById('update-status').value;
    const notes = document.getElementById('update-notes').value;

    showLoading(true);

    try {
        await apiClient.updateIncidentStatus(window.currentIncidentId, status);

        if (notes) {
            await apiClient.addIncidentNote(window.currentIncidentId, notes);
        }

        showNotification('Incident updated successfully', 'success');
        closeDetailModal();
        await loadIncidents();
    } catch (error) {
        console.error('Error updating incident:', error);
        showNotification('Error updating incident', 'error');
    } finally {
        showLoading(false);
    }
}

function closeDetailModal() {
    hideModal('detail-modal');
}

function closeDeleteModal() {
    hideModal('delete-modal');
    pendingDeleteIncidentIds = [];
}

function setDeleteConfirmationMessage(message) {
    const messageEl = document.getElementById('delete-confirmation-message');
    if (messageEl) {
        messageEl.textContent = message;
    }
}

function exportIncidents() {
    if (selectedIncidentIds.size === 0) {
        showNotification('Select at least one incident to export', 'warning');
        return;
    }

    const data = incidents
        .filter((incident) => selectedIncidentIds.has(incident._id))
        .map((incident) => {
            const securityContext = incident.securityContext || {};
            const enrichment = securityContext.enrichment || {};
            const liveScan = securityContext.liveScan || {};
            const cveMatches = getIncidentCveMatches(incident);
            const cveBySeverity = cveMatches.reduce((accumulator, cve) => {
                const severity = normalizeCveSeverity(cve);
                accumulator[severity] = (accumulator[severity] || 0) + 1;
                return accumulator;
            }, {});
            const normalizedRecommendations = (incident.recommendations || [])
                .map((rec) => normalizeRecommendationText(rec));

            return {
                'Incident ID': incident.incidentId,
                'Database ID': incident._id || '',
                'Asset Name': incident.asset?.assetName || 'Unknown',
                'Asset Type': incident.asset?.assetType || '',
                'Threat Type': incident.threatType,
                'Threat Category': incident.threatCategory || '',
                Confidence: incident.confidence || 0,
                Likelihood: incident.likelihood || 0,
                Impact: incident.impact || 0,
                'Risk Score': incident.riskScore,
                'Risk Level': incident.riskLevel,
                Status: incident.status,
                'Reported By': incident.reportedBy || 'System',
                'Date Reported': formatDateTime(incident.createdAt),
                'Incident Description': incident.description || '',
                'NIST Functions': (incident.nistFunctions || []).join(' | '),
                'NIST Controls': (incident.nistControls || []).join(' | '),
                'CVE Total': cveMatches.length,
                'CVE Critical': cveBySeverity.CRITICAL || 0,
                'CVE High': cveBySeverity.HIGH || 0,
                'CVE Medium': cveBySeverity.MEDIUM || 0,
                'CVE Low': cveBySeverity.LOW || 0,
                'CVE Unknown': cveBySeverity.UNKNOWN || 0,
                'Enrichment Source': enrichment.source || securityContext?.cve?.source || 'NIST NVD API',
                'Enrichment Confidence': enrichment.confidence || securityContext?.cve?.confidence || 'N/A',
                'Last Enriched': enrichment.lastEnrichedAt ? formatDateTime(enrichment.lastEnrichedAt) : '',
                'Scanned IP': String(liveScan.target || incident.asset?.liveScan?.target || '').trim(),
                'Observed Open Ports': Array.isArray(liveScan.observedOpenPorts) && liveScan.observedOpenPorts.length > 0
                    ? liveScan.observedOpenPorts.join(' | ')
                    : 'None identified',
                'CVE Query Terms': (securityContext?.cve?.query?.searchTerms || securityContext?.cve?.query?.queryCandidates || []).join(' | '),
                'Recommendations Count': normalizedRecommendations.length,
                Recommendations: normalizedRecommendations.join(' || '),
                'AI Model': incident.aiModel || '',
                'AI Version': incident.aiVersion || '',
                'AI Analyzed At': incident.aiAnalyzedAt ? formatDateTime(incident.aiAnalyzedAt) : '',
            };
        });

    exportToCSV('selected-incidents-report.csv', data);
    showNotification('Selected incidents exported successfully', 'success');
}

function setupUserInfo() {
    const user = getLocalStorage('user');
    const userNameEl = document.getElementById('user-name');
    if (user && userNameEl) {
        userNameEl.textContent = user.fullName || user.email;
    }
}

function setupLogoutButton() {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.type = 'button';
    }
}





