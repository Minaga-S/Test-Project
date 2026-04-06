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

    const query = new URLSearchParams(window.location.search);
    const incidentId = query.get('id');
    if (incidentId) {
        await viewIncidentDetails(incidentId);
    }
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
    showLoading(true);
    renderTableSkeleton('incidents-tbody', 8, 4);

    try {
        incidents = await apiClient.getIncidents();
        displayIncidents(incidents);
    } catch (error) {
        console.error('Error loading incidents:', error);
        showNotification('Error loading incidents', 'error');
    } finally {
        showLoading(false);
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

        row.innerHTML = `
            <td data-label="Select"><input type="checkbox" class="incident-select" data-incident-id="${incident._id}" ${isSelected ? 'checked' : ''} aria-label="Select ${incident.incidentId}"></td>
            <td data-label="Incident ID">${incident.incidentId}</td>
            <td data-label="Asset">${incident.asset?.assetName || 'Unknown'}</td>
            <td data-label="Threat Type">${incident.threatType}</td>
            <td data-label="Risk Level"><span style="color: ${getRiskColor(incident.riskLevel)}; font-weight: 600;">${incident.riskLevel}</span></td>
            <td data-label="Status"><span class="status-badge status-${incident.status.toLowerCase()}">${incident.status}</span></td>
            <td data-label="Date">${formatDate(incident.createdAt)}</td>
            <td data-label="Actions">
                <div class="row-actions">
                    <button class="btn btn-sm btn-secondary" onclick="viewIncidentDetails('${incident._id}')">View</button>
                </div>
            </td>
        `;

        row.addEventListener('click', (event) => {
            if (event.target.closest('.incident-select') || event.target.closest('button')) {
                return;
            }
            viewIncidentDetails(incident._id);
        });

        tbody.appendChild(row);
    });

    tbody.querySelectorAll('.incident-select').forEach((checkbox) => {
        checkbox.addEventListener('change', (event) => {
            const incidentId = event.target.dataset.incidentId;
            if (event.target.checked) {
                selectedIncidentIds.add(incidentId);
            } else {
                selectedIncidentIds.delete(incidentId);
            }
            updateIncidentSelectionState();
        });
    });

    updateIncidentSelectionState();
}

function updateIncidentSelectionState() {
    const selectedCountEl = document.getElementById('selected-incidents-count');
    if (selectedCountEl) {
        selectedCountEl.textContent = `${selectedIncidentIds.size} selected`;
    }

    const selectAllBtn = document.getElementById('select-all-incidents-btn');
    if (selectAllBtn) {
        const visibleCheckboxes = Array.from(document.querySelectorAll('.incident-select'));
        const allVisibleSelected = visibleCheckboxes.length > 0 && visibleCheckboxes.every((checkbox) => checkbox.checked);
        selectAllBtn.textContent = allVisibleSelected ? 'Unselect All' : 'Select All';
    }

    const deleteAllBtn = document.getElementById('delete-all-incidents-btn');
    if (deleteAllBtn) {
        deleteAllBtn.textContent = 'Delete';
    }
}

function handleSelectAllIncidentsClick() {
    const visibleCheckboxes = Array.from(document.querySelectorAll('.incident-select'));
    const allVisibleSelected = visibleCheckboxes.length > 0 && visibleCheckboxes.every((checkbox) => checkbox.checked);
    const shouldSelectAll = !allVisibleSelected;

    visibleCheckboxes.forEach((checkbox) => {
        checkbox.checked = shouldSelectAll;
        const incidentId = checkbox.dataset.incidentId;
        if (shouldSelectAll) {
            selectedIncidentIds.add(incidentId);
        } else {
            selectedIncidentIds.delete(incidentId);
        }
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

function displayIncidentDetails(incident) {
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
        .map((rec) => `<div class="recommendation-item"><strong>•</strong> ${rec}</div>`)
        .join('');

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
        .map((incident) => ({
            'Incident ID': incident.incidentId,
            Asset: incident.asset?.assetName || 'Unknown',
            'Threat Type': incident.threatType,
            'Risk Level': incident.riskLevel,
            Status: incident.status,
            Date: formatDate(incident.createdAt),
            'Risk Score': incident.riskScore,
        }));

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