/**
 * Incident Logs Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.
/**
 * SECTION GUIDE:
 * 1) Logs Boot: validates auth and fetches incident history.
 * 2) Filtering/Search: narrows incident list by status/type/text.
 * 3) Detail View: opens selected incident context and metadata.
 * 4) Updates: applies status or note changes and refreshes list.
 */



let incidents = [];

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
    renderTableSkeleton('incidents-tbody', 7, 4);

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
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No incidents found</td></tr>';
        return;
    }

    incidentsToDisplay.forEach(incident => {
        const row = document.createElement('tr');
        row.style.cursor = 'pointer';
        row.innerHTML = `
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
        row.addEventListener('click', () => viewIncidentDetails(incident._id));
        tbody.appendChild(row);
    });
}

function filterIncidents() {
    const searchQuery = document.getElementById('search-incidents').value.toLowerCase();
    const threatFilter = document.getElementById('filter-threat-type').value;
    const statusFilter = document.getElementById('filter-status').value;
    const riskFilter = document.getElementById('filter-risk-level').value;

    const filtered = incidents.filter(incident => {
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

    // Risk assessment
    document.getElementById('detail-likelihood-fill').style.width = (incident.likelihood * 25) + '%';
    document.getElementById('detail-impact-fill').style.width = (incident.impact * 25) + '%';
    document.getElementById('detail-likelihood').textContent = incident.likelihood + '/4';
    document.getElementById('detail-impact').textContent = incident.impact + '/4';
    
    const riskScoreEl = document.getElementById('detail-risk-score');
    animateCountUp(riskScoreEl, incident.riskScore || 0, 800);
    riskScoreEl.style.color = getRiskColor(incident.riskLevel);
    
    document.getElementById('detail-risk-level').textContent = incident.riskLevel;
    document.getElementById('detail-risk-level').style.color = getRiskColor(incident.riskLevel);

    // NIST mapping
    const nistFunctions = document.getElementById('detail-nist-functions');
    nistFunctions.innerHTML = (incident.nistFunctions || [])
        .map(f => `<span class="nist-tag">${f}</span>`)
        .join('');

    const nistControls = document.getElementById('detail-nist-controls');
    nistControls.innerHTML = (incident.nistControls || [])
        .map(c => `<span class="nist-tag">${c}</span>`)
        .join('');

    // Recommendations
    const recommendationsEl = document.getElementById('detail-recommendations');
    recommendationsEl.innerHTML = (incident.recommendations || [])
        .map(rec => `<div class="recommendation-item"><strong>•</strong> ${rec}</div>`)
        .join('');

    // Update form
    document.getElementById('update-status').value = incident.status;
    document.getElementById('update-notes').value = '';

    // Store current incident ID
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

function exportIncidents() {
    const data = incidents.map(incident => ({
        'Incident ID': incident.incidentId,
        'Asset': incident.asset?.assetName || 'Unknown',
        'Threat Type': incident.threatType,
        'Risk Level': incident.riskLevel,
        'Status': incident.status,
        'Date': formatDate(incident.createdAt),
        'Risk Score': incident.riskScore,
    }));

    exportToCSV('incidents-report.csv', data);
    showNotification('Report exported successfully', 'success');
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

