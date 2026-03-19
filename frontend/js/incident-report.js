/**
 * Incident Report Handler
 */

let assets = [];

document.addEventListener('DOMContentLoaded', () => {
    initializeIncidentReport();
});

async function initializeIncidentReport() {
    if (!apiClient.isAuthenticated()) {
           window.location.href = 'index.html';
        return;
    }

    setupUserInfo();
    setupLogoutButton();
    await loadAssets();
    setupEventListeners();
}

function setupEventListeners() {
    const form = document.getElementById('incident-report-form');
    if (form) {
        form.addEventListener('submit', handleIncidentSubmit);
    }

    const descriptionArea = document.getElementById('incident-description');
    if (descriptionArea) {
        descriptionArea.addEventListener('input', updateCharCount);
    }

    // Set current time
    const timeInput = document.getElementById('when-happened');
    if (timeInput) {
        const now = new Date();
        const offset = now.getTimezoneOffset() * 60000;
        const localTime = new Date(now - offset).toISOString().slice(0, 16);
        timeInput.value = localTime;
    }

    // Modal close buttons
    document.querySelectorAll('[id$="-overlay"]').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                e.target.parentElement.style.display = 'none';
            }
        });
    });
}

async function loadAssets() {
    try {
        assets = await apiClient.getAssets();
        populateAssetDropdown();
    } catch (error) {
        console.error('Error loading assets:', error);
    }
}

function populateAssetDropdown() {
    const select = document.getElementById('affected-asset');
    select.innerHTML = '<option value="">Select the affected asset</option>';

    assets.forEach(asset => {
        const option = document.createElement('option');
        option.value = asset._id;
        option.textContent = `${asset.assetName} (${asset.assetType})`;
        select.appendChild(option);
    });
}

function updateCharCount() {
    const textarea = document.getElementById('incident-description');
    const charCount = textarea.value.length;
    document.getElementById('char-count').textContent = charCount;
}

async function handleIncidentSubmit(e) {
    e.preventDefault();

    const assetId = document.getElementById('affected-asset').value;
    const description = document.getElementById('incident-description').value;
    const incidentTime = document.getElementById('when-happened').value;
    const guestAffected = document.getElementById('guest-affected').checked;
    const sensitiveDataInvolved = document.getElementById('data-involved').checked;

    // Validate
    if (!assetId) {
        showNotification('Please select an affected asset', 'warning');
        return;
    }

    if (!description || description.trim().length < 20) {
        showNotification('Please provide a detailed description (at least 20 characters)', 'warning');
        return;
    }

    // Show analysis modal
    showModal('analysis-modal');
    updateAnalysisStatus('Submitting your report...');

    try {
        // Create incident
        const incidentData = {
            assetId,
            description,
            incidentTime,
            guestAffected,
            sensitiveDataInvolved,
        };

        const incident = await apiClient.createIncident(incidentData);

        updateAnalysisStatus('AI is analyzing your incident description...');

        // Analyze threat
        const analysis = await apiClient.analyzeThreat(description);

        updateAnalysisStatus('Calculating risk assessment...');

        // Get full incident details
        const fullIncident = await apiClient.getIncident(incident._id);

        // Show success modal
        hideModal('analysis-modal');
        showSuccessModal(fullIncident, analysis);

    } catch (error) {
        console.error('Error submitting incident:', error);
        hideModal('analysis-modal');
        showNotification('Error submitting incident: ' + error.message, 'error');
    }
}

function updateAnalysisStatus(message) {
    const statusEl = document.getElementById('analysis-status');
    if (statusEl) {
        statusEl.textContent = message;
    }
    
    const progressFill = document.getElementById('progress-fill');
    if (progressFill) {
        progressFill.style.width = (Math.random() * 80 + 20) + '%';
    }
}

function showSuccessModal(incident, analysis) {
    document.getElementById('success-incident-id').textContent = incident.incidentId;
    document.getElementById('success-threat-type').textContent = analysis.threatType;
    document.getElementById('success-risk-level').textContent = incident.riskLevel;

    showModal('success-modal');

    // Setup buttons
    const backBtn = document.getElementById('back-to-form');
    const viewBtn = document.getElementById('view-details');

    if (backBtn) {
        backBtn.onclick = () => {
            hideModal('success-modal');
            document.getElementById('incident-report-form').reset();
            updateCharCount();
        };
    }

    if (viewBtn) {
        viewBtn.onclick = () => {
            window.location.href = `incident-logs.html?id=${incident._id}`;
        };
    }
}

function setupUserInfo() {
    const user = getLocalStorage('user');
    if (user) {
        document.getElementById('user-name').textContent = user.fullName || user.email;
    }
}

function setupLogoutButton() {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
}