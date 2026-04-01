/**
 * Incident Report Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.
/**
 * SECTION GUIDE:
 * 1) Report Boot: loads assets and binds report form events.
 * 2) Validation: checks minimum fields before submit.
 * 3) Submit + Analysis UX: shows progress while backend analyzes text.
 * 4) Result Handling: displays success modal and next actions.
 */



let assets = [];
let progressTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    initializeIncidentReport();
});

async function initializeIncidentReport() {
    // Page boot flow: guard auth, load user context, then prepare form data and listeners.
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'login.html';
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

    const timeInput = document.getElementById('when-happened');
    if (timeInput) {
        const now = new Date();
        const offset = now.getTimezoneOffset() * 60000;
        const localTime = new Date(now - offset).toISOString().slice(0, 16);
        timeInput.value = localTime;
    }

    document.querySelectorAll('[id$="-overlay"]').forEach((overlay) => {
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

    assets.forEach((asset) => {
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

function setSubmitButtonState(isSubmitting) {
    const submitButton = document.querySelector('#incident-report-form button[type="submit"]');
    if (!submitButton) {
        return;
    }

    submitButton.disabled = isSubmitting;
    submitButton.textContent = isSubmitting ? 'Analyzing...' : 'Submit Report';
}

function beginAnalysisProgress() {
    // Simulated progress keeps users informed while backend AI analysis runs.
    stopAnalysisProgress();

    const progressFill = document.getElementById('progress-fill');
    let currentProgress = 12;

    updateAnalysisStatus('Submitting your report...', currentProgress);

    progressTimer = window.setInterval(() => {
        currentProgress = Math.min(currentProgress + Math.random() * 7, 92);
        updateAnalysisStatus('AI is analyzing your incident description...', currentProgress);
    }, 450);
}

function stopAnalysisProgress() {
    if (progressTimer) {
        window.clearInterval(progressTimer);
        progressTimer = null;
    }
}

async function handleIncidentSubmit(e) {
    // Submit flow: validate input, show analysis modal, send request, then display result modal.
    e.preventDefault();

    const assetId = String(document.getElementById('affected-asset').value || '').trim();
    const description = document.getElementById('incident-description').value;
    const incidentTime = document.getElementById('when-happened').value;
    const guestAffected = document.getElementById('guest-affected').checked;
    const sensitiveDataInvolved = document.getElementById('data-involved').checked;

    if (!assetId) {
        showNotification('Please select an affected asset', 'warning');
        return;
    }

    if (!description || description.trim().length < 20) {
        showNotification('Please provide a detailed description (at least 20 characters)', 'warning');
        return;
    }

    setSubmitButtonState(true);
    showModal('analysis-modal');
    beginAnalysisProgress();

    try {
        // Keep payload shape aligned with backend create-incident API contract.
        const incidentData = {
            assetId,
            description,
            incidentTime,
            guestAffected,
            sensitiveDataInvolved,
        };

        const incident = await apiClient.createIncident(incidentData);

        updateAnalysisStatus('Applying NIST framework mapping and recommendations...', 96);
        stopAnalysisProgress();
        updateAnalysisStatus('Analysis complete', 100);

        setTimeout(() => {
            hideModal('analysis-modal');
            showSuccessModal(incident);
        }, 220);
    } catch (error) {
        console.error('Error submitting incident:', error);
        stopAnalysisProgress();
        hideModal('analysis-modal');
        showNotification(`Error submitting incident: ${error.message}`, 'error');
    } finally {
        setSubmitButtonState(false);
    }
}

function updateAnalysisStatus(message, progressValue = null) {
    const statusEl = document.getElementById('analysis-status');
    if (statusEl) {
        statusEl.textContent = message;
    }

    const progressFill = document.getElementById('progress-fill');
    if (progressFill) {
        if (progressValue !== null) {
            const boundedProgress = Math.max(5, Math.min(100, progressValue));
            progressFill.style.width = `${boundedProgress}%`;
        } else {
            progressFill.style.width = '35%';
        }
    }
}

function showSuccessModal(incident) {
    document.getElementById('success-incident-id').textContent = incident.incidentId || 'N/A';
    document.getElementById('success-threat-type').textContent = incident.threatType || 'Unknown';
    document.getElementById('success-risk-level').textContent = incident.riskLevel || 'Low';

    showModal('success-modal');

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




