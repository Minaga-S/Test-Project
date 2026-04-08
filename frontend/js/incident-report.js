/**
 * Incident Report Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.

let assets = [];
let progressTimer = null;
let scanTerminalTimer = null;

const SIMULATED_SCAN_LINES = [
    '[nmap] Starting Nmap 7.94 scan engine',
    '[nmap] Resolving selected target and validating route',
    '[nmap] Host is up; beginning SYN probes',
    '[nmap] Service fingerprinting in progress',
    '[nmap] Correlating discovered services with enrichment profile',
];

document.addEventListener('DOMContentLoaded', () => {
    initializeIncidentReport();
});

async function initializeIncidentReport() {
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

function setStepState(stepId, state) {
    const stepEl = document.getElementById(stepId);
    if (!stepEl) {
        return;
    }

    ensureStepStructure(stepEl);

    const textEl = stepEl.querySelector('.scan-step-text');
    const baseLabel = stepEl.dataset.stepLabel || (textEl ? textEl.textContent.trim() : stepEl.textContent.trim());
    stepEl.dataset.stepLabel = baseLabel;

    const stateEl = stepEl.querySelector('.analysis-step-state');
    const labelEl = stepEl.querySelector('.scan-step-text');

    stepEl.classList.remove('is-pending', 'is-active', 'is-done');
    stepEl.classList.add(`is-${state}`);

    if (labelEl) {
        labelEl.textContent = baseLabel;
    }

    if (!stateEl) {
        return;
    }

    if (state === 'active') {
        stateEl.textContent = 'Loading';
        return;
    }

    if (state === 'done') {
        stateEl.textContent = 'Done';
        return;
    }

    stateEl.textContent = 'Waiting';
}

function ensureStepStructure(stepEl) {
    if (stepEl.querySelector('.scan-step-text')) {
        return;
    }

    const baseLabel = stepEl.textContent.trim();
    stepEl.textContent = '';

    const circleEl = document.createElement('span');
    circleEl.className = 'scan-step-circle';
    circleEl.setAttribute('aria-hidden', 'true');

    const labelEl = document.createElement('span');
    labelEl.className = 'scan-step-text';
    labelEl.textContent = baseLabel;

    const stateEl = document.createElement('span');
    stateEl.className = 'scan-step-state analysis-step-state';
    stateEl.textContent = 'Waiting';

    stepEl.appendChild(circleEl);
    stepEl.appendChild(labelEl);
    stepEl.appendChild(stateEl);
}

function appendScanTerminalLine(text) {
    const outputEl = document.getElementById('analysis-terminal-output');
    if (!outputEl) {
        return;
    }

    const currentLines = outputEl.textContent.split('\n').filter(Boolean);
    const nextLines = [...currentLines, text].slice(-9);
    outputEl.textContent = nextLines.join('\n');
    outputEl.scrollTop = outputEl.scrollHeight;
}

function startScanTerminalSimulation() {
    stopScanTerminalSimulation(false);

    const shellEl = document.getElementById('analysis-terminal-shell');
    if (shellEl) {
        shellEl.open = true;
    }

    const outputEl = document.getElementById('analysis-terminal-output');
    if (outputEl) {
        outputEl.textContent = '[scan] Bootstrapping scan workflow...';
    }

    let lineIndex = 0;
    scanTerminalTimer = window.setInterval(() => {
        appendScanTerminalLine(SIMULATED_SCAN_LINES[lineIndex % SIMULATED_SCAN_LINES.length]);
        lineIndex += 1;
    }, 780);
}

function stopScanTerminalSimulation(autoCloseTerminal = true) {
    if (scanTerminalTimer) {
        window.clearInterval(scanTerminalTimer);
        scanTerminalTimer = null;
    }

    if (autoCloseTerminal) {
        const shellEl = document.getElementById('analysis-terminal-shell');
        if (shellEl) {
            shellEl.open = false;
        }
    }
}

function resetAnalysisSteps() {
    ['step-scan', 'step-cve', 'step-ai', 'step-rec'].forEach((stepId) => {
        const stepEl = document.getElementById(stepId);
        if (stepEl) {
            ensureStepStructure(stepEl);
        }
    });

    setStepState('step-scan', 'pending');
    setStepState('step-cve', 'pending');
    setStepState('step-ai', 'pending');
    setStepState('step-rec', 'pending');
}

function beginAnalysisProgress() {
    stopAnalysisProgress();
    resetAnalysisSteps();
    updateAnalysisDataSources(null);

    const etaEl = document.getElementById('analysis-eta');
    if (etaEl) {
        etaEl.textContent = 'Estimated completion: about 15-45 seconds depending on the asset scan, CVE lookup, and AI analysis.';
    }

    let currentProgress = 8;
    updateAnalysisStatus('Preparing live scan, CVE enrichment, and AI threat analysis...', currentProgress);

    progressTimer = window.setInterval(() => {
        currentProgress = Math.min(currentProgress + Math.random() * 5, 90);
        updateAnalysisStatus('Collecting scan results, CVEs, and threat signals...', currentProgress);
    }, 450);
}

function stopAnalysisProgress() {
    if (progressTimer) {
        window.clearInterval(progressTimer);
        progressTimer = null;
    }

    stopScanTerminalSimulation(false);
}

async function handleIncidentSubmit(e) {
    e.preventDefault();

    const assetId = String(document.getElementById('affected-asset').value || '').trim();
    const description = document.getElementById('incident-description').value;
    const incidentTime = document.getElementById('when-happened').value;
    const guestAffected = document.getElementById('guest-affected').checked;
    const paymentsAffected = document.getElementById('payments-affected').checked;
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
        let clientSecurityContext = null;

        setStepState('step-scan', 'active');
        startScanTerminalSimulation();
        updateAnalysisStatus('Requesting security context and running an on-demand live scan when allowed...', 20);
        const securityResponse = await apiClient.getAssetSecurityContext(assetId);
        clientSecurityContext = securityResponse?.securityContext || null;
        const observedOpenPorts = Array.isArray(clientSecurityContext?.liveScan?.observedOpenPorts)
            ? clientSecurityContext.liveScan.observedOpenPorts
            : [];
        appendScanTerminalLine(`[nmap] Open ports discovered: ${observedOpenPorts.length > 0 ? observedOpenPorts.join(', ') : 'none'}`);
        appendScanTerminalLine('[nmap] Live scan stage complete');
        stopScanTerminalSimulation(true);
        updateAnalysisDataSources(clientSecurityContext);
        setStepState('step-scan', 'done');

        setStepState('step-cve', 'active');
        updateAnalysisStatus('Querying NIST NVD for vulnerabilities tied to the discovered services and asset profile...', 44);
        setStepState('step-cve', 'done');

        setStepState('step-ai', 'active');
        updateAnalysisStatus('Passing the incident description, scan output, and CVE matches into AI for threat classification...', 68);

        const incidentData = {
            assetId,
            description,
            incidentTime,
            guestAffected,
            paymentsAffected,
            sensitiveDataInvolved,
            clientSecurityContext,
        };

        const incident = await apiClient.createIncident(incidentData);
        setStepState('step-ai', 'done');

        setStepState('step-rec', 'active');
        updateAnalysisStatus('Generating mitigation guidance and NIST control mapping...', 90);
        setStepState('step-rec', 'done');

        stopAnalysisProgress();
        updateAnalysisStatus('Analysis complete. Threat intelligence and recommendations are ready.', 100);

        setTimeout(() => {
            hideModal('analysis-modal');
            showSuccessModal(incident);
        }, 220);
    } catch (error) {
        console.error('Error submitting incident:', error);
        stopAnalysisProgress();
        stopScanTerminalSimulation(false);
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
            const dbId = incident?._id || incident?.id || '';
            const publicIncidentId = incident?.incidentId || '';
            const query = new URLSearchParams();

            if (dbId) {
                query.set('id', dbId);
            }

            if (publicIncidentId) {
                query.set('incidentId', publicIncidentId);
            }
            const pendingOpenTarget = {
                incidentDbId: dbId,
                incidentPublicId: publicIncidentId,
                createdAt: Date.now(),
            };

            try {
                sessionStorage.setItem('incidentLogs:openTarget', JSON.stringify(pendingOpenTarget));
            } catch (storageError) {
                // Ignore storage failures and rely on query string fallback.
                console.warn('Unable to persist incident deep-link target:', storageError);
            }
            const suffix = query.toString();
            window.location.href = suffix ? `incident-logs.html?${suffix}` : 'incident-logs.html';
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
function updateAnalysisDataSources(securityContext) {
    const scanBadge = document.getElementById('badge-scan-source');
    const cveBadge = document.getElementById('badge-cve-source');
    const confidenceBadge = document.getElementById('badge-enrichment-confidence');
    const openPortsMeta = document.getElementById('scan-open-ports-meta');
    const enrichedMeta = document.getElementById('enriched-meta');

    const sources = securityContext?.dataSources || {};
    const enrichment = securityContext?.enrichment || {};

    if (scanBadge) {
        scanBadge.textContent = sources.scan || 'Live scan pending';
    }

    if (cveBadge) {
        cveBadge.textContent = sources.cve || 'CVE enrichment pending';
    }

    if (confidenceBadge) {
        confidenceBadge.textContent = `Confidence: ${enrichment.confidence || securityContext?.cve?.confidence || 'Pending'}`;
    }

    if (openPortsMeta) {
        const observedOpenPorts = Array.isArray(securityContext?.liveScan?.observedOpenPorts)
            ? securityContext.liveScan.observedOpenPorts
            : [];
        const openPortsText = observedOpenPorts.length > 0 ? observedOpenPorts.join(', ') : 'None identified';
        openPortsMeta.textContent = `Open ports: ${openPortsText}`;
    }

    if (enrichedMeta) {
        const enrichedAt = enrichment.lastEnrichedAt || securityContext?.cve?.retrievedAt;
        const resolvedText = enrichedAt ? formatDateTime(enrichedAt) : 'Pending';
        enrichedMeta.textContent = `Last enriched: ${resolvedText}`;
    }
}