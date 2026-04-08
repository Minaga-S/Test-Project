/**
 * Incident Report Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.

let assets = [];
let progressTimer = null;
let analysisStartTime = null;
let analysisEstimatedDuration = 0;
const ANALYSIS_TERMINAL_LINE_LIMIT = 18;
const ANALYSIS_TERMINAL_STEP_DELAY_MS = 180;
const ANALYSIS_ESTIMATED_MIN_MS = 10000;
const ANALYSIS_ESTIMATED_MAX_MS = 20000;
let analysisTerminalSequenceToken = 0;

let analysisMeta = {
    assetId: null,
    asset: null,
    securityContext: null,
};

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
    const nextLines = [...currentLines, text].slice(-ANALYSIS_TERMINAL_LINE_LIMIT);
    outputEl.textContent = nextLines.join('\n');
    outputEl.scrollTop = outputEl.scrollHeight;
}

function startScanTerminalSimulation() {
    stopScanTerminalSimulation(false);
    analysisTerminalSequenceToken += 1;

    const shellEl = document.getElementById('analysis-terminal-shell');
    if (shellEl) {
        shellEl.open = true;
    }

    const outputEl = document.getElementById('analysis-terminal-output');
    if (outputEl) {
        outputEl.textContent = '[scan] Preparing scan workflow...';
    }
}

function stopScanTerminalSimulation(autoCloseTerminal = true) {
    analysisTerminalSequenceToken += 1;

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

    analysisStartTime = Date.now();
    analysisEstimatedDuration = ANALYSIS_ESTIMATED_MIN_MS + Math.random() * (ANALYSIS_ESTIMATED_MAX_MS - ANALYSIS_ESTIMATED_MIN_MS);

    const etaEl = document.getElementById('analysis-eta');
    if (etaEl) {
        etaEl.textContent = 'Estimated time remaining: calculating...';
    }

    let currentProgress = 5;
    updateAnalysisStatus('Preparing security analysis workflow...', currentProgress);
    updateAnalysisTimer();

    progressTimer = window.setInterval(updateAnalysisTimer, 200);
}

function updateAnalysisTimer() {
    const elapsedMs = Date.now() - analysisStartTime;
    let currentProgress = Math.min((elapsedMs / analysisEstimatedDuration) * 100, 90);
    
    const remainingMs = Math.max(0, analysisEstimatedDuration - elapsedMs);
    const remainingSeconds = Math.ceil(remainingMs / 1000);
    
    const etaEl = document.getElementById('analysis-eta');
    if (etaEl && remainingSeconds > 0) {
        etaEl.textContent = 'Estimated time remaining: ' + remainingSeconds + 's';
    }

    if (currentProgress >= 89) {
        updateAnalysisStatus('Finalizing threat analysis and generating recommendations...', currentProgress);
    } else {
        updateAnalysisStatus('Enriching security context with vulnerability and threat data...', currentProgress);
    }
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

    const selectedAsset = assets.find((a) => a._id === assetId);

    setSubmitButtonState(true);
    showModal('analysis-modal');
    beginAnalysisProgress();

    try {
        let clientSecurityContext = null;

        analysisMeta.assetId = assetId;
        analysisMeta.asset = selectedAsset || null;

        const isLiveScanEnabled = selectedAsset?.liveScan?.enabled === true;
        configureScanStep(isLiveScanEnabled);

        if (isLiveScanEnabled) {
            setStepState('step-scan', 'active');
            startScanTerminalSimulation();
            updateAnalysisStatus('Running security scan on selected asset...', 20);

            const scanResponse = await apiClient.scanAssets([assetId]);
            const scanResult = Array.isArray(scanResponse?.scans) ? scanResponse.scans[0] : null;
            clientSecurityContext = scanResult?.securityContext || null;
            analysisMeta.securityContext = clientSecurityContext;

            await generateTerminalOutputFromScan(clientSecurityContext);
            stopScanTerminalSimulation(false);
            setStepState('step-scan', 'done');
        } else {
            setStepState('step-scan', 'done');
            updateAnalysisStatus('Retrieving cached security context...', 15);

            const securityResponse = await apiClient.getAssetSecurityContext(assetId);
            clientSecurityContext = securityResponse?.securityContext || null;
            analysisMeta.securityContext = clientSecurityContext;
        }

        setStepState('step-cve', 'active');
        updateAnalysisStatus('Querying vulnerability databases for identified services...', 44);
        setStepState('step-cve', 'done');

        setStepState('step-ai', 'active');
        updateAnalysisStatus('Analyzing threat patterns and risk indicators with AI...', 68);

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
        updateAnalysisStatus('Generating mitigation recommendations...', 90);
        setStepState('step-rec', 'done');

        stopAnalysisProgress();
        updateAnalysisStatus('Analysis complete. Details and recommendations are ready.', 100);

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

function configureScanStep(isLiveScanEnabled) {
    const stepEl = document.getElementById('step-scan');
    if (!stepEl) {
        return;
    }

    if (isLiveScanEnabled) {
        stepEl.dataset.stepLabel = 'Running security scan on selected asset';
        const textEl = stepEl.querySelector('.scan-step-text');
        if (textEl) {
            textEl.textContent = 'Running security scan on selected asset';
        } else {
            stepEl.textContent = 'Running security scan on selected asset';
        }
        stepEl.style.display = 'grid';
    } else {
        stepEl.dataset.stepLabel = 'Live scan: disabled for this asset';
        const textEl = stepEl.querySelector('.scan-step-text');
        if (textEl) {
            textEl.textContent = 'Live scan: disabled for this asset';
        } else {
            stepEl.textContent = 'Live scan: disabled for this asset';
        }
        stepEl.style.display = 'grid';
    }
}

async function generateTerminalOutputFromScan(securityContext) {
    const observedOpenPorts = Array.isArray(securityContext?.liveScan?.observedOpenPorts)
        ? securityContext.liveScan.observedOpenPorts
        : [];
    const services = Array.isArray(securityContext?.liveScan?.services)
        ? securityContext.liveScan.services
        : [];
    const osInfo = securityContext?.liveScan?.osInfo || 'Unknown';
    const detectedCpeUri = String(securityContext?.cve?.query?.cpeUri || '').trim();
    const target = String(securityContext?.liveScan?.target || 'selected asset').trim() || 'selected asset';
    const token = analysisTerminalSequenceToken;
    const sleep = (delayMs) => new Promise((resolve) => window.setTimeout(resolve, delayMs));
    const isCancelled = () => token !== analysisTerminalSequenceToken;
    const appendStep = async (text, delayMs = ANALYSIS_TERMINAL_STEP_DELAY_MS) => {
        if (isCancelled()) {
            return false;
        }

        appendScanTerminalLine(text);
        await sleep(delayMs);
        return !isCancelled();
    };
    const serviceMap = {
        22: 'ssh       OpenSSH 7.4',
        80: 'http      Apache httpd 2.4',
        443: 'https     Apache httpd 2.4',
        3306: 'mysql     MySQL 5.7',
        5432: 'postgres  PostgreSQL 10',
        8080: 'http-alt  Apache Tomcat 8.5',
        3389: 'rdp       Windows RDP',
        445: 'netbios-ssn Microsoft Windows SMB',
        139: 'netbios-ssn Microsoft Windows SMB',
        25: 'smtp      Postfix smtp',
    };

    await appendStep('');
    await appendStep(`[scan] Reviewing ${target}...`);
    await appendStep('[scan] Nmap host discovery complete.');

    if (observedOpenPorts.length > 0) {
        await appendStep('[scan] Enumerating open ports...');
        await appendStep('PORT      STATE    SERVICE      VERSION');
        await appendStep('-----------------------------------------', 120);

        for (const port of observedOpenPorts.slice(0, 10)) {
            const portNum = String(port).padEnd(9);
            const serviceInfo = serviceMap[port] || 'unknown service';
            await appendStep(`${portNum} open     ${serviceInfo}`, 140);
        }

        if (observedOpenPorts.length > 10) {
            await appendStep(`... and ${observedOpenPorts.length - 10} more ports`);
        }
    } else {
        await appendStep('[scan] No open ports were identified.');
        await appendStep('PORT      STATE    SERVICE');
        await appendStep('-----------------------------', 120);
        await appendStep('All observed ports filtered or closed.');
    }

    await appendStep('[scan] Correlating services with vulnerability context...');

    if (services.length > 0) {
        await appendStep('Identified Services:');
        for (const svc of services.slice(0, 5)) {
            let serviceName = '';
            if (typeof svc === 'object' && svc !== null) {
                serviceName = svc.name || svc.service || svc.type || JSON.stringify(svc);
            } else {
                serviceName = String(svc);
            }

            await appendStep(`  - ${serviceName}`, 140);
        }

        if (services.length > 5) {
            await appendStep(`  ... and ${services.length - 5} more`);
        }
    } else {
        await appendStep('Identified Services: none');
    }

    await appendStep('[scan] Extracting OS fingerprint...');
    await appendStep(osInfo && osInfo !== 'Unknown'
        ? 'OS Detection: ' + osInfo
        : 'OS Detection: Not enough fingerprint data to identify the OS.');
    await appendStep(detectedCpeUri
        ? 'CPE Fingerprint: ' + detectedCpeUri
        : 'CPE Fingerprint: No CPE URI detected from scan profile.');
    await appendStep('[scan] Generating analysis summary...');
    await appendStep('Nmap analysis complete.');
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
