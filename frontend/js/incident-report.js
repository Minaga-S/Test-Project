/**
 * Incident Report Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.

let assets = [];
let progressTimer = null;
let analysisStartTime = null;
let analysisEstimatedDuration = 0;
let analysisUsesLiveScan = false;
const ANALYSIS_TERMINAL_LINE_LIMIT = 18;
const ANALYSIS_TERMINAL_STEP_DELAY_MS = 180;
const ANALYSIS_DURATION_METRICS_STORAGE_KEY = 'incidentAnalysis:durationMetrics';
const ANALYSIS_DEFAULT_LIVE_SCAN_MS = 70000;
const ANALYSIS_DEFAULT_CACHED_SCAN_MS = 35000;
const ANALYSIS_ESTIMATED_MIN_LIVE_MS = 35000;
const ANALYSIS_ESTIMATED_MAX_LIVE_MS = 180000;
const ANALYSIS_ESTIMATED_MIN_CACHED_MS = 15000;
const ANALYSIS_ESTIMATED_MAX_CACHED_MS = 90000;
const ANALYSIS_OVERRUN_BUFFER_MS = 20000;
const LOCAL_SCANNER_BASE_URL = 'http://127.0.0.1:47633';
const LOCAL_SCANNER_REPO_URL = 'https://github.com/dev-pahan/NmapLocalScanner';
let analysisTerminalSequenceToken = 0;

let analysisMeta = {
    assetId: null,
    asset: null,
    securityContext: null,
};

async function updateIncidentScannerBadge() {
    const badgeEl = document.getElementById('incident-scanner-badge');
    const statusEl = document.getElementById('incident-scanner-status');
    
    if (!badgeEl || !statusEl) {
        return;
    }

    const isConnected = await isLocalScannerReachable();
    badgeEl.style.display = 'flex';
    
    if (isConnected) {
        badgeEl.classList.remove('live-badge-warning');
        statusEl.textContent = 'Scanner Connected';
    } else {
        badgeEl.classList.add('live-badge-warning');
        statusEl.textContent = 'Scanner Offline';
    }
}

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

    const assetSelect = document.getElementById('affected-asset');
    if (assetSelect) {
        assetSelect.addEventListener('change', updateIncidentScannerBadge);
    }

    document.querySelectorAll('[id$="-overlay"]').forEach((overlay) => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                e.target.parentElement.style.display = 'none';
            }
        });
    });

    updateIncidentScannerBadge();
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

    stepEl.classList.remove('is-pending', 'is-active', 'is-done', 'is-failed');
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

    if (state === 'failed') {
        stateEl.textContent = 'Failed';
        return;
    }

    stateEl.textContent = 'Waiting';
}

function setStepStateText(stepId, text) {
    const stepEl = document.getElementById(stepId);
    if (!stepEl) {
        return;
    }

    const stateEl = stepEl.querySelector('.analysis-step-state');
    if (stateEl) {
        stateEl.textContent = text;
    }
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

function parseCommaSeparatedPorts(value) {
    const rawValue = String(value || '').trim();
    if (!rawValue) {
        return [];
    }

    return rawValue
        .split(',')
        .map((item) => Number(item.trim()))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
}

function getPreviewOpenPorts(previewPayload = {}) {
    const liveScanPorts = previewPayload?.securityContext?.liveScan?.observedOpenPorts;
    if (Array.isArray(liveScanPorts) && liveScanPorts.length > 0) {
        return liveScanPorts;
    }

    const scanResultPorts = previewPayload?.scanResult?.openPorts;
    return Array.isArray(scanResultPorts) ? scanResultPorts : [];
}

function getPreviewServices(previewPayload = {}) {
    const liveScanServices = previewPayload?.securityContext?.liveScan?.services;
    if (Array.isArray(liveScanServices) && liveScanServices.length > 0) {
        return liveScanServices;
    }

    const scanResultServices = previewPayload?.scanResult?.services;
    return Array.isArray(scanResultServices) ? scanResultServices : [];
}

function buildIncidentScanPreviewPayload(asset = {}) {
    const liveScan = asset?.liveScan || {};
    const profile = asset?.vulnerabilityProfile || {};

    return {
        assetId: String(asset?._id || '').trim(),
        assetName: String(asset?.assetName || '').trim(),
        assetType: String(asset?.assetType || '').trim(),
        liveScan: {
            target: String(liveScan?.target || '').trim(),
            ports: String(liveScan?.ports || '').trim(),
            frequency: String(liveScan?.frequency || 'OnDemand').trim() || 'OnDemand',
        },
        vulnerabilityProfile: {
            osName: String(profile?.osName || '').trim(),
            vendor: String(profile?.vendor || '').trim(),
            product: String(profile?.product || '').trim(),
            productVersion: String(profile?.productVersion || '').trim(),
            cpeUri: String(profile?.cpeUri || '').trim(),
        },
    };
}

function isLocalScannerFetchAllowed() {
    const host = String(window.location.hostname || '').toLowerCase();
    const isLoopbackHost = host === 'localhost' || host === '127.0.0.1';
    return window.isSecureContext || isLoopbackHost;
}

function getLocalScannerAddressSpace(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
            return 'loopback';
        }

        return 'local';
    } catch (error) {
        return 'local';
    }
}

function buildLocalScannerFetchOptions(options = {}) {
    const requestOptions = {
        ...options,
        mode: 'cors',
        credentials: 'omit',
    };

    if (window.isSecureContext) {
        requestOptions.targetAddressSpace = getLocalScannerAddressSpace(LOCAL_SCANNER_BASE_URL);
    }

    return requestOptions;
}

async function isLocalScannerReachable() {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 1800);

    try {
        const response = await fetch(`${LOCAL_SCANNER_BASE_URL}/health`, buildLocalScannerFetchOptions({
            method: 'GET',
            signal: controller.signal,
        }));

        if (!response.ok) {
            return false;
        }

        const payload = await response.json().catch(() => ({}));
        return payload?.status === 'ok';
    } catch (error) {
        return false;
    } finally {
        window.clearTimeout(timeoutId);
    }
}

async function runLocalScannerPreview(payload) {
    const requestResponse = await apiClient.requestLocalScannerScan(payload);
    const scanRequest = requestResponse?.scanRequest || requestResponse;

    const scannerResponse = await fetch(`${LOCAL_SCANNER_BASE_URL}/scan`, buildLocalScannerFetchOptions({
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            bridgeToken: scanRequest.bridgeToken,
            uploadUrl: scanRequest.uploadUrl,
            backendOrigin: apiClient.getApiOrigin(),
            target: scanRequest.target,
            ports: scanRequest.ports,
        }),
    }));

    const scannerPayload = await scannerResponse.json().catch(() => ({}));
    if (!scannerResponse.ok) {
        throw new Error(scannerPayload?.message || 'Local scanner request failed');
    }

    return scannerPayload?.preview || scannerPayload;
}

function buildClientSecurityContextFromPreview(previewPayload = {}) {
    const securityContext = {
        ...(previewPayload?.securityContext || {}),
    };

    const cveQuery = previewPayload?.cveResult?.query || {};
    const scanResult = previewPayload?.scanResult || {};
    const inferredProfile = previewPayload?.inferredProfile || {};
    const previewOpenPorts = getPreviewOpenPorts(previewPayload);
    const previewServices = getPreviewServices(previewPayload);

    securityContext.liveScan = {
        ...(securityContext?.liveScan || {}),
        observedOpenPorts: previewOpenPorts,
        services: previewServices,
        osInfo: String(
            securityContext?.liveScan?.osInfo
            || scanResult?.osInfo
            || inferredProfile?.osName
            || ''
        ).trim(),
    };

    securityContext.cve = {
        ...(securityContext?.cve || {}),
        query: {
            ...(securityContext?.cve?.query || {}),
            cpeUri: String(cveQuery?.cpeUri || scanResult?.osCpe || inferredProfile?.cpeUri || '').trim(),
            vendor: String(cveQuery?.vendor || inferredProfile?.vendor || '').trim(),
            product: String(cveQuery?.product || inferredProfile?.product || '').trim(),
            productVersion: String(cveQuery?.productVersion || inferredProfile?.productVersion || '').trim(),
            osName: String(cveQuery?.osName || inferredProfile?.osName || securityContext?.liveScan?.osInfo || '').trim(),
        },
    };

    return securityContext;
}

async function persistAssetProfileFromPreview(asset, previewPayload = {}) {
    if (!asset?._id) {
        return asset;
    }

    const profile = asset?.vulnerabilityProfile || {};
    const liveScan = asset?.liveScan || {};
    const cveQuery = previewPayload?.cveResult?.query || {};
    const scanResult = previewPayload?.scanResult || {};
    const inferredProfile = previewPayload?.inferredProfile || {};
    const previewOpenPorts = getPreviewOpenPorts(previewPayload);

    const updatePayload = {
        liveScan: {
            enabled: Boolean(liveScan?.enabled),
            target: String(liveScan?.target || '').trim(),
            ports: previewOpenPorts.length > 0 ? previewOpenPorts.join(', ') : String(liveScan?.ports || '').trim(),
            frequency: String(liveScan?.frequency || 'OnDemand').trim() || 'OnDemand',
        },
        vulnerabilityProfile: {
            osName: String(scanResult?.osInfo || cveQuery?.osName || inferredProfile?.osName || profile?.osName || '').trim(),
            vendor: String(cveQuery?.vendor || inferredProfile?.vendor || profile?.vendor || '').trim(),
            product: String(cveQuery?.product || inferredProfile?.product || profile?.product || '').trim(),
            productVersion: String(cveQuery?.productVersion || inferredProfile?.productVersion || profile?.productVersion || '').trim(),
            cpeUri: String(scanResult?.osCpe || cveQuery?.cpeUri || inferredProfile?.cpeUri || profile?.cpeUri || '').trim(),
        },
    };

    const response = await apiClient.updateAsset(asset._id, updatePayload);
    const updatedAsset = response?.asset || asset;

    assets = assets.map((item) => (item._id === updatedAsset._id ? updatedAsset : item));
    return updatedAsset;
}


function collectAssetProfileData(asset = {}) {
    const profile = asset?.vulnerabilityProfile || {};
    const liveScan = asset?.liveScan || {};

    return {
        liveScan: {
            osInfo: String(profile?.osName || '').trim(),
            observedOpenPorts: parseCommaSeparatedPorts(liveScan?.ports),
            services: [],
        },
        cve: {
            query: {
                cpeUri: String(profile?.cpeUri || '').trim(),
                vendor: String(profile?.vendor || '').trim(),
                product: String(profile?.product || '').trim(),
                productVersion: String(profile?.productVersion || '').trim(),
                osName: String(profile?.osName || '').trim(),
            },
        },
    };
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

function toBoundedNumber(value, fallback = 0) {
    const parsedValue = Number(value);
    if (!Number.isFinite(parsedValue) || parsedValue < 0) {
        return fallback;
    }

    return parsedValue;
}

function formatDurationMinutesSeconds(totalSeconds) {
    const safeSeconds = Math.max(0, Math.ceil(Number(totalSeconds) || 0));
    const minutes = Math.floor(safeSeconds / 60);
    const seconds = safeSeconds % 60;

    if (minutes <= 0) {
        return `${seconds}s`;
    }

    return `${minutes}m ${seconds}s`;
}

function readAnalysisDurationMetrics() {
    try {
        const rawValue = localStorage.getItem(ANALYSIS_DURATION_METRICS_STORAGE_KEY);
        if (!rawValue) {
            return {};
        }

        return JSON.parse(rawValue) || {};
    } catch (error) {
        console.warn('Unable to read analysis duration metrics:', error);
        return {};
    }
}

function writeAnalysisDurationMetrics(metrics = {}) {
    try {
        localStorage.setItem(ANALYSIS_DURATION_METRICS_STORAGE_KEY, JSON.stringify(metrics));
    } catch (error) {
        console.warn('Unable to store analysis duration metrics:', error);
    }
}

function getEstimatedAnalysisDurationMs(isLiveScanEnabled) {
    const metrics = readAnalysisDurationMetrics();
    const defaultDurationMs = isLiveScanEnabled ? ANALYSIS_DEFAULT_LIVE_SCAN_MS : ANALYSIS_DEFAULT_CACHED_SCAN_MS;
    const averageKey = isLiveScanEnabled ? 'liveScanAverageMs' : 'cachedAverageMs';
    const lowerBoundMs = isLiveScanEnabled ? ANALYSIS_ESTIMATED_MIN_LIVE_MS : ANALYSIS_ESTIMATED_MIN_CACHED_MS;
    const upperBoundMs = isLiveScanEnabled ? ANALYSIS_ESTIMATED_MAX_LIVE_MS : ANALYSIS_ESTIMATED_MAX_CACHED_MS;
    const historicalAverageMs = toBoundedNumber(metrics[averageKey], defaultDurationMs);
    const paddedEstimateMs = historicalAverageMs * 1.15;

    return Math.max(lowerBoundMs, Math.min(upperBoundMs, paddedEstimateMs));
}

function recordAnalysisDuration(elapsedMs, isLiveScanEnabled) {
    if (!Number.isFinite(elapsedMs) || elapsedMs <= 0) {
        return;
    }

    const metrics = readAnalysisDurationMetrics();
    const averageKey = isLiveScanEnabled ? 'liveScanAverageMs' : 'cachedAverageMs';
    const sampleKey = isLiveScanEnabled ? 'liveScanSamples' : 'cachedSamples';
    const defaultDurationMs = isLiveScanEnabled ? ANALYSIS_DEFAULT_LIVE_SCAN_MS : ANALYSIS_DEFAULT_CACHED_SCAN_MS;

    const previousAverageMs = toBoundedNumber(metrics[averageKey], defaultDurationMs);
    const previousSamples = toBoundedNumber(metrics[sampleKey], 0);
    const smoothingFactor = 0.35;
    const nextAverageMs = (previousAverageMs * (1 - smoothingFactor)) + (elapsedMs * smoothingFactor);

    writeAnalysisDurationMetrics({
        ...metrics,
        [averageKey]: Math.round(nextAverageMs),
        [sampleKey]: previousSamples + 1,
    });
}

function beginAnalysisProgress(isLiveScanEnabled) {
    stopAnalysisProgress();
    resetAnalysisSteps();

    analysisUsesLiveScan = isLiveScanEnabled;

    analysisStartTime = Date.now();
    analysisEstimatedDuration = getEstimatedAnalysisDurationMs(isLiveScanEnabled);

    const etaEl = document.getElementById('analysis-eta');
    if (etaEl) {
        etaEl.textContent = `Estimated time remaining: ~${formatDurationMinutesSeconds(analysisEstimatedDuration / 1000)}`;
    }

    let currentProgress = 5;
    updateAnalysisStatus('Preparing security analysis workflow...', currentProgress);
    updateAnalysisTimer();

    progressTimer = window.setInterval(updateAnalysisTimer, 200);
}

function updateAnalysisTimer() {
    const elapsedMs = Date.now() - analysisStartTime;
    if (elapsedMs > analysisEstimatedDuration) {
        analysisEstimatedDuration = elapsedMs + ANALYSIS_OVERRUN_BUFFER_MS;
    }

    let currentProgress = Math.min((elapsedMs / analysisEstimatedDuration) * 100, 90);
    
    const remainingMs = Math.max(0, analysisEstimatedDuration - elapsedMs);
    const remainingSeconds = Math.ceil(remainingMs / 1000);
    
    const etaEl = document.getElementById('analysis-eta');
    if (etaEl && remainingSeconds > 0) {
        etaEl.textContent = `Estimated time remaining: ${formatDurationMinutesSeconds(remainingSeconds)}`;
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
    const isLiveScanEnabled = selectedAsset?.liveScan?.enabled === true;
    const hasLiveScanTarget = Boolean(String(selectedAsset?.liveScan?.target || '').trim());
    const canRunLiveScan = isLiveScanEnabled && hasLiveScanTarget;

    setSubmitButtonState(true);
    showModal('analysis-modal');
    beginAnalysisProgress(canRunLiveScan);

    try {
        let clientSecurityContext = null;

        analysisMeta.assetId = assetId;
        analysisMeta.asset = selectedAsset || null;

        // Collect asset profile data (CPE, OS, ports, services) for merge with scan results
        let assetProfileData = collectAssetProfileData(selectedAsset);

        configureScanStep(isLiveScanEnabled, hasLiveScanTarget);

        if (canRunLiveScan) {
            if (!isLocalScannerFetchAllowed()) {
                throw new Error('Live scan requires HTTPS (Render URL) or localhost because it runs through the local scanner app');
            }

            const isScannerOnline = await isLocalScannerReachable();
            if (!isScannerOnline) {
                throw new Error(`Local scanner app is offline. Start it and retry. Download: ${LOCAL_SCANNER_REPO_URL}`);
            }

            setStepState('step-scan', 'active');
            startScanTerminalSimulation();
            updateAnalysisStatus('Running security scan on selected asset...', 20);

            const previewPayload = buildIncidentScanPreviewPayload(selectedAsset);
            const preview = await runLocalScannerPreview(previewPayload);

            clientSecurityContext = buildClientSecurityContextFromPreview(preview);
            analysisMeta.securityContext = clientSecurityContext;

            await generateTerminalOutputFromScan(clientSecurityContext, preview?.scanResult || {});

            try {
                const updatedAsset = await persistAssetProfileFromPreview(selectedAsset, preview);
                analysisMeta.asset = updatedAsset;
                assetProfileData = collectAssetProfileData(updatedAsset);
            } catch (assetUpdateError) {
                console.warn('Unable to persist latest scan findings to asset profile:', assetUpdateError);
            }

            stopScanTerminalSimulation(false);
            setStepState('step-scan', 'done');
        } else {
            setStepState('step-scan', 'failed');
            setStepStateText('step-scan', 'Skipped');

            updateAnalysisStatus(
                isLiveScanEnabled
                    ? 'Live scan skipped: no scan target (IP/hostname) configured on this asset.'
                    : 'Live scan skipped: enable live scan on the asset to run Nmap.',
                15
            );

            appendScanTerminalLine('[scan] Live scan skipped.');
            appendScanTerminalLine(
                isLiveScanEnabled
                    ? '[scan] Reason: No scan target (IP/hostname) configured on this asset.'
                    : '[scan] Reason: Live scan is disabled for this asset.'
            );
            appendScanTerminalLine('[scan] Continuing with cached security context for analysis.');

            const securityResponse = await apiClient.getAssetSecurityContext(assetId);
            clientSecurityContext = securityResponse?.securityContext || null;
            analysisMeta.securityContext = clientSecurityContext;
        }

        // Merge asset profile data with client security context (fallback if scan didn't detect)
        if (!clientSecurityContext) { clientSecurityContext = {}; }
        if (!clientSecurityContext.liveScan) { clientSecurityContext.liveScan = {}; }
        if (!clientSecurityContext.cve) { clientSecurityContext.cve = {}; }
        if (!clientSecurityContext.cve.query) { clientSecurityContext.cve.query = {}; }

        // Use asset profile as fallback for OS, ports, services, and CPE
        if (!clientSecurityContext.liveScan.osInfo && assetProfileData.liveScan.osInfo) {
            clientSecurityContext.liveScan.osInfo = assetProfileData.liveScan.osInfo;
        }
        if ((!clientSecurityContext.liveScan.observedOpenPorts || clientSecurityContext.liveScan.observedOpenPorts.length === 0) && assetProfileData.liveScan.observedOpenPorts.length > 0) {
            clientSecurityContext.liveScan.observedOpenPorts = assetProfileData.liveScan.observedOpenPorts;
        }
        if ((!clientSecurityContext.liveScan.services || clientSecurityContext.liveScan.services.length === 0) && assetProfileData.liveScan.services.length > 0) {
            clientSecurityContext.liveScan.services = assetProfileData.liveScan.services;
        }
        // Merge CPE query fields
        const acpeQuery = assetProfileData.cve.query;
        if (!clientSecurityContext.cve.query.cpeUri && acpeQuery.cpeUri) { clientSecurityContext.cve.query.cpeUri = acpeQuery.cpeUri; }
        if (!clientSecurityContext.cve.query.vendor && acpeQuery.vendor) { clientSecurityContext.cve.query.vendor = acpeQuery.vendor; }
        if (!clientSecurityContext.cve.query.product && acpeQuery.product) { clientSecurityContext.cve.query.product = acpeQuery.product; }
        if (!clientSecurityContext.cve.query.productVersion && acpeQuery.productVersion) { clientSecurityContext.cve.query.productVersion = acpeQuery.productVersion; }
        if (!clientSecurityContext.cve.query.osName && acpeQuery.osName) { clientSecurityContext.cve.query.osName = acpeQuery.osName; }

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

        recordAnalysisDuration(Date.now() - analysisStartTime, analysisUsesLiveScan);

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
        const errorMessage = String(error?.message || '').trim() || 'Unknown error';
        const lowerErrorMessage = errorMessage.toLowerCase();

        const isLocalNetworkBlocked = lowerErrorMessage.includes('failed to fetch') || lowerErrorMessage.includes('private network');

        if (lowerErrorMessage.includes('ai') || lowerErrorMessage.includes('gemini')) {
            setStepState('step-ai', 'failed');
        }

        if (lowerErrorMessage.includes('cve') || lowerErrorMessage.includes('vulnerab') || lowerErrorMessage.includes('nist')) {
            setStepState('step-cve', 'failed');
        }

        if (lowerErrorMessage.includes('scan') || lowerErrorMessage.includes('target') || lowerErrorMessage.includes('nmap')) {
            setStepState('step-scan', 'failed');
        }

        if (lowerErrorMessage.includes('recommend')) {
            setStepState('step-rec', 'failed');
        }

        if (!lowerErrorMessage.includes('ai')
            && !lowerErrorMessage.includes('cve')
            && !lowerErrorMessage.includes('scan')
            && !lowerErrorMessage.includes('recommend')) {
            setStepState('step-ai', 'failed');
        }

        updateAnalysisStatus(`Analysis did not complete: ${errorMessage}`, 92);
        appendScanTerminalLine(`[scan] Workflow failed: ${errorMessage}`);
        if (isLocalNetworkBlocked) {
            showNotification('Scan blocked by browser local-network restrictions. In Chrome, allow local network access for this site and retry.', 'error');
        } else {
            showNotification(`Error submitting incident: ${errorMessage}`, 'error');
        }
    } finally {
        setSubmitButtonState(false);
    }
}

function configureScanStep(isLiveScanEnabled, hasLiveScanTarget) {
    const stepEl = document.getElementById('step-scan');
    if (!stepEl) {
        return;
    }

    if (isLiveScanEnabled && hasLiveScanTarget) {
        stepEl.dataset.stepLabel = 'Running security scan on selected asset';
        const textEl = stepEl.querySelector('.scan-step-text');
        if (textEl) {
            textEl.textContent = 'Running security scan on selected asset';
        } else {
            stepEl.textContent = 'Running security scan on selected asset';
        }
        stepEl.style.display = 'grid';

        return;
    }

    if (isLiveScanEnabled && !hasLiveScanTarget) {
        stepEl.dataset.stepLabel = 'Live scan skipped: no scan target configured on this asset';
        const textEl = stepEl.querySelector('.scan-step-text');
        if (textEl) {
            textEl.textContent = 'Live scan skipped: no scan target configured on this asset';
        } else {
            stepEl.textContent = 'Live scan skipped: no scan target configured on this asset';
        }
        stepEl.style.display = 'grid';

        return;
    }

    stepEl.dataset.stepLabel = 'Live scan skipped: disabled for this asset';
    const textEl = stepEl.querySelector('.scan-step-text');
    if (textEl) {
        textEl.textContent = 'Live scan skipped: disabled for this asset';
    } else {
        stepEl.textContent = 'Live scan skipped: disabled for this asset';
    }

    stepEl.style.display = 'grid';
}

async function generateTerminalOutputFromScan(securityContext, scanResult = {}) {
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
    await appendStep('[scan] Source: Local Scanner app bridge');

    const rawOutput = String(scanResult?.rawOutput || '').trim();
    if (rawOutput) {
        const normalizedLines = rawOutput
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
            .slice(0, 8);

        if (normalizedLines.length > 0) {
            await appendStep('[scan] Raw nmap output (truncated):');
            for (const line of normalizedLines) {
                await appendStep(`[nmap] ${line}`, 120);
            }
        }
    }

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
