/**
 * Asset Management Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.

let assets = [];
let currentEditingAssetId = null;
let selectedAssetIds = new Set();
let pendingDeleteAssetIds = [];
const DEFAULT_SCAN_FREQUENCY = 'OnDemand';
const ASSET_SCAN_TERMINAL_LINE_LIMIT = 18;
const ASSET_SCAN_TERMINAL_STEP_DELAY_MS = 180;
const ASSET_SCAN_PROGRESS_INTERVAL_MS = 420;
const ASSET_SCAN_DURATION_METRICS_STORAGE_KEY = 'assetScan:durationMetrics';
const ASSET_SCAN_DEFAULT_ESTIMATED_MS = 75000;
const ASSET_SCAN_ESTIMATED_MIN_MS = 35000;
const ASSET_SCAN_ESTIMATED_MAX_MS = 180000;
const ASSET_SCAN_OVERRUN_BUFFER_MS = 15000;
const CRITICALITY_HIGH_RISK_PORTS = new Set([21, 23, 25, 53, 79, 110, 111, 135, 137, 138, 139, 143, 161, 389, 443, 445, 512, 513, 514, 1524, 2049, 3306, 3389, 5432, 5900, 6379, 8080]);
const CRITICALITY_HIGH_RISK_SERVICE_KEYWORDS = [
    'telnet',
    'ftp',
    'tftp',
    'rpc',
    'rpcbind',
    'nfs',
    'smb',
    'samba',
    'netbios',
    'distccd',
    'rlogin',
    'rsh',
    'rexec',
    'postgres',
    'mysql',
    'vnc',
    'rdp',
    'ldap',
    'snmp',
];
const CRITICALITY_SCORE_LOW_THRESHOLD = 1;
const CRITICALITY_SCORE_MEDIUM_THRESHOLD = 4;
const CRITICALITY_SCORE_HIGH_THRESHOLD = 8;
const CRITICALITY_SCORE_CRITICAL_THRESHOLD = 12;
const CRITICALITY_OPEN_PORT_SCORE_CAP = 5;
const CRITICALITY_OPEN_PORT_SCORE_PER_PORT = 0.5;
const CRITICALITY_HIGH_RISK_PORT_SCORE_CAP = 6;
const CRITICALITY_HIGH_RISK_PORT_SCORE_PER_MATCH = 1.3;
const CRITICALITY_HIGH_RISK_SERVICE_SCORE_CAP = 6;
const CRITICALITY_HIGH_RISK_SERVICE_SCORE_PER_MATCH = 1.5;
const CRITICALITY_CPE_PRESENT_SCORE = 0.8;
const CRITICALITY_CPE_WELL_FORMED_SCORE = 0.6;
const CRITICALITY_CPE_VERSION_SPECIFIC_SCORE = 1.2;
const CVE_SEVERITY_SCORE_MAP = {
    CRITICAL: 9,
    HIGH: 6,
    MEDIUM: 3,
    LOW: 1,
};
const CRITICALITY_CVE_MAX_SCORE_CAP = 12;
const CRITICALITY_CVE_COUNT_SCORE_CAP = 4;
const CRITICALITY_CVE_COUNT_SCORE_PER_MATCH = 0.45;
const LOCAL_SCANNER_BASE_URL = 'http://127.0.0.1:47633';
const LOCAL_SCANNER_REPO_URL = 'https://github.com/dev-pahan/NmapLocalScanner';
let assetScanTerminalTimer = null;
let assetScanTerminalSequenceToken = 0;
let assetScanProgressTimer = null;
let assetScanStartTime = null;
let assetScanEstimatedDuration = 0;
let assetScanMeta = {
    target: null,
    securityContext: null,
};
let isCriticalityManuallyOverridden = false;
let isApplyingDetectedCriticality = false;

async function updateAssetScannerBadge() {
    const badgeEl = document.getElementById('asset-scanner-badge');
    const statusEl = document.getElementById('asset-scanner-status');
    
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

function isIpv4Address(value) {
    return /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/.test(String(value || '').trim());
}

function isPrivateIpv4Address(value) {
    const parts = String(value || '').trim().split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
        return false;
    }

    const first = parts[0];
    const second = parts[1];

    if (first === 10) return true;
    if (first === 127) return true;
    if (first === 169 && second === 254) return true;
    if (first === 172 && second >= 16 && second <= 31) return true;
    if (first === 192 && second === 168) return true;
    if (first === 100 && second >= 64 && second <= 127) return true;
    return false;
}

function isLocalScanHostname(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return normalized === 'localhost'
        || normalized.endsWith('.local')
        || normalized.endsWith('.internal')
        || normalized.endsWith('.lan');
}

function isAllowedLiveScanTarget(value) {
    const normalized = String(value || '').trim();
    if (!normalized) {
        return false;
    }

    if (isIpv4Address(normalized)) {
        return isPrivateIpv4Address(normalized);
    }

    return isLocalScanHostname(normalized);
}

function setScanDetailsVisibility(isVisible) {
    const panel = document.getElementById('asset-edit-scan-panel');
    if (panel) {
        panel.style.display = isVisible ? 'block' : 'none';
    }
}

function setAssetModalMode(isEditMode) {
    setScanDetailsVisibility(isEditMode);
}

function mapScoreToCriticality(score) {
    if (score >= CRITICALITY_SCORE_CRITICAL_THRESHOLD) return 'Critical';
    if (score >= CRITICALITY_SCORE_HIGH_THRESHOLD) return 'High';
    if (score >= CRITICALITY_SCORE_MEDIUM_THRESHOLD) return 'Medium';
    if (score >= CRITICALITY_SCORE_LOW_THRESHOLD) return 'Low';
    return '';
}

function normalizeDetectedPort(portValue) {
    const parsedPort = Number(portValue);
    if (!Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
        return null;
    }

    return parsedPort;
}

function collectOpenPortsForCriticality(previewPayload = {}) {
    const liveScan = previewPayload?.securityContext?.liveScan || {};
    const scanResult = previewPayload?.scanResult || {};
    const rawOpenPorts = Array.isArray(liveScan.observedOpenPorts) && liveScan.observedOpenPorts.length > 0
        ? liveScan.observedOpenPorts
        : (Array.isArray(scanResult.openPorts) ? scanResult.openPorts : []);

    const normalizedPorts = rawOpenPorts
        .map((portValue) => normalizeDetectedPort(portValue))
        .filter((portValue) => portValue !== null);

    return [...new Set(normalizedPorts)];
}

function collectServiceFingerprintsForCriticality(previewPayload = {}) {
    const liveScan = previewPayload?.securityContext?.liveScan || {};
    const scanResult = previewPayload?.scanResult || {};
    const services = Array.isArray(liveScan.services) && liveScan.services.length > 0
        ? liveScan.services
        : (Array.isArray(scanResult.services) ? scanResult.services : []);

    return services.map((service) => {
        if (typeof service === 'string') {
            return service.toLowerCase();
        }

        const serviceName = String(service?.service || service?.name || '').trim();
        const serviceVersion = String(service?.version || '').trim();
        return `${serviceName} ${serviceVersion}`.trim().toLowerCase();
    }).filter(Boolean);
}

function collectCpeValuesForCriticality(previewPayload = {}) {
    const inferredProfile = previewPayload?.inferredProfile || {};
    const cveQuery = previewPayload?.cveResult?.query || {};
    const scanResult = previewPayload?.scanResult || {};

    return [inferredProfile.cpeUri, cveQuery.cpeUri, scanResult.osCpe]
        .map((value) => String(value || '').trim().toLowerCase())
        .filter(Boolean);
}

function hasVersionSpecificCpe(cpeValues = []) {
    return cpeValues.some((cpe) => {
        if (!cpe.startsWith('cpe:2.3:')) {
            return false;
        }

        const cpeParts = cpe.split(':');
        const versionToken = cpeParts[5] || '';
        return Boolean(versionToken) && versionToken !== '*' && versionToken !== '-';
    });
}

function calculateCveRiskScore(cveMatches = []) {
    if (cveMatches.length === 0) {
        return {
            score: 0,
            hasCriticalCve: false,
            hasHighCve: false,
        };
    }

    const severityScores = cveMatches.map((match) => {
        const severity = String(match?.severity || '').trim().toUpperCase();
        return CVE_SEVERITY_SCORE_MAP[severity] || 0;
    });
    const maxSeverityScore = Math.max(...severityScores, 0);
    const cveCountScore = Math.min(cveMatches.length * CRITICALITY_CVE_COUNT_SCORE_PER_MATCH, CRITICALITY_CVE_COUNT_SCORE_CAP);

    return {
        score: Math.min(maxSeverityScore + cveCountScore, CRITICALITY_CVE_MAX_SCORE_CAP),
        hasCriticalCve: cveMatches.some((match) => String(match?.severity || '').trim().toUpperCase() === 'CRITICAL'),
        hasHighCve: cveMatches.some((match) => String(match?.severity || '').trim().toUpperCase() === 'HIGH'),
    };
}

function detectCriticalityFromPreview(previewPayload = {}) {
    const cveMatches = Array.isArray(previewPayload?.cveResult?.matches) ? previewPayload.cveResult.matches : [];
    const openPorts = collectOpenPortsForCriticality(previewPayload);
    const serviceFingerprints = collectServiceFingerprintsForCriticality(previewPayload);
    const cpeValues = collectCpeValuesForCriticality(previewPayload);

    const highRiskPortCount = openPorts.filter((port) => CRITICALITY_HIGH_RISK_PORTS.has(port)).length;
    const highRiskServiceCount = serviceFingerprints.filter((serviceText) => CRITICALITY_HIGH_RISK_SERVICE_KEYWORDS
        .some((keyword) => serviceText.includes(keyword))).length;

    const openPortScore = Math.min(openPorts.length * CRITICALITY_OPEN_PORT_SCORE_PER_PORT, CRITICALITY_OPEN_PORT_SCORE_CAP);
    const highRiskPortScore = Math.min(highRiskPortCount * CRITICALITY_HIGH_RISK_PORT_SCORE_PER_MATCH, CRITICALITY_HIGH_RISK_PORT_SCORE_CAP);
    const highRiskServiceScore = Math.min(highRiskServiceCount * CRITICALITY_HIGH_RISK_SERVICE_SCORE_PER_MATCH, CRITICALITY_HIGH_RISK_SERVICE_SCORE_CAP);
    const cpePresenceScore = cpeValues.length > 0 ? CRITICALITY_CPE_PRESENT_SCORE : 0;
    const cpeWellFormedScore = cpeValues.some((cpe) => cpe.startsWith('cpe:2.3:') || cpe.startsWith('cpe:/'))
        ? CRITICALITY_CPE_WELL_FORMED_SCORE
        : 0;
    const cpeVersionScore = hasVersionSpecificCpe(cpeValues) ? CRITICALITY_CPE_VERSION_SPECIFIC_SCORE : 0;
    const cveRisk = calculateCveRiskScore(cveMatches);

    let totalRiskScore = openPortScore + highRiskPortScore + highRiskServiceScore + cpePresenceScore + cpeWellFormedScore + cpeVersionScore + cveRisk.score;

    // If severe CVEs are present and exposure data confirms reachability, push the score floor up.
    if (cveRisk.hasCriticalCve && (openPorts.length > 0 || highRiskServiceCount > 0 || cpeValues.length > 0)) {
        totalRiskScore = Math.max(totalRiskScore, CRITICALITY_SCORE_CRITICAL_THRESHOLD);
    } else if (cveRisk.hasHighCve && (openPorts.length > 0 || highRiskServiceCount > 0)) {
        totalRiskScore = Math.max(totalRiskScore, CRITICALITY_SCORE_HIGH_THRESHOLD);
    }

    return mapScoreToCriticality(totalRiskScore);
}

function applyDetectedCriticality(previewPayload = {}) {
    const criticalityEl = document.getElementById('asset-criticality');
    if (!criticalityEl || isCriticalityManuallyOverridden) {
        return;
    }

    const detectedCriticality = detectCriticalityFromPreview(previewPayload);
    if (!detectedCriticality || criticalityEl.value === detectedCriticality) {
        return;
    }

    isApplyingDetectedCriticality = true;
    criticalityEl.value = detectedCriticality;
    isApplyingDetectedCriticality = false;
}

function setupCriticalityOverrideTracking() {
    const criticalityEl = document.getElementById('asset-criticality');
    if (!criticalityEl || criticalityEl.dataset.overrideListenerBound === 'true') {
        return;
    }

    criticalityEl.addEventListener('change', () => {
        if (!isApplyingDetectedCriticality) {
            isCriticalityManuallyOverridden = true;
        }
    });

    criticalityEl.dataset.overrideListenerBound = 'true';
}


function ensureAssetScanStepStructure(stepEl) {
    if (!stepEl || stepEl.querySelector('.scan-step-text')) {
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
    stateEl.className = 'scan-step-state';
    stateEl.textContent = 'Waiting';

    stepEl.appendChild(circleEl);
    stepEl.appendChild(labelEl);
    stepEl.appendChild(stateEl);
}

function setAssetScanStepState(stepId, state) {
    const stepEl = document.getElementById(stepId);
    if (!stepEl) {
        return;
    }

    ensureAssetScanStepStructure(stepEl);
    stepEl.classList.remove('is-pending', 'is-active', 'is-done');
    stepEl.classList.add(`is-${state}`);

    const stateEl = stepEl.querySelector('.scan-step-state');
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

function updateAssetScanStatus(message, progressValue) {
    const statusEl = document.getElementById('asset-scan-status');
    if (statusEl) {
        statusEl.textContent = message;
    }

    const progressEl = document.getElementById('asset-scan-progress-fill');
    if (progressEl) {
        const boundedProgress = Math.max(5, Math.min(100, Number(progressValue) || 5));
        progressEl.style.width = `${boundedProgress}%`;
    }
}

function appendAssetScanTerminalLine(line) {
    const outputEl = document.getElementById('asset-scan-terminal-output');
    if (!outputEl) {
        return;
    }

    const currentLines = outputEl.textContent.split('\n').filter(Boolean);
    const nextLines = [...currentLines, line].slice(-ASSET_SCAN_TERMINAL_LINE_LIMIT);
    outputEl.textContent = nextLines.join('\n');
    outputEl.scrollTop = outputEl.scrollHeight;
}

function startAssetScanTerminalSimulation() {
    stopAssetScanTerminalSimulation(false);
    assetScanTerminalSequenceToken += 1;

    const terminalShell = document.getElementById('asset-scan-terminal-shell');
    if (terminalShell) {
        terminalShell.open = true;
    }

    const outputEl = document.getElementById('asset-scan-terminal-output');
    if (outputEl) {
        outputEl.textContent = '[scan] Preparing scan workflow...';
    }
}
function stopAssetScanTerminalSimulation(autoCloseTerminal = true) {
    assetScanTerminalSequenceToken += 1;

    if (assetScanTerminalTimer) {
        window.clearInterval(assetScanTerminalTimer);
        assetScanTerminalTimer = null;
    }

    if (autoCloseTerminal) {
        const terminalShell = document.getElementById('asset-scan-terminal-shell');
        if (terminalShell) {
            terminalShell.open = false;
        }
    }
}
async function generateAssetTerminalOutput(preview) {
    const securityContext = preview?.securityContext || {};
    const observedOpenPorts = Array.isArray(securityContext?.liveScan?.observedOpenPorts)
        ? securityContext.liveScan.observedOpenPorts
        : [];
    const services = Array.isArray(securityContext?.liveScan?.services)
        ? securityContext.liveScan.services
        : [];
    const osInfo = securityContext?.liveScan?.osInfo || 'Unknown';
    const target = String(securityContext?.liveScan?.target || 'target asset').trim() || 'target asset';
    const token = assetScanTerminalSequenceToken;
    const sleep = (delayMs) => new Promise((resolve) => window.setTimeout(resolve, delayMs));
    const isCancelled = () => token !== assetScanTerminalSequenceToken;
    const appendStep = async (line, delayMs = ASSET_SCAN_TERMINAL_STEP_DELAY_MS) => {
        if (isCancelled()) {
            return false;
        }

        appendAssetScanTerminalLine(line);
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
    await appendStep(`[scan] Host ${target} is up.`);
    await appendStep('[scan] Reviewing discovered ports...');

    if (observedOpenPorts.length > 0) {
        await appendStep('PORT      STATE    SERVICE      VERSION');
        await appendStep('___________________________________________', 120);

        for (const port of observedOpenPorts.slice(0, 10)) {
            const portNum = String(port).padEnd(9);
            const serviceInfo = serviceMap[port] || 'unknown service';
            await appendStep(`${portNum} open     ${serviceInfo}`, 140);
        }

        if (observedOpenPorts.length > 10) {
            await appendStep(`... and ${observedOpenPorts.length - 10} more ports`);
        }
    } else {
        await appendStep('PORT      STATE    SERVICE');
        await appendStep('___________________________', 120);
        await appendStep('All observed ports filtered or closed.');
    }

    await appendStep('[scan] Fingerprinting services...');

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
    }

    await appendStep('[scan] Running OS detection...');
    await appendStep(osInfo && osInfo !== 'Unknown'
        ? `OS Detection: ${osInfo}`
        : 'OS Detection: Not enough fingerprint data to identify the OS.');
    await appendStep(`[scan] Scan complete at ${new Date().toLocaleTimeString()}.`);
}

function resetAssetScanWorkflow() {
    ['asset-step-discovery', 'asset-step-probe', 'asset-step-fingerprint', 'asset-step-summary'].forEach((stepId) => {
        setAssetScanStepState(stepId, 'pending');
    });

    updateAssetScanStatus('Preparing asset security scan...', 8);
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

function readAssetScanDurationMetrics() {
    try {
        const rawValue = localStorage.getItem(ASSET_SCAN_DURATION_METRICS_STORAGE_KEY);
        if (!rawValue) {
            return {};
        }

        return JSON.parse(rawValue) || {};
    } catch (error) {
        console.warn('Unable to read asset scan duration metrics:', error);
        return {};
    }
}

function writeAssetScanDurationMetrics(metrics = {}) {
    try {
        localStorage.setItem(ASSET_SCAN_DURATION_METRICS_STORAGE_KEY, JSON.stringify(metrics));
    } catch (error) {
        console.warn('Unable to store asset scan duration metrics:', error);
    }
}

function getEstimatedAssetScanDurationMs() {
    const metrics = readAssetScanDurationMetrics();
    const historicalAverageMs = toBoundedNumber(metrics.averageMs, ASSET_SCAN_DEFAULT_ESTIMATED_MS);
    const paddedEstimateMs = historicalAverageMs * 1.15;

    return Math.max(ASSET_SCAN_ESTIMATED_MIN_MS, Math.min(ASSET_SCAN_ESTIMATED_MAX_MS, paddedEstimateMs));
}

function recordAssetScanDuration(elapsedMs) {
    if (!Number.isFinite(elapsedMs) || elapsedMs <= 0) {
        return;
    }

    const metrics = readAssetScanDurationMetrics();
    const previousAverageMs = toBoundedNumber(metrics.averageMs, ASSET_SCAN_DEFAULT_ESTIMATED_MS);
    const previousSamples = toBoundedNumber(metrics.samples, 0);
    const smoothingFactor = 0.35;
    const nextAverageMs = (previousAverageMs * (1 - smoothingFactor)) + (elapsedMs * smoothingFactor);

    writeAssetScanDurationMetrics({
        averageMs: Math.round(nextAverageMs),
        samples: previousSamples + 1,
    });
}


function beginAssetScanProgress() {
    if (assetScanProgressTimer) {
        window.clearInterval(assetScanProgressTimer);
    }

    assetScanStartTime = Date.now();
    assetScanEstimatedDuration = getEstimatedAssetScanDurationMs();

    let currentProgress = 5;
    updateAssetScanStatus('Preparing asset security scan...', currentProgress);

    const etaEl = document.getElementById('asset-scan-eta');
    if (etaEl) {
        etaEl.textContent = `Estimated time remaining: ~${formatDurationMinutesSeconds(assetScanEstimatedDuration / 1000)}`;
    }

    updateAssetScanTimer();

    assetScanProgressTimer = window.setInterval(updateAssetScanTimer, 200);
}

function updateAssetScanTimer() {
    const elapsedMs = Date.now() - assetScanStartTime;
    if (elapsedMs > assetScanEstimatedDuration) {
        assetScanEstimatedDuration = elapsedMs + ASSET_SCAN_OVERRUN_BUFFER_MS;
    }

    let currentProgress = Math.min((elapsedMs / assetScanEstimatedDuration) * 100, 90);
    
    const remainingMs = Math.max(0, assetScanEstimatedDuration - elapsedMs);
    const remainingSeconds = Math.ceil(remainingMs / 1000);
    
    const etaEl = document.getElementById('asset-scan-eta');
    if (etaEl && remainingSeconds > 0) {
        etaEl.textContent = `Estimated time remaining: ${formatDurationMinutesSeconds(remainingSeconds)}`;
    }

    if (currentProgress >= 89) {
        updateAssetScanStatus('Finalizing scan results...', currentProgress);
    } else {
        updateAssetScanStatus('Scanning target and enriching vulnerability data...', currentProgress);
    }
}

function stopAssetScanProgress() {
    if (assetScanProgressTimer) {
        window.clearInterval(assetScanProgressTimer);
        assetScanProgressTimer = null;
    }
}
function showAssetScanWorkflowModal() {
    resetAssetScanWorkflow();
    showModal('asset-scan-modal');
    startAssetScanTerminalSimulation();
    beginAssetScanProgress();
}

function hideAssetScanWorkflowModal() {
    stopAssetScanProgress();
    stopAssetScanTerminalSimulation(false);
    hideModal('asset-scan-modal');
}

function applyScanPreviewToForm(previewPayload = {}) {
    const inferredProfile = previewPayload?.inferredProfile || {};
    const cveQuery = previewPayload?.cveResult?.query || {};
    const securityContext = previewPayload?.securityContext || {};
    const liveScan = securityContext?.liveScan || {};
    const scanResult = previewPayload?.scanResult || {};

    const openPorts = Array.isArray(liveScan.observedOpenPorts) && liveScan.observedOpenPorts.length > 0
        ? liveScan.observedOpenPorts
        : (Array.isArray(scanResult.openPorts) ? scanResult.openPorts : []);
    const openPortsText = openPorts.length > 0 ? openPorts.join(', ') : 'None identified';

    const services = Array.isArray(liveScan.services) && liveScan.services.length > 0
        ? liveScan.services
        : (Array.isArray(scanResult.services) ? scanResult.services : []);
    const serviceNames = [...new Set(services
        .map((service) => String(service?.service || '').trim())
        .filter(Boolean))];
    const servicesText = serviceNames.length > 0
        ? serviceNames.join(', ')
        : 'None identified';

    const previewOpenPortsEl = document.getElementById('asset-preview-open-ports');
    if (previewOpenPortsEl) {
        previewOpenPortsEl.value = openPortsText;
    }

    const previewServicesEl = document.getElementById('asset-preview-services');
    if (previewServicesEl) {
        previewServicesEl.value = servicesText;
    }

    document.getElementById('asset-live-scan-enabled').checked = true;

    const detectedOsName = liveScan.osInfo || scanResult.osInfo || inferredProfile.osName || '';
    const detectedVendor = cveQuery.vendor || inferredProfile.vendor || '';
    const detectedProduct = cveQuery.product || inferredProfile.product || '';
    const detectedProductVersion = cveQuery.productVersion || inferredProfile.productVersion || '';
    const detectedCpeUri = scanResult.osCpe || cveQuery.cpeUri || inferredProfile.cpeUri || '';

    document.getElementById('asset-os-name').value = detectedOsName;
    document.getElementById('asset-vendor').value = detectedVendor;
    document.getElementById('asset-product').value = detectedProduct;
    document.getElementById('asset-product-version').value = detectedProductVersion;
    document.getElementById('asset-cpe-uri').value = detectedCpeUri;

    applyDetectedCriticality(previewPayload);
}
function resetScanPreviewFields() {
    const previewOpenPortsEl = document.getElementById('asset-preview-open-ports');
    if (previewOpenPortsEl) {
        previewOpenPortsEl.value = '';
    }

    const previewServicesEl = document.getElementById('asset-preview-services');
    if (previewServicesEl) {
        previewServicesEl.value = '';
    }
}

function normalizeCpeUri(value) {
    const rawValue = String(value || '').trim();
    if (!rawValue) {
        return '';
    }

    const tokenMatch = rawValue.match(/(cpe:2\.3:[^\s,;]+|cpe:\/[^\s,;]+)/i);
    if (!tokenMatch) {
        return '';
    }

    return tokenMatch[1].replace(/[)\].,;\/]+$/, '');
}

function buildScanPreviewPayload() {
    const payload = {
        assetName: String(document.getElementById('asset-name').value || '').trim(),
        assetType: String(document.getElementById('asset-type').value || '').trim(),
        liveScan: {
            enabled: true,
            target: String(document.getElementById('asset-scan-target').value || '').trim(),
            ports: String(document.getElementById('asset-scan-ports').value || '').trim(),
            frequency: String(document.getElementById('asset-scan-frequency').value || DEFAULT_SCAN_FREQUENCY),
        },
        vulnerabilityProfile: {
            osName: String(document.getElementById('asset-os-name').value || '').trim(),
            vendor: String(document.getElementById('asset-vendor').value || '').trim(),
            product: String(document.getElementById('asset-product').value || '').trim(),
            productVersion: String(document.getElementById('asset-product-version').value || '').trim(),
            cpeUri: normalizeCpeUri(document.getElementById('asset-cpe-uri').value || ''),
        },
    };

    if (currentEditingAssetId) {
        payload.assetId = currentEditingAssetId;
    }

    return payload;
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

function redirectToLocalScannerSetup() {
    window.location.href = 'settings.html?tab=local-scanner&scanSetup=1';
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

async function runLiveScanPreview() {
    setScanDetailsVisibility(true);

    if (!isLocalScannerFetchAllowed()) {
        showNotification('Local scanner access requires HTTPS (Render URL) or localhost. Open the secure app URL and retry.', 'warning');
        return;
    }

    // A fresh live scan should be allowed to refresh criticality from detected findings.
    isCriticalityManuallyOverridden = false;

    const payload = buildScanPreviewPayload();
    if (!payload.liveScan.target) {
        showNotification('Scan target is required before running live scan', 'warning');
        return;
    }

    if (!isAllowedLiveScanTarget(payload.liveScan.target)) {
        showNotification('Only private/local network scan targets are allowed', 'error');
        return;
    }

    const isScannerOnline = await isLocalScannerReachable();
    if (!isScannerOnline) {
        const shouldRedirectToSetup = window.confirm(
            `Local scanner app is offline. Open Settings to set it up?\n\nYou can also download it here: ${LOCAL_SCANNER_REPO_URL}`
        );

        if (shouldRedirectToSetup) {
            redirectToLocalScannerSetup();
        }

        return;
    }

    showAssetScanWorkflowModal();

    try {
        setAssetScanStepState('asset-step-discovery', 'active');
        updateAssetScanStatus('Running security scan on target asset...', 20);

        setAssetScanStepState('asset-step-discovery', 'done');
        setAssetScanStepState('asset-step-probe', 'active');
        updateAssetScanStatus('Retrieving vulnerability profile for asset...', 44);

        const preview = await runLocalScannerPreview(payload);

        await generateAssetTerminalOutput(preview);
        stopAssetScanTerminalSimulation(false);

        setAssetScanStepState('asset-step-probe', 'done');
        setAssetScanStepState('asset-step-fingerprint', 'active');
        updateAssetScanStatus('Fingerprinting services and extracting OS details...', 68);

        applyScanPreviewToForm(preview);

        setAssetScanStepState('asset-step-fingerprint', 'done');
        setAssetScanStepState('asset-step-summary', 'active');
        updateAssetScanStatus('Populating asset form with detected data...', 90);
        setAssetScanStepState('asset-step-summary', 'done');
        updateAssetScanStatus('Scan complete. Asset data has been auto-filled.', 100);

        recordAssetScanDuration(Date.now() - assetScanStartTime);

        setTimeout(() => {
            hideAssetScanWorkflowModal();
        }, 280);

        showNotification('Scan completed. Detected data has been auto-filled.', 'success');
    } catch (error) {
        console.error('Asset scan preview error:', error);
        stopAssetScanProgress();
        stopAssetScanTerminalSimulation(false);
        hideAssetScanWorkflowModal();
        const errorMessage = String(error?.message || '').toLowerCase();
        if (errorMessage.includes('failed to fetch') || errorMessage.includes('private network')) {
            showNotification('Scan blocked by browser local-network restrictions. In Chrome, allow local network access for this site and retry.', 'warning');
            return;
        }

        showNotification('Scan failed. You can still enter details manually.', 'warning');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initializeAssets();
});

async function initializeAssets() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }

    setupUserInfo();
    setupLogoutButton();
    setupEventListeners();
    setupCriticalityOverrideTracking();
    await loadAssets();
}

function setupEventListeners() {
    const addBtn = document.getElementById('add-asset-btn');
    if (addBtn) {
        addBtn.addEventListener('click', openAssetModal);
    }

    const runLiveScanBtn = document.getElementById('asset-run-live-scan-btn');
    if (runLiveScanBtn) {
        runLiveScanBtn.addEventListener('click', runLiveScanPreview);
    }



    const enterManualBtn = document.getElementById('asset-enter-manual-btn');
    if (enterManualBtn) {
        enterManualBtn.addEventListener('click', () => {
            setScanDetailsVisibility(true);
            showNotification('You can now enter scan and software details manually.', 'info');
        });
    }

    const selectAllAssetsBtn = document.getElementById('select-all-assets-btn');
    if (selectAllAssetsBtn) {
        selectAllAssetsBtn.addEventListener('click', handleSelectAllAssetsClick);
    }

    const deleteAllAssetsBtn = document.getElementById('delete-all-assets-btn');
    if (deleteAllAssetsBtn) {
        deleteAllAssetsBtn.addEventListener('click', handleBulkDeleteAssets);
    }

    const modalClose = document.getElementById('modal-close');
    if (modalClose) {
        modalClose.addEventListener('click', closeAssetModal);
    }

    const cancelBtn = document.getElementById('cancel-btn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeAssetModal);
    }

    const modalOverlay = document.getElementById('modal-overlay');
    if (modalOverlay) {
        modalOverlay.addEventListener('click', closeAssetModal);
    }

    const assetForm = document.getElementById('asset-form');
    if (assetForm) {
        assetForm.addEventListener('submit', handleAssetFormSubmit);
    }

    const searchInput = document.getElementById('search-assets');
    if (searchInput) {
        searchInput.addEventListener('input', filterAssets);
    }

    const filterType = document.getElementById('filter-type');
    if (filterType) {
        filterType.addEventListener('change', filterAssets);
    }

    const filterStatus = document.getElementById('filter-status');
    if (filterStatus) {
        filterStatus.addEventListener('change', filterAssets);
    }

    const deleteConfirm = document.getElementById('delete-confirm');
    if (deleteConfirm) {
        deleteConfirm.addEventListener('click', confirmDelete);
    }

    const deleteCancel = document.getElementById('delete-cancel');
    if (deleteCancel) {
        deleteCancel.addEventListener('click', closeDeleteModal);
    }

    const deleteOverlay = document.getElementById('delete-overlay');
    if (deleteOverlay) {
        deleteOverlay.addEventListener('click', closeDeleteModal);
    }
}

async function loadAssets() {
    renderTableSkeleton('assets-tbody', 8, 4);

    try {
        assets = await apiClient.getAssets();
        displayAssets(assets);
    } catch (error) {
        console.error('Error loading assets:', error);
        showNotification('Error loading assets', 'error');
    }
}

function displayAssets(assetsToDisplay) {
    const tbody = document.getElementById('assets-tbody');
    tbody.innerHTML = '';

    if (!assetsToDisplay || assetsToDisplay.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No assets registered</td></tr>';
        updateSelectionState();
        return;
    }

    assetsToDisplay.forEach((asset) => {
        const isSelected = selectedAssetIds.has(asset._id);
        const selectButtonLabel = isSelected ? 'Unselect' : 'Select';
        const row = document.createElement('tr');
        row.style.cursor = 'pointer';
        row.innerHTML = `
            <td data-label="Select"><button type="button" class="btn btn-sm asset-select-btn ${isSelected ? 'is-selected' : ''}" data-asset-id="${asset._id}" aria-label="Select ${asset.assetName}" aria-pressed="${isSelected ? 'true' : 'false'}">${selectButtonLabel}</button></td>
            <td data-label="Asset Name">${asset.assetName}</td>
            <td data-label="Type">${asset.assetType}</td>
            <td data-label="Location">${asset.location || '-'}</td>
            <td data-label="Status"><span class="status-badge status-${asset.status.toLowerCase()}">${asset.status}</span></td>
            <td data-label="Criticality">${asset.criticality}</td>
            <td data-label="Owner">${asset.owner || '-'}</td>
            <td data-label="Actions">
                <div class="row-actions">
                    <button class="btn btn-sm btn-secondary" onclick="editAsset('${asset._id}')">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="openDeleteModal('${asset._id}')">Delete</button>
                </div>
            </td>
        `;

        row.addEventListener('click', (event) => {
            if (event.target.closest('.asset-select-btn') || event.target.closest('button')) {
                return;
            }

            editAsset(asset._id);
        });

        tbody.appendChild(row);
    });

    tbody.querySelectorAll('.asset-select-btn').forEach((selectButton) => {
        selectButton.addEventListener('click', (event) => {
            const assetId = event.currentTarget.dataset.assetId;
            const isSelected = selectedAssetIds.has(assetId);

            if (isSelected) {
                selectedAssetIds.delete(assetId);
            } else {
                selectedAssetIds.add(assetId);
            }

            updateAssetSelectButtonState(event.currentTarget, !isSelected);
            updateSelectionState();
        });
    });

    updateSelectionState();
}

function updateAssetSelectButtonState(selectButton, isSelected) {
    if (!selectButton) {
        return;
    }

    selectButton.classList.toggle('is-selected', isSelected);
    selectButton.textContent = isSelected ? 'Unselect' : 'Select';
    selectButton.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
}

function updateSelectionState() {
    const selectedCountEl = document.getElementById('selected-assets-count');
    if (selectedCountEl) {
        selectedCountEl.textContent = `${selectedAssetIds.size} selected`;
    }

    const selectAllBtn = document.getElementById('select-all-assets-btn');
    if (selectAllBtn) {
        const visibleSelectButtons = Array.from(document.querySelectorAll('.asset-select-btn'));
        const allVisibleSelected = visibleSelectButtons.length > 0 && visibleSelectButtons.every((button) => selectedAssetIds.has(button.dataset.assetId));
        selectAllBtn.textContent = allVisibleSelected ? 'Unselect All' : 'Select All';
    }
}

function handleSelectAllAssetsClick() {
    const visibleSelectButtons = Array.from(document.querySelectorAll('.asset-select-btn'));
    const allVisibleSelected = visibleSelectButtons.length > 0 && visibleSelectButtons.every((button) => selectedAssetIds.has(button.dataset.assetId));
    const shouldSelectAll = !allVisibleSelected;

    visibleSelectButtons.forEach((button) => {
        const assetId = button.dataset.assetId;
        if (shouldSelectAll) {
            selectedAssetIds.add(assetId);
        } else {
            selectedAssetIds.delete(assetId);
        }

        updateAssetSelectButtonState(button, shouldSelectAll);
    });

    updateSelectionState();
}

async function handleBulkDeleteAssets() {
    if (selectedAssetIds.size === 0) {
        showNotification('Select at least one asset to delete', 'warning');
        return;
    }

    currentEditingAssetId = null;
    pendingDeleteAssetIds = Array.from(selectedAssetIds);
    setDeleteConfirmationMessage(`Delete ${pendingDeleteAssetIds.length} selected assets? This action cannot be undone.`);
    showModal('delete-modal');
}

function filterAssets() {
    const searchQuery = document.getElementById('search-assets').value.toLowerCase();
    const typeFilter = document.getElementById('filter-type').value;
    const statusFilter = document.getElementById('filter-status').value;

    const filtered = assets.filter((asset) => {
        const matchesSearch = asset.assetName.toLowerCase().includes(searchQuery)
            || asset.description?.toLowerCase().includes(searchQuery);
        const matchesType = !typeFilter || asset.assetType === typeFilter;
        const matchesStatus = !statusFilter || asset.status === statusFilter;

        return matchesSearch && matchesType && matchesStatus;
    });

    displayAssets(filtered);
}

function openAssetModal() {
    currentEditingAssetId = null;
    document.getElementById('modal-title').textContent = 'Add New Asset';
    document.getElementById('asset-form').reset();
    resetScanPreviewFields();
    isCriticalityManuallyOverridden = false;
    setAssetModalMode(false);
    updateAssetScannerBadge();
    showModal('asset-modal');
}

function closeAssetModal() {
    hideModal('asset-modal');
    document.getElementById('asset-form').reset();
    currentEditingAssetId = null;
    resetScanPreviewFields();
    isCriticalityManuallyOverridden = false;
    setAssetModalMode(false);
}

async function editAsset(assetId) {
    try {
        const asset = await apiClient.getAsset(assetId);

        currentEditingAssetId = assetId;
        document.getElementById('modal-title').textContent = 'Edit Asset';

        document.getElementById('asset-name').value = asset.assetName;
        document.getElementById('asset-type').value = asset.assetType;
        document.getElementById('asset-location').value = asset.location || '';
        document.getElementById('asset-description').value = asset.description || '';
        document.getElementById('asset-criticality').value = asset.criticality;
        isCriticalityManuallyOverridden = false;
        document.getElementById('asset-owner').value = asset.owner || '';
        document.getElementById('asset-status').value = asset.status;

        const liveScan = asset.liveScan || {};
        const vulnerabilityProfile = asset.vulnerabilityProfile || {};

        document.getElementById('asset-live-scan-enabled').checked = Boolean(liveScan.enabled);
        document.getElementById('asset-scan-target').value = liveScan.target || '';
        document.getElementById('asset-scan-ports').value = liveScan.ports || '';
        document.getElementById('asset-scan-frequency').value = liveScan.frequency || DEFAULT_SCAN_FREQUENCY;

        document.getElementById('asset-os-name').value = vulnerabilityProfile.osName || '';
        document.getElementById('asset-vendor').value = vulnerabilityProfile.vendor || '';
        document.getElementById('asset-product').value = vulnerabilityProfile.product || '';
        document.getElementById('asset-product-version').value = vulnerabilityProfile.productVersion || '';
        document.getElementById('asset-cpe-uri').value = vulnerabilityProfile.cpeUri || '';

        const previewOpenPortsEl = document.getElementById('asset-preview-open-ports');
        if (previewOpenPortsEl) {
            previewOpenPortsEl.value = 'Run live scan to refresh';
        }

        const previewServicesEl = document.getElementById('asset-preview-services');
        if (previewServicesEl) {
            previewServicesEl.value = 'Run live scan to refresh';
        }

            setAssetModalMode(true);
        showModal('asset-modal');
    } catch (error) {
        console.error('Error loading asset:', error);
        showNotification('Error loading asset', 'error');
    }
}

async function handleAssetFormSubmit(e) {
    e.preventDefault();

    const formData = getFormData(e.target);
    const payload = {
        assetName: formData.assetName,
        assetType: formData.assetType,
        location: formData.location,
        description: formData.description,
        criticality: formData.criticality,
        owner: formData.owner,
        status: formData.status,
        liveScan: {
            enabled: document.getElementById('asset-live-scan-enabled').checked,
            target: (formData.scanTarget || '').trim(),
            ports: (formData.scanPorts || '').trim(),
            frequency: formData.scanFrequency || DEFAULT_SCAN_FREQUENCY,
        },
        vulnerabilityProfile: {
            osName: (formData.osName || '').trim(),
            vendor: (formData.vendor || '').trim(),
            product: (formData.product || '').trim(),
            productVersion: (formData.productVersion || '').trim(),
            cpeUri: (formData.cpeUri || '').trim(),
        },
    };

    if (payload.liveScan.enabled && !payload.liveScan.target) {
        showNotification('Scan target is required when live scan is enabled', 'error');
        return;
    }

    if (payload.liveScan.target && !isAllowedLiveScanTarget(payload.liveScan.target)) {
        showNotification('Only private/local network scan targets are allowed', 'error');
        return;
    }

    showLoading(true);

    try {
        if (currentEditingAssetId) {
            await apiClient.updateAsset(currentEditingAssetId, payload);
            showNotification('Asset updated successfully', 'success');
        } else {
            await apiClient.createAsset(payload);
            showNotification('Asset created successfully', 'success');
        }

        closeAssetModal();
        await loadAssets();
    } catch (error) {
        console.error('Error saving asset:', error);
        const errorMessage = String(error?.message || '').trim();
        showNotification(errorMessage || 'Error saving asset', 'error');
    } finally {
        showLoading(false);
    }
}

function openDeleteModal(assetId) {
    currentEditingAssetId = assetId;
    pendingDeleteAssetIds = [];
    setDeleteConfirmationMessage('Are you sure you want to delete this asset? This action cannot be undone.');
    showModal('delete-modal');
}

function closeDeleteModal() {
    hideModal('delete-modal');
    currentEditingAssetId = null;
    pendingDeleteAssetIds = [];
}

async function confirmDelete() {
    showLoading(true);

    try {
        if (pendingDeleteAssetIds.length > 0) {
            const deleteResults = await Promise.allSettled(pendingDeleteAssetIds.map((assetId) => apiClient.deleteAsset(assetId)));
            const deletedCount = deleteResults.filter((result) => result.status === 'fulfilled').length;
            const failedCount = deleteResults.length - deletedCount;

            pendingDeleteAssetIds.forEach((assetId) => selectedAssetIds.delete(assetId));
            updateSelectionState();

            if (failedCount > 0) {
                showNotification(`Deleted ${deletedCount} assets, ${failedCount} failed`, 'warning');
            } else {
                showNotification(`Deleted ${deletedCount} assets successfully`, 'success');
            }
        } else if (currentEditingAssetId) {
            await apiClient.deleteAsset(currentEditingAssetId);
            selectedAssetIds.delete(currentEditingAssetId);
            updateSelectionState();
            showNotification('Asset deleted successfully', 'success');
        }

        closeDeleteModal();
        await loadAssets();
    } catch (error) {
        console.error('Error deleting asset:', error);
        showNotification('Error deleting asset', 'error');
    } finally {
        showLoading(false);
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

function setDeleteConfirmationMessage(message) {
    const messageEl = document.getElementById('delete-confirmation-message');
    if (messageEl) {
        messageEl.textContent = message;
    }
}




