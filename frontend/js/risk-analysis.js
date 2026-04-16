/**
 * Risk Analysis Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.
/**
 * SECTION GUIDE:
 * 1) Analysis Boot: validates auth and initializes widgets.
 * 2) Data Aggregation: fetches matrix/distribution/trends in parallel.
 * 3) Visualization: renders risk charts and asset breakdowns.
 * 4) Reporting: builds export output for risk review workflows.
 */



const CHART_JS_URL = 'https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js';
const JSPDF_URL = 'https://cdn.jsdelivr.net/npm/jspdf@2.5.1/dist/jspdf.umd.min.js';
const MOBILE_BREAKPOINT = 768;

let charts = {};
let chartJsLoadPromise = null;
let jsPdfLoadPromise = null;

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function sanitizeClassToken(value, fallback = 'unknown') {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized) {
        return fallback;
    }

    const sanitized = normalized.replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    return sanitized || fallback;
}

document.addEventListener('DOMContentLoaded', () => {
    initializeRiskAnalysis();
});

async function initializeRiskAnalysis() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }

    setupUserInfo();
    setupLogoutButton();
    setupEventListeners();
    setupCollapsiblePanels();
    await loadRiskData();
}

function setupEventListeners() {
    const exportBtn = document.getElementById('export-risk-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', openRiskExportModal);
    }

    const riskExportClose = document.getElementById('risk-export-close');
    if (riskExportClose) {
        riskExportClose.addEventListener('click', closeRiskExportModal);
    }

    const riskExportCancel = document.getElementById('risk-export-cancel');
    if (riskExportCancel) {
        riskExportCancel.addEventListener('click', closeRiskExportModal);
    }

    const riskExportOverlay = document.getElementById('risk-export-overlay');
    if (riskExportOverlay) {
        riskExportOverlay.addEventListener('click', closeRiskExportModal);
    }

    const riskExportCsvButton = document.getElementById('risk-export-csv-btn');
    if (riskExportCsvButton) {
        riskExportCsvButton.addEventListener('click', () => {
            handleComplianceExport('csv');
        });
    }

    const riskExportJsonButton = document.getElementById('risk-export-json-btn');
    if (riskExportJsonButton) {
        riskExportJsonButton.addEventListener('click', () => {
            handleComplianceExport('json');
        });
    }

    const riskExportPdfButton = document.getElementById('risk-export-pdf-btn');
    if (riskExportPdfButton) {
        riskExportPdfButton.addEventListener('click', () => {
            handleComplianceExport('pdf');
        });
    }
}

function setupCollapsiblePanels() {
    const toggles = document.querySelectorAll('.collapsible-toggle');

    toggles.forEach((toggle) => {
        toggle.addEventListener('click', () => {
            const panel = toggle.closest('.collapsible-panel');
            if (!panel) return;

            const isCollapsed = panel.classList.toggle('collapsed');
            toggle.setAttribute('aria-expanded', String(!isCollapsed));

            if (!isCollapsed) {
                setTimeout(() => {
                    Object.values(charts).forEach((chart) => {
                        if (chart && chart.resize) {
                            chart.resize();
                        }
                    });
                }, 150);
            }
        });
    });
}

async function ensureChartJsLoaded() {
    if (window.Chart) {
        return;
    }

    if (!chartJsLoadPromise) {
        // Shared promise guarantees only one script injection even when multiple
        // widgets request charts concurrently.
        chartJsLoadPromise = new Promise((resolve, reject) => {
            const existingScript = document.querySelector(`script[src="${CHART_JS_URL}"]`);
            if (existingScript) {
                existingScript.addEventListener('load', () => resolve(), { once: true });
                existingScript.addEventListener('error', () => reject(new Error('Failed to load Chart.js')), { once: true });
                return;
            }

            const script = document.createElement('script');
            script.src = CHART_JS_URL;
            script.defer = true;
            script.onload = () => resolve();
            script.onerror = () => reject(new Error('Failed to load Chart.js'));
            document.head.appendChild(script);
        });
    }

    await chartJsLoadPromise;
}

async function ensureJsPdfLoaded() {
    if (window.jspdf?.jsPDF) {
        return;
    }

    if (!jsPdfLoadPromise) {
        // Mirror chart loader behavior so export actions cannot race and append
        // duplicate jsPDF script tags.
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

async function loadRiskData() {
    // Load all risk widgets together so the page stays consistent and finishes faster.
    renderTableSkeleton('risk-breakdown-tbody', 8, 4);

    try {
        const [
            riskMatrixResponse,
            riskDistributionResponse,
            riskTrendsResponse,
            assetRisksResponse,
            incidentsResponse,
        ] = await Promise.all([
            apiClient.getRiskMatrix(),
            apiClient.getRiskDistributionChart(),
            apiClient.getRiskTrends(),
            apiClient.getRiskByAsset(),
            apiClient.getIncidents(),
        ]);

        // Normalize API shapes so UI still works if endpoints return wrapped or direct payloads.
        const riskMatrix = riskMatrixResponse?.matrix || [];
        const riskDistribution = riskDistributionResponse?.chart || riskDistributionResponse || {};
        const riskTrends = riskTrendsResponse || {};
        const assetRisks = assetRisksResponse?.assetRisks || [];
        const incidents = Array.isArray(incidentsResponse)
            ? incidentsResponse
            : (Array.isArray(incidentsResponse?.incidents) ? incidentsResponse.incidents : []);

        await ensureChartJsLoaded();

        displayRiskMatrix(riskMatrix);
        displayRiskDistribution(riskDistribution);
        displayRiskTrends(riskTrends);
        displayAssetRisks(assetRisks);
        displayRecommendationsPriority(incidents);
        displayRiskBreakdown(incidents);
    } catch (error) {
        console.error('Error loading risk data:', error);
        showNotification('Error loading risk analysis', 'error');
    }
}

function getRiskColor(level) {
    const levelMap = {
        Critical: '#E53E3E',
        High: '#F56565',
        Medium: '#ED8936',
        Low: '#48BB78',
    };

    return levelMap[level] || '#718096';
}

function displayRiskMatrix(matrixData) {
    // Bubble chart visualizes where incidents sit on likelihood (x) and impact (y).
    const canvas = document.getElementById('risk-matrix-chart');
    if (!canvas) return;

    const points = Array.isArray(matrixData)
        ? matrixData.map((item) => ({
            x: Number(item.x) || 1,
            y: Number(item.y) || 1,
            r: Number(item.r) || 10,
            label: item.label || 'Incident',
            riskLevel: item.riskLevel || 'Low',
            threatType: item.threatType || 'Unknown',
        }))
        : [];

    const ctx = canvas.getContext('2d');
    if (charts.riskMatrix) charts.riskMatrix.destroy();

    charts.riskMatrix = new Chart(ctx, {
        type: 'bubble',
        data: {
            datasets: [{
                label: 'Risk Matrix',
                data: points,
                backgroundColor: points.map((point) => getRiskColor(point.riskLevel)),
                borderColor: '#FFFFFF',
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false,
                },
                tooltip: {
                    backgroundColor: 'rgba(45, 55, 72, 0.95)',
                    padding: 12,
                    borderRadius: 8,
                    titleFont: {
                        size: 13,
                        weight: 600,
                    },
                    bodyFont: {
                        size: 12,
                    },
                    callbacks: {
                        label: (context) => {
                            const riskPoint = context.raw || {};
                            return `${riskPoint.threatType || 'Unknown'} (${riskPoint.riskLevel || 'Low'})`;
                        },
                    },
                },
            },
            scales: {
                x: {
                    type: 'linear',
                    position: 'bottom',
                    title: {
                        display: true,
                        text: 'Likelihood',
                        font: {
                            size: 13,
                            weight: 600,
                        },
                        color: '#2D3748',
                    },
                    ticks: {
                        color: '#718096',
                    },
                    grid: {
                        color: 'rgba(203, 213, 225, 0.2)',
                        drawBorder: false,
                    },
                    min: 0,
                    max: 4,
                },
                y: {
                    title: {
                        display: true,
                        text: 'Impact',
                        font: {
                            size: 13,
                            weight: 600,
                        },
                        color: '#2D3748',
                    },
                    ticks: {
                        color: '#718096',
                    },
                    grid: {
                        color: 'rgba(203, 213, 225, 0.2)',
                        drawBorder: false,
                    },
                    min: 0,
                    max: 4,
                },
            },
        },
    });
}

function displayRiskDistribution(data) {
    const canvas = document.getElementById('risk-distribution-chart');
    if (!canvas) return;

    const labels = Array.isArray(data?.labels) ? data.labels : [];
    const values = Array.isArray(data?.data) ? data.data : [];

    const ctx = canvas.getContext('2d');
    if (charts.riskDistribution) charts.riskDistribution.destroy();

    charts.riskDistribution = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: ['#F56565', '#ED8936', '#5B8DEE', '#48BB78'],
                borderColor: '#FFFFFF',
                borderWidth: 2,
                borderRadius: 6,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12,
                        },
                        color: '#4A5568',
                    },
                },
                tooltip: {
                    backgroundColor: 'rgba(45, 55, 72, 0.95)',
                    padding: 12,
                    borderRadius: 8,
                    titleFont: {
                        size: 13,
                        weight: 600,
                    },
                    bodyFont: {
                        size: 12,
                    },
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((sum, val) => sum + val, 0);
                            const percentage = Math.round((context.parsed * 100) / total);
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        },
                    },
                },
            },
        },
    });
}

function displayRiskTrends(data) {
    const canvas = document.getElementById('risk-trends-chart');
    if (!canvas) return;

    const labels = Array.isArray(data?.labels) ? data.labels : [];
    const values = Array.isArray(data?.data) ? data.data : [];

    const ctx = canvas.getContext('2d');
    if (charts.riskTrends) charts.riskTrends.destroy();

    charts.riskTrends = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Risk Score Trend',
                data: values,
                borderColor: '#4070FF',
                backgroundColor: 'rgba(64, 112, 255, 0.1)',
                tension: 0.4,
                fill: true,
                borderWidth: 3,
                pointRadius: 5,
                pointBackgroundColor: '#4070FF',
                pointBorderColor: '#FFFFFF',
                pointBorderWidth: 2,
                pointHoverRadius: 7,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        padding: 15,
                        font: {
                            size: 12,
                        },
                        color: '#4A5568',
                    },
                },
                tooltip: {
                    backgroundColor: 'rgba(45, 55, 72, 0.95)',
                    padding: 12,
                    borderRadius: 8,
                    titleFont: {
                        size: 13,
                        weight: 600,
                    },
                    bodyFont: {
                        size: 12,
                    },
                },
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#718096',
                        font: {
                            size: 11,
                        },
                    },
                    grid: {
                        color: 'rgba(203, 213, 225, 0.3)',
                        drawBorder: false,
                    },
                },
                x: {
                    ticks: {
                        color: '#718096',
                        font: {
                            size: 11,
                        },
                    },
                    grid: {
                        display: false,
                        drawBorder: false,
                    },
                },
            },
        },
    });
}

function displayAssetRisks(assetRisks) {
    const riskLevels = ['Critical', 'High', 'Medium', 'Low'];
    const safeAssetRisks = Array.isArray(assetRisks) ? assetRisks : [];

    riskLevels.forEach((level) => {
        const container = document.getElementById(`${level.toLowerCase()}-assets-list`);
        if (!container) return;

        const assetsOfLevel = safeAssetRisks.filter((asset) => asset.riskLevel === level);
        if (assetsOfLevel.length === 0) {
            container.innerHTML = '<p>No assets</p>';
            return;
        }

        container.innerHTML = assetsOfLevel
            .slice(0, 8)
            .map((asset) => `<p>- ${escapeHtml(asset.assetName || 'Unknown')}</p>`)
            .join('');
    });
}

function displayRecommendationsPriority(incidents) {
    // Prioritize recommendations by risk level so responders handle the most urgent items first.
    const container = document.getElementById('recommendations-priority-list');
    if (!container) return;

    const incidentList = Array.isArray(incidents) ? incidents : [];

    const ranked = incidentList
        .map((incident) => ({
            incidentId: incident.incidentId || 'N/A',
            riskLevel: incident.riskLevel || 'Low',
            threatType: incident.threatType || 'Unknown',
            recommendation: incident.recommendations?.[0]
                || 'Review containment steps and harden the affected system.',
        }))
        .sort((a, b) => {
            const score = { Critical: 4, High: 3, Medium: 2, Low: 1 };
            return (score[b.riskLevel] || 0) - (score[a.riskLevel] || 0);
        })
        .slice(0, 8);

    if (ranked.length === 0) {
        container.innerHTML = '<p>No recommendations available.</p>';
        return;
    }

    container.innerHTML = ranked.map((item) => `
        <div class="priority-item ${sanitizeClassToken(item.riskLevel, 'low')}">
            <div>
                <strong>${escapeHtml(item.riskLevel)} Priority</strong>
                <p>${escapeHtml(item.recommendation)}</p>
            </div>
            <small>${escapeHtml(item.incidentId)} • ${escapeHtml(item.threatType)}</small>
        </div>
    `).join('');
}

function displayRiskBreakdown(incidents) {
    // Tabular breakdown gives auditors and operators exact scoring inputs per incident.
    const tbody = document.getElementById('risk-breakdown-tbody');
    if (!tbody) return;

    const incidentList = Array.isArray(incidents) ? incidents : [];
    tbody.innerHTML = '';

    if (incidentList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No incidents</td></tr>';
        return;
    }

    incidentList.forEach((incident) => {
        const safeIncidentId = escapeHtml(incident.incidentId || 'N/A');
        const safeAssetName = escapeHtml(incident.asset?.assetName || 'Unknown');
        const safeThreatType = escapeHtml(incident.threatType || 'Unknown');
        const safeLikelihood = escapeHtml(`${incident.likelihood || 0}`);
        const safeImpact = escapeHtml(`${incident.impact || 0}`);
        const safeRiskScore = escapeHtml(`${incident.riskScore || 0}`);
        const safeRiskLevel = escapeHtml(incident.riskLevel || 'Low');
        const riskPriority = incident.riskLevel === 'Critical' ? 'Urgent' : incident.riskLevel === 'High' ? 'High' : incident.riskLevel === 'Medium' ? 'Medium' : 'Low';
        const safeRiskPriority = escapeHtml(riskPriority);
        const row = document.createElement('tr');
        row.innerHTML = `
            <td data-label="Incident ID">${safeIncidentId}</td>
            <td data-label="Asset">${safeAssetName}</td>
            <td data-label="Threat Type">${safeThreatType}</td>
            <td data-label="Likelihood">${safeLikelihood}/4</td>
            <td data-label="Impact">${safeImpact}/4</td>
            <td data-label="Risk Score"><strong class="animated-risk-score" data-target-score="${safeRiskScore}">0</strong></td>
            <td data-label="Risk Level"><span style="color: ${getRiskColor(incident.riskLevel)}; font-weight: 600;">${safeRiskLevel}</span></td>
            <td data-label="Priority">${safeRiskPriority}</td>
        `;
        tbody.appendChild(row);

        const animatedScoreEl = row.querySelector('.animated-risk-score');
        animateCountUp(animatedScoreEl, incident.riskScore || 0, 800);
    });
}

function openRiskExportModal() {
    showModal('risk-export-modal');
}

function closeRiskExportModal() {
    hideModal('risk-export-modal');
}

async function handleComplianceExport(exportFormat = 'csv') {
    const format = String(exportFormat || 'csv').trim().toLowerCase();

    try {
        showLoading(true);
        const reportResponse = await apiClient.getComplianceReport('json');
        const payload = {
            generatedAt: reportResponse?.generatedAt || new Date().toISOString(),
            incidentCount: reportResponse?.incidentCount || 0,
            summary: reportResponse?.report?.summary || '',
            functions: reportResponse?.report?.functions || {},
            controls: reportResponse?.report?.controls || {},
        };

        if (format === 'json') {
            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
            downloadBlob(blob, 'compliance-report.json');
        } else if (format === 'pdf') {
            await exportCompliancePdf(payload);
        } else {
            const rows = [
                { Section: 'Summary', Key: 'GeneratedAt', Value: payload.generatedAt },
                { Section: 'Summary', Key: 'IncidentCount', Value: payload.incidentCount },
                { Section: 'Summary', Key: 'Coverage', Value: payload.summary },
                ...Object.entries(payload.functions).map(([key, value]) => ({ Section: 'Functions', Key: key, Value: value })),
                ...Object.entries(payload.controls).map(([key, value]) => ({ Section: 'Controls', Key: key, Value: value })),
            ];
            exportToCSV('compliance-report.csv', rows);
        }

        closeRiskExportModal();
        showNotification('Compliance report exported successfully', 'success');
    } catch (error) {
        console.error('Compliance report export failed:', error);
        showNotification('Failed to export compliance report', 'error');
    } finally {
        showLoading(false);
    }
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

async function exportCompliancePdf(payload) {
    await ensureJsPdfLoaded();
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    let y = 20;
    doc.setFontSize(16);
    doc.text('Compliance Report', 14, y);

    y += 10;
    doc.setFontSize(11);
    doc.text(`Generated: ${payload.generatedAt}`, 14, y);
    y += 7;
    doc.text(`Incident Count: ${payload.incidentCount}`, 14, y);
    y += 7;
    doc.text(`Coverage: ${payload.summary}`, 14, y, { maxWidth: 180 });

    y += 12;
    doc.setFontSize(13);
    doc.text('Function Coverage', 14, y);
    y += 8;
    doc.setFontSize(11);
    Object.entries(payload.functions).forEach(([name, count]) => {
        doc.text(`${name}: ${count}`, 16, y);
        y += 6;
    });

    y += 4;
    doc.setFontSize(13);
    doc.text('Control Coverage', 14, y);
    y += 8;
    doc.setFontSize(11);
    Object.entries(payload.controls).forEach(([name, count]) => {
        if (y > 275) {
            doc.addPage();
            y = 20;
        }
        doc.text(`${name}: ${count}`, 16, y);
        y += 6;
    });

    doc.save('compliance-report.pdf');
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

window.addEventListener('resize', () => {
    Object.values(charts).forEach((chart) => {
        if (chart && chart.resize) {
            chart.resize();
        }
    });
});




