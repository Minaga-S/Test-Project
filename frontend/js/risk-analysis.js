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
const MOBILE_BREAKPOINT = 768;

let charts = {};
let chartJsLoadPromise = null;

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
        exportBtn.addEventListener('click', exportRiskReport);
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
            .map((asset) => `<p>- ${asset.assetName}</p>`)
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
        <div class="priority-item ${item.riskLevel.toLowerCase()}">
            <div>
                <strong>${item.riskLevel} Priority</strong>
                <p>${item.recommendation}</p>
            </div>
            <small>${item.incidentId} • ${item.threatType}</small>
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
        const row = document.createElement('tr');
        row.innerHTML = `
            <td data-label="Incident ID">${incident.incidentId || 'N/A'}</td>
            <td data-label="Asset">${incident.asset?.assetName || 'Unknown'}</td>
            <td data-label="Threat Type">${incident.threatType || 'Unknown'}</td>
            <td data-label="Likelihood">${incident.likelihood || 0}/4</td>
            <td data-label="Impact">${incident.impact || 0}/4</td>
            <td data-label="Risk Score"><strong class="animated-risk-score" data-target-score="${incident.riskScore || 0}">0</strong></td>
            <td data-label="Risk Level"><span style="color: ${getRiskColor(incident.riskLevel)}; font-weight: 600;">${incident.riskLevel || 'Low'}</span></td>
            <td data-label="Priority">${incident.riskLevel === 'Critical' ? 'Urgent' : incident.riskLevel === 'High' ? 'High' : incident.riskLevel === 'Medium' ? 'Medium' : 'Low'}</td>
        `;
        tbody.appendChild(row);

        const animatedScoreEl = row.querySelector('.animated-risk-score');
        animateCountUp(animatedScoreEl, incident.riskScore || 0, 800);
    });
}

function exportRiskReport() {
    const incidents = Array.from(document.querySelectorAll('#risk-breakdown-tbody tr'))
        .map((row) => {
            const cells = row.querySelectorAll('td');
            return {
                'Incident ID': cells[0]?.textContent || '',
                'Asset': cells[1]?.textContent || '',
                'Threat': cells[2]?.textContent || '',
                'Likelihood': cells[3]?.textContent || '',
                'Impact': cells[4]?.textContent || '',
                'Risk Score': cells[5]?.textContent || '',
                'Risk Level': cells[6]?.textContent || '',
            };
        })
        .filter((item) => item['Incident ID']);

    exportToCSV('risk-analysis-report.csv', incidents);
    showNotification('Risk report exported successfully', 'success');
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




