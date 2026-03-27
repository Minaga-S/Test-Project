/**
 * Risk Analysis Handler
 */

let charts = {};

document.addEventListener('DOMContentLoaded', () => {
    initializeRiskAnalysis();
});

async function initializeRiskAnalysis() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'index.html';
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

async function loadRiskData() {
    showLoading(true);

    try {
        const [
            riskMatrix,
            riskDistribution,
            riskTrends,
            assetRisks,
            incidents,
        ] = await Promise.all([
            apiClient.getRiskMatrix(),
            apiClient.getRiskDistributionChart(),
            apiClient.getRiskTrends(),
            apiClient.getRiskByAsset(),
            apiClient.getIncidents(),
        ]);

        displayRiskMatrix(riskMatrix);
        displayRiskDistribution(riskDistribution);
        displayRiskTrends(riskTrends);
        displayAssetRisks(assetRisks);
        displayRecommendationsPriority(incidents);
        displayRiskBreakdown(incidents);
    } catch (error) {
        console.error('Error loading risk data:', error);
        showNotification('Error loading risk analysis', 'error');
    } finally {
        showLoading(false);
    }
}

function displayRiskMatrix(data) {
    if (!data) return;

    const canvas = document.getElementById('risk-matrix-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (charts.riskMatrix) charts.riskMatrix.destroy();

    charts.riskMatrix = new Chart(ctx, {
        type: 'bubble',
        data: {
            datasets: [{
                label: 'Risk Matrix',
                data: data.points || [],
                backgroundColor: data.colors || '#0f766e',
                borderColor: '#0f172a',
                borderWidth: 1,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false,
                },
                tooltip: {
                    callbacks: {
                        label: (context) => context.raw.label || '',
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
                    },
                    min: 0,
                    max: 4,
                },
                y: {
                    title: {
                        display: true,
                        text: 'Impact',
                    },
                    min: 0,
                    max: 4,
                },
            },
        },
    });
}

function displayRiskDistribution(data) {
    if (!data) return;

    const canvas = document.getElementById('risk-distribution-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (charts.riskDistribution) charts.riskDistribution.destroy();

    charts.riskDistribution = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.labels || [],
            datasets: [{
                data: data.data || [],
                backgroundColor: ['#b91c1c', '#dc2626', '#d97706', '#15803d'],
                borderColor: '#fff',
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                },
            },
        },
    });
}

function displayRiskTrends(data) {
    if (!data) return;

    const canvas = document.getElementById('risk-trends-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (charts.riskTrends) charts.riskTrends.destroy();

    charts.riskTrends = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [{
                label: 'Risk Score Trend',
                data: data.data || [],
                borderColor: '#dc2626',
                backgroundColor: 'rgba(220, 38, 38, 0.12)',
                tension: 0.4,
                fill: true,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false,
                },
            },
            scales: {
                y: {
                    beginAtZero: true,
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
            <td>${incident.incidentId || 'N/A'}</td>
            <td>${incident.asset?.assetName || 'Unknown'}</td>
            <td>${incident.threatType || 'Unknown'}</td>
            <td>${incident.likelihood || 0}/4</td>
            <td>${incident.impact || 0}/4</td>
            <td><strong>${incident.riskScore || 0}</strong></td>
            <td><span style="color: ${getRiskColor(incident.riskLevel)}; font-weight: 600;">${incident.riskLevel || 'Low'}</span></td>
            <td>${incident.riskLevel === 'Critical' ? 'Urgent' : incident.riskLevel === 'High' ? 'High' : incident.riskLevel === 'Medium' ? 'Medium' : 'Low'}</td>
        `;
        tbody.appendChild(row);
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
