/**
 * Risk Analysis Handler
 */

let riskData = [];
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
    await loadRiskData();
}

function setupEventListeners() {
    const exportBtn = document.getElementById('export-risk-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportRiskReport);
    }
}

async function loadRiskData() {
    showLoading(true);

    try {
        // Load risk matrix data
        const riskMatrix = await apiClient.getRiskMatrix();
        displayRiskMatrix(riskMatrix);

        // Load risk distribution
        const riskDistribution = await apiClient.getRiskDistributionChart();
        displayRiskDistribution(riskDistribution);

        // Load risk trends
        const riskTrends = await apiClient.getRiskTrends();
        displayRiskTrends(riskTrends);

        // Load asset risks
        const assetRisks = await apiClient.getRiskByAsset();
        displayAssetRisks(assetRisks);

        // Load risk breakdown
        const incidents = await apiClient.getIncidents();
        displayRiskBreakdown(incidents);

    } catch (error) {
        console.error('Error loading risk data:', error);
        showNotification('Error loading risk analysis', 'error');
    } finally {
        showLoading(false);
    }
}

function displayRiskMatrix(data) {
    const container = document.getElementById('risk-matrix-chart');
    if (!container || !data) return;

    const canvas = container;
    const ctx = canvas.getContext('2d');

    // Destroy existing chart
    if (charts.riskMatrix) charts.riskMatrix.destroy();

    charts.riskMatrix = new Chart(ctx, {
        type: 'bubble',
        data: {
            datasets: [{
                label: 'Risk Matrix',
                data: data.points || [],
                backgroundColor: data.colors || '#27ae60',
                borderColor: '#000',
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
                        label: function(context) {
                            return context.raw.label || '';
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

    destroyChart('risk-distribution-chart');

    const ctx = document.getElementById('risk-distribution-chart').getContext('2d');
    const colors = ['#c0392b', '#e74c3c', '#f39c12', '#27ae60'];

    charts.riskDistribution = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.data,
                backgroundColor: colors,
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

    destroyChart('risk-trends-chart');

    const ctx = document.getElementById('risk-trends-chart').getContext('2d');

    charts.riskTrends = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Risk Score Trend',
                data: data.data,
                borderColor: '#e74c3c',
                backgroundColor: 'rgba(231, 76, 60, 0.1)',
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
    
    riskLevels.forEach(level => {
        const containerId = `${level.toLowerCase()}-assets-list`;
        const container = document.getElementById(containerId);
        
        if (container) {
            const assetsOfLevel = assetRisks.filter(a => a.riskLevel === level);
            
            if (assetsOfLevel.length === 0) {
                container.innerHTML = '<p>No assets</p>';
            } else {
                container.innerHTML = assetsOfLevel
                    .map(a => `<p>• ${a.assetName}</p>`)
                    .join('');
            }
        }
    });
}

function displayRiskBreakdown(incidents) {
    const tbody = document.getElementById('risk-breakdown-tbody');
    tbody.innerHTML = '';

    if (!incidents || incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No incidents</td></tr>';
        return;
    }

    incidents.forEach(incident => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${incident.incidentId}</td>
            <td>${incident.asset?.assetName || 'Unknown'}</td>
            <td>${incident.threatType}</td>
            <td>${incident.likelihood}/4</td>
            <td>${incident.impact}/4</td>
            <td><strong>${incident.riskScore}</strong></td>
            <td><span style="color: ${getRiskColor(incident.riskLevel)}; font-weight: 600;">${incident.riskLevel}</span></td>
            <td>${incident.riskLevel === 'Critical' ? '🔴 Urgent' : incident.riskLevel === 'High' ? '🟠 High' : incident.riskLevel === 'Medium' ? '🟡 Medium' : '🟢 Low'}</td>
        `;
        tbody.appendChild(row);
    });
}

function exportRiskReport() {
    const incidents = Array.from(document.querySelectorAll('#risk-breakdown-tbody tr'))
        .map(row => {
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
        });

    exportToCSV('risk-analysis-report.csv', incidents);
    showNotification('Risk report exported successfully', 'success');
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