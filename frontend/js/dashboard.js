/**
 * Dashboard Page Handler
 */

let dashboardCharts = {};

document.addEventListener('DOMContentLoaded', () => {
    initializeDashboard();
});

async function initializeDashboard() {
    // Check authentication
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'index.html';
        return;
    }

    // Setup user info
    await displayUserInfo();

    // Setup logout button
    setupLogoutButton();

    // Setup collapsible sections
    setupCollapsiblePanels();

    // Load dashboard data
    await loadDashboardData();
}

async function displayUserInfo() {
    try {
        const profileResponse = getLocalStorage('user') || await apiClient.getProfile();
        const user = profileResponse?.user || profileResponse;
        
        if (user) {
            document.getElementById('user-name').textContent = user.fullName || user.email;
            const initial = (user.fullName || user.email)[0].toUpperCase();
            document.getElementById('user-initial').textContent = initial;
            setLocalStorage('user', user);
        }
    } catch (error) {
        console.error('Error loading user info:', error);
    }
}

function setupLogoutButton() {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.type = 'button';
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
                    Object.values(dashboardCharts).forEach((chart) => {
                        if (chart && chart.resize) {
                            chart.resize();
                        }
                    });
                }, 150);
            }
        });
    });
}

async function loadDashboardData() {
    showLoading(true);

    try {
        // Load metrics
        const metricsResponse = await apiClient.getDashboardMetrics();
        const metrics = metricsResponse?.metrics || metricsResponse || {};
        displayMetrics(metrics);

        // Load recent incidents
        const incidentsResponse = await apiClient.getRecentIncidents();
        const incidents = Array.isArray(incidentsResponse)
            ? incidentsResponse
            : (Array.isArray(incidentsResponse?.incidents) ? incidentsResponse.incidents : []);
        displayRecentIncidents(incidents);

        // Load charts
        await loadCharts();

    } catch (error) {
        console.error('Error loading dashboard:', error);
        showNotification('Error loading dashboard data', 'error');
    } finally {
        showLoading(false);
    }
}

function displayMetrics(metrics) {
    const elements = {
        'total-assets': metrics.totalAssets || 0,
        'open-incidents': metrics.openIncidents || 0,
        'critical-risks': metrics.criticalRisks || 0,
        'resolved-issues': metrics.resolvedIssues || 0,
    };

    Object.entries(elements).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value;
        }
    });
}

function displayRecentIncidents(incidents) {
    const tbody = document.getElementById('recent-incidents-tbody');
    const incidentList = Array.isArray(incidents) ? incidents : [];
    const summary = document.getElementById('dashboard-recent-incidents-summary');

    if (summary) {
        if (incidentList.length === 0) {
            summary.innerHTML = '<span class="summary-badge severity-low">0 incidents</span>';
        } else {
            const severity = getHighestRiskLevel(incidentList.map((item) => item.riskLevel));
            summary.innerHTML = `<span class="summary-badge severity-${severity.toLowerCase()}">${incidentList.length} incidents</span>`;
        }
    }
    
    if (incidentList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No recent incidents</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    incidentList.slice(0, 5).forEach(incident => {
        const riskLevel = incident.riskLevel || 'Low';
        const status = incident.status || 'Open';
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${incident.incidentId}</td>
            <td>${incident.asset?.assetName || 'Unknown'}</td>
            <td>${incident.threatType || 'Unknown'}</td>
            <td><span class="risk-${riskLevel.toLowerCase()}">${riskLevel}</span></td>
            <td><span class="status-badge status-${status}">${status}</span></td>
            <td>${formatDate(incident.createdAt)}</td>
            <td>
                <a href="incident-logs.html?id=${incident._id}" class="link">View</a>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function loadCharts() {
    try {
        // Risk Distribution Chart
        const riskResponse = await apiClient.getRiskDistributionChart();
        const riskData = riskResponse?.chart || riskResponse;
        const riskSummary = document.getElementById('dashboard-risk-distribution-summary');
        if (riskData?.labels && riskData?.data) {
            destroyChart('risk-distribution-chart');
            dashboardCharts.riskDistribution = createPieChart(
                'risk-distribution-chart',
                riskData.labels,
                riskData.data,
                'Risk Distribution'
            );

            if (riskSummary) {
                const total = riskData.data.reduce((sum, value) => sum + (Number(value) || 0), 0);
                const severity = findDominantSeverity(riskData.labels, riskData.data);
                riskSummary.innerHTML = `<span class="summary-badge severity-${severity.toLowerCase()}">${total} total</span>`;
            }
        } else if (riskSummary) {
            riskSummary.innerHTML = '<span class="summary-badge severity-low">0 total</span>';
        }

        // Threat Categories Chart
        const threatResponse = await apiClient.getThreatCategoriesChart();
        const threatData = threatResponse?.chart || threatResponse;
        const threatSummary = document.getElementById('dashboard-threat-categories-summary');
        if (threatData?.labels && threatData?.data) {
            destroyChart('threat-categories-chart');
            dashboardCharts.threatCategories = createPieChart(
                'threat-categories-chart',
                threatData.labels,
                threatData.data,
                'Threat Categories'
            );

            if (threatSummary) {
                const total = threatData.data.reduce((sum, value) => sum + (Number(value) || 0), 0);
                threatSummary.innerHTML = `<span class="summary-badge severity-medium">${total} threats</span>`;
            }
        } else if (threatSummary) {
            threatSummary.innerHTML = '<span class="summary-badge severity-low">0 threats</span>';
        }

        // Vulnerable Assets Chart
        const assetsResponse = await apiClient.getVulnerableAssetsChart();
        const assetsData = assetsResponse?.chart || assetsResponse;
        const assetsSummary = document.getElementById('dashboard-vulnerable-assets-summary');
        if (assetsData?.labels && assetsData?.data) {
            destroyChart('vulnerable-assets-chart');
            dashboardCharts.vulnerableAssets = createBarChart(
                'vulnerable-assets-chart',
                assetsData.labels,
                assetsData.data,
                'Vulnerability Count'
            );

            if (assetsSummary) {
                const total = assetsData.data.reduce((sum, value) => sum + (Number(value) || 0), 0);
                const severity = findDominantSeverity(assetsData.labels, assetsData.data);
                assetsSummary.innerHTML = `<span class="summary-badge severity-${severity.toLowerCase()}">${total} incidents</span>`;
            }
        } else if (assetsSummary) {
            assetsSummary.innerHTML = '<span class="summary-badge severity-low">0 incidents</span>';
        }

    } catch (error) {
        console.error('Error loading charts:', error);
    }
}

function getHighestRiskLevel(riskLevels = []) {
    const rank = {
        Critical: 4,
        High: 3,
        Medium: 2,
        Low: 1,
    };

    return riskLevels.reduce((highest, level) => {
        const current = rank[level] ? level : 'Low';
        return rank[current] > rank[highest] ? current : highest;
    }, 'Low');
}

function findDominantSeverity(labels = [], data = []) {
    if (!Array.isArray(labels) || !Array.isArray(data) || labels.length === 0 || data.length === 0) {
        return 'Low';
    }

    let dominantIndex = 0;
    data.forEach((value, index) => {
        if ((Number(value) || 0) > (Number(data[dominantIndex]) || 0)) {
            dominantIndex = index;
        }
    });

    const label = String(labels[dominantIndex] || '').toLowerCase();
    if (label.includes('critical')) return 'Critical';
    if (label.includes('high')) return 'High';
    if (label.includes('medium')) return 'Medium';
    return 'Low';
}

// Handle window resize for responsive charts
window.addEventListener('resize', () => {
    Object.values(dashboardCharts).forEach(chart => {
        if (chart && chart.resize) {
            chart.resize();
        }
    });
});