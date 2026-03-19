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
        logoutBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to logout?')) {
                handleLogout();
            }
        });
    }
}

function handleLogout() {
    apiClient.logout();
    window.location.href = 'index.html';
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
        if (riskData?.labels && riskData?.data) {
            destroyChart('risk-distribution-chart');
            dashboardCharts.riskDistribution = createPieChart(
                'risk-distribution-chart',
                riskData.labels,
                riskData.data,
                'Risk Distribution'
            );
        }

        // Threat Categories Chart
        const threatResponse = await apiClient.getThreatCategoriesChart();
        const threatData = threatResponse?.chart || threatResponse;
        if (threatData?.labels && threatData?.data) {
            destroyChart('threat-categories-chart');
            dashboardCharts.threatCategories = createPieChart(
                'threat-categories-chart',
                threatData.labels,
                threatData.data,
                'Threat Categories'
            );
        }

        // Vulnerable Assets Chart
        const assetsResponse = await apiClient.getVulnerableAssetsChart();
        const assetsData = assetsResponse?.chart || assetsResponse;
        if (assetsData?.labels && assetsData?.data) {
            destroyChart('vulnerable-assets-chart');
            dashboardCharts.vulnerableAssets = createBarChart(
                'vulnerable-assets-chart',
                assetsData.labels,
                assetsData.data,
                'Vulnerability Count'
            );
        }

    } catch (error) {
        console.error('Error loading charts:', error);
    }
}

// Handle window resize for responsive charts
window.addEventListener('resize', () => {
    Object.values(dashboardCharts).forEach(chart => {
        if (chart && chart.resize) {
            chart.resize();
        }
    });
});