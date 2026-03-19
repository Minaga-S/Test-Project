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
        window.location.href = '/index.html';
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
        const user = getLocalStorage('user') || await apiClient.getProfile();
        
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
                logout();
            }
        });
    }
}

async function loadDashboardData() {
    showLoading(true);

    try {
        // Load metrics
        const metrics = await apiClient.getDashboardMetrics();
        displayMetrics(metrics);

        // Load recent incidents
        const incidents = await apiClient.getRecentIncidents();
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
    
    if (!incidents || incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No recent incidents</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    incidents.slice(0, 5).forEach(incident => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${incident.incidentId}</td>
            <td>${incident.asset?.assetName || 'Unknown'}</td>
            <td>${incident.threatType}</td>
            <td><span class="risk-${incident.riskLevel.toLowerCase()}">${incident.riskLevel}</span></td>
            <td><span class="status-badge status-${incident.status}">${incident.status}</span></td>
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
        const riskData = await apiClient.getRiskDistributionChart();
        if (riskData) {
            destroyChart('risk-distribution-chart');
            dashboardCharts.riskDistribution = createPieChart(
                'risk-distribution-chart',
                riskData.labels,
                riskData.data,
                'Risk Distribution'
            );
        }

        // Threat Categories Chart
        const threatData = await apiClient.getThreatCategoriesChart();
        if (threatData) {
            destroyChart('threat-categories-chart');
            dashboardCharts.threatCategories = createPieChart(
                'threat-categories-chart',
                threatData.labels,
                threatData.data,
                'Threat Categories'
            );
        }

        // Vulnerable Assets Chart
        const assetsData = await apiClient.getVulnerableAssetsChart();
        if (assetsData) {
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