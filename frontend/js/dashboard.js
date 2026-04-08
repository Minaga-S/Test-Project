/**
 * Dashboard Page Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.
/**
 * SECTION GUIDE:
 * 1) Dashboard Boot: validates auth and loads user context.
 * 2) Metrics/Data Load: fetches dashboard summaries and incidents.
 * 3) Chart Rendering: builds visual widgets from API responses.
 * 4) Panel/UI Controls: handles collapsible sections and resize behavior.
 */



const CHART_JS_URL = 'https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js';
const MOBILE_BREAKPOINT = 768;
const METRIC_ANIMATION_DURATION_MS = 800;
let chartJsLoadPromise = null;
let dashboardCharts = {};
let isTwoFactorEnabled = false;

document.addEventListener('DOMContentLoaded', () => {
    initializeDashboard();
});

async function initializeDashboard() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }

    await displayUserInfo();
    setupLogoutButton();
    setupCollapsiblePanels();
    setupMetricCarousel();
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
            isTwoFactorEnabled = Boolean(user.twoFactorEnabled);
            updateLiveBadgeState();
            setLocalStorage('user', user);
        }
    } catch (error) {
        console.error('Error loading user info:', error);
    }
}

function updateLiveBadgeState() {
    const lastUpdatedEl = document.getElementById('last-updated-text');
    const liveBadge = lastUpdatedEl ? lastUpdatedEl.closest('.live-badge') : null;

    if (!lastUpdatedEl || !liveBadge) {
        return;
    }

    liveBadge.classList.toggle('live-badge-warning', !isTwoFactorEnabled);

    if (!isTwoFactorEnabled) {
        lastUpdatedEl.textContent = '2FA not enabled';
    }
}

function setupLogoutButton() {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.type = 'button';
        logoutBtn.addEventListener('click', logout);
    }
}

function setupCollapsiblePanels() {
    const toggles = document.querySelectorAll('.collapsible-toggle');

    toggles.forEach((toggle) => {
        toggle.addEventListener('click', () => {
            const panel = toggle.closest('.collapsible-panel');
            if (!panel) {
                return;
            }

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

function setupMetricCarousel() {
    const track = document.querySelector('.metrics-section');
    const dotsContainer = document.getElementById('metric-carousel-dots');
    if (!track || !dotsContainer) {
        return;
    }

    const cards = Array.from(track.querySelectorAll('.metric-card'));
    if (cards.length === 0) {
        return;
    }

    dotsContainer.innerHTML = '';
    const dots = cards.map((_, index) => {
        const dot = document.createElement('button');
        dot.type = 'button';
        dot.className = 'metric-carousel-dot';
        dot.setAttribute('aria-label', `Go to metric ${index + 1}`);
        dot.addEventListener('click', () => {
            const cardWidth = cards[0].getBoundingClientRect().width;
            const gap = parseFloat(getComputedStyle(track).gap || '0');
            const targetLeft = index * (cardWidth + gap);
            track.scrollTo({ left: targetLeft, behavior: 'smooth' });
        });

        dotsContainer.appendChild(dot);
        return dot;
    });

    const setActiveDot = () => {
        if (window.innerWidth > MOBILE_BREAKPOINT) {
            dots.forEach((dot) => {
                dot.classList.remove('is-active');
                dot.removeAttribute('aria-current');
            });
            return;
        }

        const cardWidth = cards[0].getBoundingClientRect().width;
        const gap = parseFloat(getComputedStyle(track).gap || '0');
        const step = cardWidth + gap;
        const rawIndex = step > 0 ? Math.round(track.scrollLeft / step) : 0;
        const activeIndex = Math.max(0, Math.min(cards.length - 1, rawIndex));

        dots.forEach((dot, index) => {
            const isActive = index === activeIndex;
            dot.classList.toggle('is-active', isActive);
            if (isActive) {
                dot.setAttribute('aria-current', 'true');
            } else {
                dot.removeAttribute('aria-current');
            }
        });
    };

    track.addEventListener('scroll', setActiveDot, { passive: true });
    window.addEventListener('resize', setActiveDot);
    setActiveDot();
}

async function loadDashboardData() {
    showDashboardSkeleton();

    try {
        const metricsPromise = apiClient.getDashboardMetrics();
        const incidentsPromise = apiClient.getRecentIncidents();
        const trendsPromise = apiClient.getMetricsTrends();
        const chartsPromise = loadCharts();

        const [metricsResponse, incidentsResponse, trendsResponse] = await Promise.all([
            metricsPromise,
            incidentsPromise,
            trendsPromise,
        ]);

        const metrics = metricsResponse?.metrics || metricsResponse || {};
        displayMetrics(metrics);

        const trends = trendsResponse?.trends || {};
        if (trendsResponse) {
            await ensureChartJsLoaded();
            renderSparklines(trends);
        }

        const incidents = Array.isArray(incidentsResponse)
            ? incidentsResponse
            : (Array.isArray(incidentsResponse?.incidents) ? incidentsResponse.incidents : []);
        displayRecentIncidents(incidents);

        await chartsPromise;
    } catch (error) {
        console.error('Error loading dashboard:', error);
        showNotification('Error loading dashboard data', 'error');
    } finally {
        hideDashboardSkeleton();
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
            animateMetricValue(el, value);
        }
    });

    // Display deltas (vs last week)
    if (metrics.deltas) {
        displayDeltas(metrics.deltas);
    }

    // Update live timestamp
    if (metrics.lastUpdated) {
        updateLiveTimestamp(metrics.lastUpdated);
    }

    // Add pulse indicator if critical risks are high
    const criticalRisksCard = document.querySelector('.metric-card-danger');
    if (criticalRisksCard && metrics.criticalRisks > 0) {
        criticalRisksCard.classList.add('pulse-indicator');
    } else if (criticalRisksCard) {
        criticalRisksCard.classList.remove('pulse-indicator');
    }
}

function animateMetricValue(element, targetValue) {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const parsedTarget = Number(targetValue) || 0;
    const startValue = Number(element.textContent) || 0;

    if (prefersReducedMotion || startValue === parsedTarget) {
        element.textContent = parsedTarget;
        return;
    }

    const startTime = performance.now();

    const tick = (now) => {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / METRIC_ANIMATION_DURATION_MS, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(startValue + (parsedTarget - startValue) * eased);

        element.textContent = value;

        if (progress < 1) {
            requestAnimationFrame(tick);
        }
    };

    requestAnimationFrame(tick);
}

function showDashboardSkeleton() {
    const metricIds = ['total-assets', 'open-incidents', 'critical-risks', 'resolved-issues'];
    metricIds.forEach((id) => {
        const metricEl = document.getElementById(id);
        if (metricEl) {
            metricEl.classList.add('metric-value-skeleton');
            metricEl.textContent = '';
        }
    });

    setDashboardSummarySkeleton('dashboard-risk-distribution-summary');
    setDashboardSummarySkeleton('dashboard-threat-categories-summary');
    setDashboardSummarySkeleton('dashboard-vulnerable-assets-summary');
    setDashboardSummarySkeleton('dashboard-recent-incidents-summary');

    const tbody = document.getElementById('recent-incidents-tbody');
    if (tbody) {
        const skeletonRows = Array.from({ length: 3 }, () => `
            <tr class="incidents-skeleton-row">
                <td><span class="skeleton-block w-sm"></span></td>
                <td><span class="skeleton-block w-md"></span></td>
                <td><span class="skeleton-block w-md"></span></td>
                <td><span class="skeleton-block w-sm"></span></td>
                <td><span class="skeleton-block w-sm"></span></td>
                <td><span class="skeleton-block w-sm"></span></td>
                <td><span class="skeleton-block w-xs"></span></td>
            </tr>
        `).join('');

        tbody.innerHTML = skeletonRows;
    }
}

function hideDashboardSkeleton() {
    const metricIds = ['total-assets', 'open-incidents', 'critical-risks', 'resolved-issues'];
    metricIds.forEach((id) => {
        const metricEl = document.getElementById(id);
        if (metricEl) {
            metricEl.classList.remove('metric-value-skeleton');
        }
    });
}

function setDashboardSummarySkeleton(elementId) {
    const summaryEl = document.getElementById(elementId);
    if (!summaryEl) {
        return;
    }

    summaryEl.innerHTML = createSummaryBadgeSkeleton();
}

function updateLiveTimestamp(timestamp) {
    const lastUpdatedEl = document.getElementById('last-updated-text');
    if (!lastUpdatedEl) return;

    if (!isTwoFactorEnabled) {
        updateLiveBadgeState();
        return;
    }

    const now = new Date();
    const diff = Math.floor((now - new Date(timestamp)) / 1000);

    let timeText = 'Updated now';
    if (diff < 60) {
        timeText = 'Updated just now';
    } else if (diff < 3600) {
        const minutes = Math.floor(diff / 60);
        timeText = `Updated ${minutes}m ago`;
    } else if (diff < 86400) {
        const hours = Math.floor(diff / 3600);
        timeText = `Updated ${hours}h ago`;
    } else {
        const days = Math.floor(diff / 86400);
        timeText = `Updated ${days}d ago`;
    }

    lastUpdatedEl.textContent = timeText;
    updateLiveBadgeState();

    // Update incrementally every minute
    setTimeout(() => {
        updateLiveTimestamp(timestamp);
    }, 60000);
}

function displayDeltas(deltas) {
    const deltaElements = {
        'delta-total-assets': deltas.totalAssets,
        'delta-open-incidents': deltas.openIncidents,
        'delta-critical-risks': deltas.criticalRisks,
        'delta-resolved-issues': deltas.resolvedIssues,
    };

    Object.entries(deltaElements).forEach(([elementId, delta]) => {
        const el = document.getElementById(elementId);
        if (!el) return;

        const isPositive = delta > 0;
        const isNeutral = delta === 0;
        const absValue = Math.abs(delta);
        const arrow = isNeutral ? '\u2013' : (isPositive ? '\u2191' : '\u2193');
        
        // Determine direction (for some metrics, up is bad; for others, good)
        const metricType = elementId.split('-').pop();
        const isBadWhenUp = ['open-incidents', 'critical-risks'].includes(metricType) || 
                            elementId.includes('open') || 
                            elementId.includes('critical');
        
        const classType = isNeutral ? 'neutral' : (
            isBadWhenUp 
                ? (isPositive ? 'negative' : 'positive')
                : (isPositive ? 'positive' : 'negative')
        );

        el.innerHTML = `<span class="metric-delta-arrow">${arrow}</span> <span class="metric-delta-${classType}">${absValue}</span>`;
        el.className = `metric-delta metric-delta-${classType}`;
    });
}

function renderSparklines(trends) {
    const sparklineConfigs = [
        {
            canvasId: 'sparkline-total-assets',
            data: trends.totalAssets || [],
            borderColor: '#4070FF',
            backgroundColor: 'rgba(64, 112, 255, 0.1)',
        },
        {
            canvasId: 'sparkline-open-incidents',
            data: trends.openIncidents || [],
            borderColor: '#ED8936',
            backgroundColor: 'rgba(237, 137, 54, 0.1)',
        },
        {
            canvasId: 'sparkline-critical-risks',
            data: trends.criticalRisks || [],
            borderColor: '#F56565',
            backgroundColor: 'rgba(245, 101, 101, 0.1)',
        },
        {
            canvasId: 'sparkline-resolved-issues',
            data: trends.resolvedIssues || [],
            borderColor: '#48BB78',
            backgroundColor: 'rgba(72, 187, 120, 0.1)',
        },
    ];

    sparklineConfigs.forEach((config) => {
        const canvas = document.getElementById(config.canvasId);
        if (!canvas || !config.data.length) return;

        if (!window.Chart) {
            console.warn('Chart.js not loaded');
            return;
        }

        const ctx = canvas.getContext('2d');

        new window.Chart(ctx, {
            type: 'line',
            data: {
                labels: Array.from({ length: config.data.length }, (_, i) => i),
                datasets: [
                    {
                        label: 'Trend',
                        data: config.data,
                        borderColor: config.borderColor,
                        backgroundColor: config.backgroundColor,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 0,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false,
                    },
                    tooltip: {
                        enabled: false,
                    },
                },
                scales: {
                    x: {
                        display: false,
                    },
                    y: {
                        display: false,
                        beginAtZero: true,
                    },
                },
            },
        });
    });
}

function displayRecentIncidents(incidents) {
    const tbody = document.getElementById('recent-incidents-tbody');
    if (!tbody) {
        return;
    }

    const incidentList = Array.isArray(incidents) ? incidents : [];
    const summary = document.getElementById('dashboard-recent-incidents-summary');

    if (summary) {
        if (incidentList.length === 0) {
            summary.innerHTML = createSummaryBadge('0 incidents');
        } else {
            summary.innerHTML = createSummaryBadge(`${incidentList.length} incidents`);
        }
    }

    if (incidentList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No recent incidents</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    incidentList.slice(0, 5).forEach((incident) => {
        const riskLevel = incident.riskLevel || 'Low';
        const status = incident.status || 'Open';
        const incidentDbId = String(incident?._id || incident?.id || '').trim();
        const incidentPublicId = String(incident?.incidentId || '').trim();
        const viewUrl = new URL('incident-logs.html', window.location.href);

        if (incidentDbId) {
            viewUrl.searchParams.set('id', incidentDbId);
        }

        if (incidentPublicId) {
            viewUrl.searchParams.set('incidentId', incidentPublicId);
        }

        const row = document.createElement('tr');
        row.innerHTML = `
            <td data-label="Incident ID">${incident.incidentId}</td>
            <td data-label="Asset">${incident.asset?.assetName || 'Unknown'}</td>
            <td data-label="Threat Type">${incident.threatType || 'Unknown'}</td>
            <td data-label="Risk Level"><span class="risk-${riskLevel.toLowerCase()}">${riskLevel}</span></td>
            <td data-label="Status"><span class="status-badge status-${status}">${status}</span></td>
            <td data-label="Date">${formatDate(incident.createdAt)}</td>
            <td data-label="Action">
                <button type="button" class="btn btn-sm btn-secondary">View</button>
            </td>
        `;

        const actionButton = row.querySelector('button');
        actionButton.addEventListener('click', () => {
            const navigationTarget = {
                incidentDbId,
                incidentPublicId,
                createdAt: Date.now(),
            };

            try {
                sessionStorage.setItem('incidentLogs:openTarget', JSON.stringify(navigationTarget));
            } catch (storageError) {
                console.warn('Unable to persist incident deep-link target:', storageError);
            }

            window.location.href = viewUrl.toString();
        });

        tbody.appendChild(row);
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

async function loadCharts() {
    try {
        const [riskResponse, threatResponse, assetsResponse] = await Promise.all([
            apiClient.getRiskDistributionChart(),
            apiClient.getThreatCategoriesChart(),
            apiClient.getVulnerableAssetsChart(),
        ]);

        await ensureChartJsLoaded();

        const riskData = riskResponse?.chart || riskResponse;
        const threatData = threatResponse?.chart || threatResponse;
        const assetsData = assetsResponse?.chart || assetsResponse;

        renderRiskDistributionChart(riskData);
        renderThreatCategoriesChart(threatData);
        renderVulnerableAssetsChart(assetsData);
    } catch (error) {
        console.error('Error loading charts:', error);
    }
}

function renderRiskDistributionChart(riskData) {
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
            riskSummary.innerHTML = createSummaryBadge(`${total} total`);
        }
    } else if (riskSummary) {
        riskSummary.innerHTML = createSummaryBadge('0 total');
    }
}

function renderThreatCategoriesChart(threatData) {
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
            threatSummary.innerHTML = createSummaryBadge(`${total} threats`);
        }
    } else if (threatSummary) {
        threatSummary.innerHTML = createSummaryBadge('0 threats');
    }
}

function renderVulnerableAssetsChart(assetsData) {
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
            assetsSummary.innerHTML = createSummaryBadge(`${total} incidents`);
        }
    } else if (assetsSummary) {
        assetsSummary.innerHTML = createSummaryBadge('0 incidents');
    }
}

function createSummaryBadge(text) {
    return `<span class="summary-badge">${text}</span>`;
}

function createSummaryBadgeSkeleton() {
    return '<span class="summary-badge summary-badge-skeleton" aria-hidden="true"></span>';
}

window.addEventListener('resize', () => {
    Object.values(dashboardCharts).forEach((chart) => {
        if (chart && chart.resize) {
            chart.resize();
        }
    });
});



