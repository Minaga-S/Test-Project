/**
 * Utility Functions
 */
// NOTE: UI utility layer: shared helpers used by multiple pages for modals, formatting, and navigation.
/**
 * SECTION GUIDE:
 * 1) Formatting Helpers: date/time and display utilities used across pages.
 * 2) Validation Helpers: shared checks for form-level input quality.
 * 3) UI Helpers: modals/loading/toasts/logout confirmation handling.
 * 4) Navigation Helpers: sidebar state, breadcrumbs, and shared interactions.
 */




window.APP_DEPARTMENTS = [
    'Management',
    'Front Office',
    'Reservations',
    'Housekeeping',
    'Food and Beverage',
    'Finance',
    'Human Resources',
    'Security',
    'Maintenance',
    'Sales and Marketing',
    'IT and Systems',
    'Operations',
];

window.APP_SECURITY_QUESTIONS = [
    'What was the name of your first school?',
    'What city were you born in?',
    'What is your mother\'s maiden name?',
    'What was your childhood nickname?',
    'What is the name of your favorite teacher?',
    'What is your favorite movie?',
    'What was the make of your first car?',
    'What is the name of your first pet?',
    'What street did you grow up on?',
];

// ============== DATE & TIME ==============

function formatDate(date) {
    if (!date) return 'N/A';
    const d = new Date(date);
    return d.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    });
}

function formatDateTime(date) {
    if (!date) return 'N/A';
    const d = new Date(date);
    return d.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function timeAgo(date) {
    if (!date) return 'N/A';
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    return formatDate(date);
}

// ============== VALIDATION ==============

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password.length >= 8;
}

function validateForm(formElement) {
    const formData = new FormData(formElement);
    const errors = {};

    for (const [key, value] of formData) {
        if (!value.trim()) {
            errors[key] = 'This field is required';
        }
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors,
    };
}

// ============== FORM HANDLING ==============

function getFormData(formElement) {
    const formData = new FormData(formElement);
    const data = {};

    for (const [key, value] of formData) {
        data[key] = value;
    }

    return data;
}

function displayFormError(fieldName, errorMessage) {
    const field = document.getElementById(fieldName);
    if (field) {
        const group = field.closest('.form-group');
        if (group) {
            group.classList.add('error');
            group.classList.remove('success');
        }
    }

    const errorElement = document.getElementById(`${fieldName}-error`);
    if (errorElement) {
        errorElement.textContent = errorMessage;
        errorElement.style.display = 'block';
    }
}

function clearFormError(fieldName) {
    const field = document.getElementById(fieldName);
    if (field) {
        const group = field.closest('.form-group');
        if (group) {
            group.classList.remove('error');
        }
    }

    const errorElement = document.getElementById(`${fieldName}-error`);
    if (errorElement) {
        errorElement.textContent = '';
        errorElement.style.display = 'none';
    }
}

function clearFormErrors(formElement) {
    const groups = formElement.querySelectorAll('.form-group.error');
    groups.forEach((group) => {
        group.classList.remove('error');
    });

    const errorElements = formElement.querySelectorAll('.error-message');
    errorElements.forEach((el) => {
        el.textContent = '';
        el.style.display = 'none';
    });
}

// ============== UI HELPERS ==============

function showLoading(show = true) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = show ? 'flex' : 'none';
    }
}

function animateCountUp(element, targetValue, duration = 800) {
    if (!element) {
        return;
    }

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const finalValue = Number(targetValue) || 0;
    const startValue = Number(element.textContent) || 0;

    if (prefersReducedMotion || startValue === finalValue) {
        element.textContent = finalValue;
        return;
    }

    const startTime = performance.now();

    const update = (now) => {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(startValue + (finalValue - startValue) * eased);
        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    };

    requestAnimationFrame(update);
}

function renderTableSkeleton(tbodyId, columnCount, rowCount = 3) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) {
        return;
    }

    const widthClasses = ['w-sm', 'w-md', 'w-md', 'w-sm', 'w-sm', 'w-sm', 'w-xs', 'w-sm'];
    const rows = [];

    for (let rowIndex = 0; rowIndex < rowCount; rowIndex += 1) {
        const cells = [];
        for (let colIndex = 0; colIndex < columnCount; colIndex += 1) {
            const widthClass = widthClasses[colIndex % widthClasses.length];
            cells.push(`<td><span class="skeleton-block ${widthClass}"></span></td>`);
        }

        rows.push(`<tr class="incidents-skeleton-row">${cells.join('')}</tr>`);
    }

    tbody.innerHTML = rows.join('');
}

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
    }
}

function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

function toggleModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
    }
}

function showNotification(message, type = 'info') {
    let notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.className = 'notification-container';
        document.body.appendChild(notificationContainer);
    }

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        padding: 1rem;
        border-radius: 8px;
        background-color: ${
            type === 'success' ? '#48BB78' :
            type === 'error' ? '#F56565' :
            type === 'warning' ? '#ED8936' :
            '#5B8DEE'
        };
        color: white;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        animation: slideIn 0.3s ease;
    `;

    notificationContainer.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

const LOGOUT_MODAL_ID = 'logout-confirm-modal';

function ensureLogoutModal() {
    let modal = document.getElementById(LOGOUT_MODAL_ID);
    if (modal) {
        return modal;
    }

    modal = document.createElement('div');
    modal.id = LOGOUT_MODAL_ID;
    modal.className = 'modal';
    modal.style.display = 'none';
    modal.innerHTML = `
        <div class="modal-overlay" data-logout-dismiss="true"></div>
        <div class="modal-content modal-content-small confirm-modal">
            <div class="modal-header">
                <h2><span class="material-symbols-rounded" aria-hidden="true">logout</span> Confirm Logout</h2>
            </div>
            <p>Are you sure you want to log out of your account?</p>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" id="logout-cancel-btn">Stay Logged In</button>
                <button type="button" class="btn btn-danger" id="logout-confirm-btn">Log Out</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    modal.addEventListener('click', (event) => {
        const shouldDismiss = event.target.matches('[data-logout-dismiss="true"]') || event.target.id === 'logout-cancel-btn';
        if (shouldDismiss) {
            hideModal(LOGOUT_MODAL_ID);
        }

        if (event.target.id === 'logout-confirm-btn') {
            // Logout stays client-driven because tokens are bearer-based and cleared locally;
            // this keeps the flow resilient even if backend logout endpoints are unavailable.
            apiClient.logout();
            window.location.href = 'login.html';
        }
    });

    return modal;
}

function logout() {
    ensureLogoutModal();
    showModal(LOGOUT_MODAL_ID);
}

function normalizeIconography() {
    const navIconByRoute = {
        'dashboard.html': 'dashboard',
        'assets.html': 'inventory_2',
        'report-incident.html': 'report_problem',
        'incident-logs.html': 'assignment',
        'risk-analysis.html': 'monitoring',
        'settings.html': 'settings',
    };

    document.querySelectorAll('.sidebar .nav-item').forEach((navItem) => {
        const label = navItem.querySelector('span:not(.icon)')?.textContent?.trim() || 'Navigation';
        navItem.dataset.tooltip = label;
        navItem.setAttribute('title', label);

        const href = navItem.getAttribute('href') || '';
        const route = href.split('?')[0];
        const iconName = navIconByRoute[route] || 'chevron_right';

        const iconEl = navItem.querySelector('.icon');
        if (iconEl) {
            iconEl.classList.add('material-symbols-rounded');
            iconEl.setAttribute('aria-hidden', 'true');
            iconEl.textContent = iconName;
        }
    });

    document.querySelectorAll('.metric-icon').forEach((iconEl, index) => {
        const metricIcons = ['inventory_2', 'warning', 'priority_high', 'task_alt'];
        iconEl.classList.add('material-symbols-rounded');
        iconEl.setAttribute('aria-hidden', 'true');
        iconEl.textContent = metricIcons[index] || 'insights';
    });

    const emojiHeadingMap = {
        '🛡️': 'shield',
        '⚠️': 'warning',
        '📊': 'monitoring',
        '✅': 'task_alt',
        '📖': 'menu_book',
        '❓': 'help',
        '📞': 'support_agent',
    };

    document.querySelectorAll('h2, h3, .icon').forEach((element) => {
        const text = (element.textContent || '').trim();
        const firstToken = text.split(' ')[0];
        const mappedIcon = emojiHeadingMap[firstToken];

        if (!mappedIcon) {
            return;
        }

        const label = text.replace(firstToken, '').trim();
        // Rebuild with DOM nodes so mapped icon labels never flow through HTML parsing.
        element.textContent = '';

        const iconSpan = document.createElement('span');
        iconSpan.className = 'material-symbols-rounded';
        iconSpan.setAttribute('aria-hidden', 'true');
        iconSpan.textContent = mappedIcon;

        element.appendChild(iconSpan);
        if (label) {
            element.appendChild(document.createTextNode(` ${label}`));
        }
    });
}

function injectHeaderBreadcrumbs() {
    const headerLeft = document.querySelector('.top-header .header-left');
    const activeNavItem = document.querySelector('.sidebar .nav-item.active');
    const activeNavText = activeNavItem?.querySelector('span:not(.icon)')?.textContent?.trim();
    const activeNavHref = String(activeNavItem?.getAttribute('href') || '').trim();
    const pageBreadcrumbLabel = String(document.body.dataset.breadcrumbLabel || '').trim();
    const pageBreadcrumbParent = String(document.body.dataset.breadcrumbParent || '').trim();
    const pageBreadcrumbParentHref = String(document.body.dataset.breadcrumbParentHref || '').trim();
    const currentLabel = pageBreadcrumbLabel || activeNavText;

    if (!headerLeft || !currentLabel || headerLeft.querySelector('.header-breadcrumb')) {
        return;
    }

    const breadcrumb = document.createElement('nav');
    breadcrumb.className = 'header-breadcrumb';
    breadcrumb.setAttribute('aria-label', 'Breadcrumb');

    const isDashboardPage = currentLabel.toLowerCase() === 'dashboard';

    const appendSeparator = () => {
        const separator = document.createElement('span');
        separator.className = 'separator';
        separator.textContent = '/';
        breadcrumb.appendChild(separator);
    };

    const appendLink = (label, href, isCurrent = false) => {
        const link = document.createElement('a');
        link.textContent = label;
        if (href) {
            link.href = href;
        }
        if (isCurrent) {
            link.setAttribute('aria-current', 'page');
        }
        breadcrumb.appendChild(link);
    };

    const appendCurrentLabel = (label) => {
        const current = document.createElement('span');
        current.textContent = label;
        current.setAttribute('aria-current', 'page');
        breadcrumb.appendChild(current);
    };

    if (isDashboardPage) {
        appendLink('Dashboard', 'dashboard.html', true);
        headerLeft.appendChild(breadcrumb);
        return;
    }

    appendLink('Dashboard', 'dashboard.html');

    const defaultParentLabel = activeNavText && activeNavText.toLowerCase() !== 'dashboard' && activeNavText !== currentLabel
        ? activeNavText
        : '';
    const parentLabel = pageBreadcrumbParent || defaultParentLabel;
    const parentHref = pageBreadcrumbParentHref || activeNavHref;

    if (parentLabel) {
        appendSeparator();
        if (parentHref) {
            appendLink(parentLabel, parentHref);
        } else {
            const parentSpan = document.createElement('span');
            parentSpan.textContent = parentLabel;
            breadcrumb.appendChild(parentSpan);
        }
    }

    appendSeparator();
    appendCurrentLabel(currentLabel);

    headerLeft.appendChild(breadcrumb);
}

function setupSmoothDetailsAnimations() {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
        return;
    }

    if (document.body.dataset.smoothDetailsBound === 'true') {
        return;
    }

    document.addEventListener('click', (event) => {
        const summary = event.target.closest('details > summary');
        if (!summary) {
            return;
        }

        const detailsEl = summary.parentElement;
        if (!detailsEl || detailsEl.tagName.toLowerCase() !== 'details') {
            return;
        }

        event.preventDefault();

        if (detailsEl.dataset.isAnimating === 'true') {
            return;
        }

        const isOpening = !detailsEl.open;
        const contentElement = Array.from(detailsEl.children).find((child) => child.tagName.toLowerCase() !== 'summary');

        if (!contentElement) {
            detailsEl.open = isOpening;
            return;
        }

        const startHeight = detailsEl.offsetHeight;

        if (isOpening) {
            detailsEl.open = true;
        }

        const endHeight = isOpening
            ? summary.offsetHeight + contentElement.scrollHeight
            : summary.offsetHeight;

        detailsEl.dataset.isAnimating = 'true';
        detailsEl.style.overflow = 'hidden';
        detailsEl.style.height = `${startHeight}px`;
        detailsEl.style.transition = 'height var(--duration-normal) var(--ease-standard)';

        requestAnimationFrame(() => {
            detailsEl.style.height = `${endHeight}px`;
        });

        const finishAnimation = () => {
            if (!isOpening) {
                detailsEl.open = false;
            }

            detailsEl.style.height = '';
            detailsEl.style.overflow = '';
            detailsEl.style.transition = '';
            delete detailsEl.dataset.isAnimating;
        };

        detailsEl.addEventListener('transitionend', finishAnimation, { once: true });
    });

    document.body.dataset.smoothDetailsBound = 'true';
}

function setupSmoothPanelTransitions() {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const toggles = Array.from(document.querySelectorAll('.collapsible-toggle[data-target]'));

    toggles.forEach((toggle) => {
        if (toggle.dataset.smoothToggleBound === 'true') {
            return;
        }

        toggle.addEventListener('click', () => {
            const panel = toggle.closest('.collapsible-panel');
            const targetId = String(toggle.dataset.target || '').trim();
            const content = targetId ? document.getElementById(targetId) : panel?.querySelector('.collapsible-content');
            if (!panel || !content) {
                return;
            }

            const willExpand = panel.classList.contains('collapsed');
            if (prefersReducedMotion) {
                content.style.maxHeight = willExpand ? `${content.scrollHeight}px` : '0px';
                return;
            }

            const currentHeight = content.getBoundingClientRect().height;
            const targetHeight = willExpand ? content.scrollHeight : 0;

            content.style.maxHeight = `${currentHeight}px`;
            requestAnimationFrame(() => {
                content.style.maxHeight = `${targetHeight}px`;
            });

            const clearExpandedInlineStyle = () => {
                if (willExpand) {
                    content.style.maxHeight = '';
                }
            };

            content.addEventListener('transitionend', clearExpandedInlineStyle, { once: true });
        });

        toggle.dataset.smoothToggleBound = 'true';
    });
}

function setupSidebarToggle() {
    const sidebar = document.querySelector('.sidebar');
    const topHeader = document.querySelector('.top-header');
    const headerLeft = document.querySelector('.header-left') || topHeader;

    if (!sidebar || !topHeader || !headerLeft) {
        return;
    }

    let toggleBtn = document.getElementById('sidebar-toggle-btn');
    if (!toggleBtn) {
        toggleBtn = document.createElement('button');
        toggleBtn.id = 'sidebar-toggle-btn';
        toggleBtn.type = 'button';
        toggleBtn.className = 'sidebar-toggle-btn';
        toggleBtn.setAttribute('aria-label', 'Toggle sidebar');
        toggleBtn.setAttribute('aria-expanded', 'false');
        toggleBtn.innerHTML = '<span class="material-symbols-rounded" aria-hidden="true">menu</span>';
        headerLeft.prepend(toggleBtn);
    }

    const sidebarHeader = sidebar.querySelector('.sidebar-header');
    const headerLogo = sidebarHeader?.querySelector('.logo-mini');
    const headerTitle = sidebarHeader?.querySelector('h2');

    if (sidebarHeader && headerLogo && headerTitle && !sidebarHeader.querySelector('.sidebar-header-main')) {
        const headerMain = document.createElement('div');
        headerMain.className = 'sidebar-header-main';
        headerMain.appendChild(headerLogo);
        headerMain.appendChild(headerTitle);
        sidebarHeader.prepend(headerMain);
    }

    const navItems = Array.from(sidebar.querySelectorAll('.nav-item'));
    navItems.forEach((item) => {
        const label = item.querySelector('span:not(.icon)')?.textContent?.trim();
        if (label) {
            item.setAttribute('data-tooltip', label);
            item.setAttribute('title', label);
        }
    });

    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.setAttribute('data-tooltip', 'Logout');
        logoutBtn.setAttribute('title', 'Logout');
    }

    const setDesktopToggleState = (isCollapsed) => {
        toggleBtn.setAttribute('aria-expanded', String(!isCollapsed));
        toggleBtn.setAttribute('aria-label', isCollapsed ? 'Expand sidebar' : 'Collapse sidebar');
    };

    const updateSidebarState = (isCollapsed) => {
        if (window.innerWidth <= 768) {
            document.body.classList.remove('sidebar-collapsed');
            toggleBtn.setAttribute('aria-label', 'Toggle sidebar');
            return;
        }

        document.body.classList.toggle('sidebar-collapsed', isCollapsed);
        setDesktopToggleState(isCollapsed);
    };

    const savedCollapsedState = localStorage.getItem('sidebarCollapsed') === 'true';
    updateSidebarState(savedCollapsedState);

    toggleBtn.addEventListener('click', () => {
        if (window.innerWidth <= 768) {
            const isOpen = document.body.classList.toggle('sidebar-open');
            toggleBtn.setAttribute('aria-expanded', String(isOpen));
            return;
        }

        const nextCollapsed = !document.body.classList.contains('sidebar-collapsed');
        localStorage.setItem('sidebarCollapsed', String(nextCollapsed));
        updateSidebarState(nextCollapsed);
    });

    document.addEventListener('click', (event) => {
        if (window.innerWidth > 768) {
            return;
        }

        const inSidebar = event.target.closest('.sidebar');
        const isToggle = event.target.closest('#sidebar-toggle-btn');
        if (!inSidebar && !isToggle) {
            document.body.classList.remove('sidebar-open');
            toggleBtn.setAttribute('aria-expanded', 'false');
        }
    });

    navItems.forEach((item) => {
        item.addEventListener('click', () => {
            if (window.innerWidth > 768) {
                return;
            }

            document.body.classList.remove('sidebar-open');
            toggleBtn.setAttribute('aria-expanded', 'false');
        });
    });

    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            document.body.classList.remove('sidebar-open');
            toggleBtn.setAttribute('aria-expanded', 'false');
            const isCollapsedOnResize = localStorage.getItem('sidebarCollapsed') === 'true';
            updateSidebarState(isCollapsedOnResize);
        }
    });
}

function setupPageTransitions() {
    // Keep native browser navigation for instant page transitions.
}

function setupMobileHaptics() {
    const supportsVibrate = typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function';
    const isTouchDevice = window.matchMedia('(pointer: coarse)').matches;
    if (!supportsVibrate || !isTouchDevice) {
        return;
    }

    let lastHapticAt = 0;
    document.addEventListener('click', (event) => {
        const interactive = event.target.closest('button, .btn, .tab-btn, .collapsible-toggle, .nav-item, a');
        if (!interactive) {
            return;
        }

        const now = Date.now();
        if (now - lastHapticAt < 70) {
            return;
        }

        navigator.vibrate(10);
        lastHapticAt = now;
    }, { passive: true });
}

function hideAuditLogNavigationForNonAdmins() {
    const user = getLocalStorage('user');
    const isAdmin = String(user?.role || '').trim() === 'Admin';
    document.body.classList.toggle('is-admin', isAdmin);

    if (isAdmin) {
        return;
    }

    // If local cache is missing or stale, re-verify role with the profile endpoint.
    // Non-admin state remains the secure default while verification is in progress.
    if (apiClient?.isAuthenticated && apiClient.isAuthenticated()) {
        apiClient.getProfile()
            .then((profileResponse) => {
                const profile = profileResponse?.user || profileResponse || {};
                const hasAdminRole = String(profile?.role || '').trim() === 'Admin';

                if (profile && typeof setLocalStorage === 'function') {
                    setLocalStorage('user', profile);
                }

                document.body.classList.toggle('is-admin', hasAdminRole);
            })
            .catch(() => {
                document.body.classList.remove('is-admin');
            });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    normalizeIconography();
    injectHeaderBreadcrumbs();
    setupSmoothDetailsAnimations();
    setupSmoothPanelTransitions();
    setupSidebarToggle();
    setupPageTransitions();
    setupMobileHaptics();
    hideAuditLogNavigationForNonAdmins();
});

document.addEventListener('click', (event) => {
    const logoutButton = event.target.closest('#logout-btn');
    if (!logoutButton) {
        return;
    }

    event.preventDefault();
    logout();
});

// ============== RISK LEVEL HELPERS ==============

function getRiskColor(riskLevel) {
    const colors = {
        'Critical': '#E53E3E',
        'High': '#F56565',
        'Medium': '#ED8936',
        'Low': '#48BB78',
    };
    return colors[riskLevel] || '#718096';
}

function getRiskBadge(riskLevel) {
    const badges = {
        'Critical': 'CRITICAL',
        'High': 'HIGH',
        'Medium': 'MEDIUM',
        'Low': 'LOW',
    };
    return badges[riskLevel] || 'N/A';
}

function getStatusBadge(status) {
    const badges = {
        'Open': 'OPEN',
        'InProgress': 'IN PROGRESS',
        'Resolved': 'RESOLVED',
    };
    return badges[status] || 'N/A';
}

// ============== CHART HELPERS ==============

function destroyChart(chartId) {
    const chartElement = document.getElementById(chartId);
    if (chartElement && chartElement.chart) {
        chartElement.chart.destroy();
    }
}

function createBarChart(canvasId, labels, data, title = '') {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: title,
                data,
                backgroundColor: [
                    '#4070FF',
                    '#5B8DEE',
                    '#7B9BE6',
                    '#9AB5DD',
                    '#B8CDE1',
                ],
                borderRadius: 8,
                borderSkipped: false,
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
                    displayColors: true,
                },
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
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

function createPieChart(canvasId, labels, data, title = '') {
    const ctx = document.getElementById(canvasId).getContext('2d');
    const riskColors = ['#F56565', '#ED8936', '#5B8DEE', '#48BB78', '#4070FF'];
    
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                label: title,
                data,
                backgroundColor: riskColors.slice(0, labels.length),
                borderColor: '#FFFFFF',
                borderWidth: 2,
                borderRadius: 8,
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

function createLineChart(canvasId, labels, data, title = '') {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: title,
                data,
                borderColor: '#48BB78',
                backgroundColor: 'rgba(72, 187, 120, 0.1)',
                tension: 0.4,
                fill: true,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false,
                },
            },
        },
    });
}

// ============== LOCAL STORAGE ==============

function setLocalStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch (e) {
        console.error('LocalStorage error:', e);
    }
}

function getLocalStorage(key) {
    try {
        const value = localStorage.getItem(key);
        return value ? JSON.parse(value) : null;
    } catch (e) {
        console.error('LocalStorage error:', e);
        return null;
    }
}

function removeLocalStorage(key) {
    try {
        localStorage.removeItem(key);
    } catch (e) {
        console.error('LocalStorage error:', e);
    }
}

// ============== EXPORT FUNCTIONS ==============

function exportToCSV(filename, data) {
    let csv = 'data:text/csv;charset=utf-8,';
    
    // Headers
    const headers = Object.keys(data[0] || {});
    csv += headers.join(',') + '\n';
    
    // Rows
    data.forEach(row => {
        const values = headers.map(header => {
            const value = row[header];
            return typeof value === 'string' && value.includes(',') 
                ? `"${value}"` 
                : value;
        });
        csv += values.join(',') + '\n';
    });
    
    const encodedUri = encodeURI(csv);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', filename);
    link.click();
}

// ============== ADD ANIMATIONS ==============

const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);





const APP_MANIFEST_PATH = 'manifest.webmanifest';
const APP_THEME_COLOR = '#0f172a';

function ensureAppMetadata() {
    if (typeof document === 'undefined' || !document.head) {
        return;
    }

    if (!document.querySelector('link[rel="manifest"]')) {
        const manifestLink = document.createElement('link');
        manifestLink.rel = 'manifest';
        manifestLink.href = APP_MANIFEST_PATH;
        document.head.appendChild(manifestLink);
    }

    let themeColorMeta = document.querySelector('meta[name="theme-color"]');
    if (!themeColorMeta) {
        themeColorMeta = document.createElement('meta');
        themeColorMeta.name = 'theme-color';
        document.head.appendChild(themeColorMeta);
    }

    themeColorMeta.content = APP_THEME_COLOR;
}

document.addEventListener('DOMContentLoaded', ensureAppMetadata);