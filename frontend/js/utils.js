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
    const errorElement = document.getElementById(`${fieldName}-error`);
    if (errorElement) {
        errorElement.textContent = errorMessage;
        errorElement.style.display = 'block';
    }
}

function clearFormError(fieldName) {
    const errorElement = document.getElementById(`${fieldName}-error`);
    if (errorElement) {
        errorElement.textContent = '';
        errorElement.style.display = 'none';
    }
}

function clearFormErrors(formElement) {
    const errorElements = formElement.querySelectorAll('.error-message');
    errorElements.forEach(el => {
        el.textContent = '';
    });
}

// ============== UI HELPERS ==============

function showLoading(show = true) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = show ? 'flex' : 'none';
    }
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
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem;
        border-radius: 8px;
        background-color: ${
            type === 'success' ? '#27ae60' :
            type === 'error' ? '#e74c3c' :
            type === 'warning' ? '#f39c12' :
            '#3498db'
        };
        color: white;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);

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
            apiClient.logout();
            window.location.href = 'index.html';
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
        element.innerHTML = `<span class="material-symbols-rounded" aria-hidden="true">${mappedIcon}</span> ${label}`;
    });
}

function injectHeaderBreadcrumbs() {
    const headerLeft = document.querySelector('.top-header .header-left');
    const activeNavText = document.querySelector('.sidebar .nav-item.active span:not(.icon)')?.textContent?.trim();

    if (!headerLeft || !activeNavText || headerLeft.querySelector('.header-breadcrumb')) {
        return;
    }

    const breadcrumb = document.createElement('nav');
    breadcrumb.className = 'header-breadcrumb';
    breadcrumb.setAttribute('aria-label', 'Breadcrumb');
    breadcrumb.innerHTML = `
        <a href="dashboard.html">Dashboard</a>
        <span class="separator">/</span>
        <span aria-current="page">${activeNavText}</span>
    `;

    headerLeft.appendChild(breadcrumb);
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

    const updateSidebarState = (isCollapsed) => {
        if (window.innerWidth <= 768) {
            document.body.classList.remove('sidebar-collapsed');
            return;
        }

        document.body.classList.toggle('sidebar-collapsed', isCollapsed);
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

    sidebar.querySelectorAll('.nav-item').forEach((item) => {
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

document.addEventListener('DOMContentLoaded', () => {
    normalizeIconography();
    injectHeaderBreadcrumbs();
    setupSidebarToggle();
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
        'Critical': '#c0392b',
        'High': '#e74c3c',
        'Medium': '#f39c12',
        'Low': '#27ae60',
    };
    return colors[riskLevel] || '#95a5a6';
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
                backgroundColor: '#27ae60',
                borderRadius: 8,
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
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
                    },
                },
            },
        },
    });
}

function createPieChart(canvasId, labels, data, title = '') {
    const ctx = document.getElementById(canvasId).getContext('2d');
    const colors = ['#27ae60', '#3498db', '#f39c12', '#e74c3c', '#9b59b6'];
    
    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels,
            datasets: [{
                label: title,
                data,
                backgroundColor: colors,
                borderRadius: 8,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
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
                borderColor: '#27ae60',
                backgroundColor: 'rgba(39, 174, 96, 0.1)',
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

// ============== TABLE RENDERING ==============

function createTableRow(data) {
    const tr = document.createElement('tr');
    Object.values(data).forEach(value => {
        const td = document.createElement('td');
        td.innerHTML = value;
        tr.appendChild(td);
    });
    return tr;
}

function populateTable(tableBodyId, data, columns) {
    const tbody = document.getElementById(tableBodyId);
    tbody.innerHTML = '';

    if (data.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="${columns.length}" class="text-center">No data found</td>`;
        tbody.appendChild(tr);
        return;
    }

    data.forEach(item => {
        const tr = document.createElement('tr');
        columns.forEach(col => {
            const td = document.createElement('td');
            td.innerHTML = item[col.key];
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
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

function exportToPDF(filename, htmlContent) {
    // Note: This is a placeholder. In production, use a library like jsPDF
    console.log('PDF export requires a library like jsPDF');
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




