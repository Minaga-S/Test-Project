/**
 * Settings Page Handler
 */

document.addEventListener('DOMContentLoaded', () => {
    initializeSettings();
});

async function initializeSettings() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'index.html';
        return;
    }

    setupUserInfo();
    setupLogoutButton();
    setupTabHandlers();
    await loadUserSettings();
}

function setupTabHandlers() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            const tabName = button.getAttribute('data-tab');
            
            // Remove active class from all buttons and tabs
            tabButtons.forEach(btn => btn.classList.remove('tab-btn-active'));
            document.querySelectorAll('.settings-tab-content').forEach(tab => {
                tab.classList.remove('tab-active');
            });
            
            // Add active class to clicked button and corresponding tab
            button.classList.add('tab-btn-active');
            document.getElementById(`${tabName}-tab`).classList.add('tab-active');
        });
    });

    // Setup form handlers
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', handleProfileUpdate);
    }

    const passwordForm = document.getElementById('password-form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', handlePasswordChange);
    }

    const notificationsForm = document.getElementById('notifications-form');
    if (notificationsForm) {
        notificationsForm.addEventListener('submit', handleNotificationsUpdate);
    }
}

async function loadUserSettings() {
    showLoading(true);

    try {
        const user = await apiClient.getProfile();
        
        // Fill profile tab
        document.getElementById('profile-name').value = user.fullName || '';
        document.getElementById('profile-email').value = user.email || '';
        document.getElementById('profile-role').value = user.role || 'User';
        document.getElementById('profile-department').value = user.department || '';

        // Load notification preferences
        const preferences = getLocalStorage('notificationPreferences') || {};
        document.getElementById('notify-critical').checked = preferences.notifyCritical !== false;
        document.getElementById('notify-high').checked = preferences.notifyHigh !== false;
        document.getElementById('notify-new-incident').checked = preferences.notifyNewIncident !== false;
        document.getElementById('notify-resolved').checked = preferences.notifyResolved !== false;
        document.getElementById('notify-daily-summary').checked = preferences.notifyDailySummary !== false;

    } catch (error) {
        console.error('Error loading settings:', error);
        showNotification('Error loading settings', 'error');
    } finally {
        showLoading(false);
    }
}

async function handleProfileUpdate(e) {
    e.preventDefault();

    const fullName = document.getElementById('profile-name').value;
    const department = document.getElementById('profile-department').value;

    showLoading(true);

    try {
        await apiClient.updateProfile({
            fullName,
            department,
        });

        showNotification('Profile updated successfully', 'success');
        
        // Update local storage
        const user = getLocalStorage('user');
        user.fullName = fullName;
        user.department = department;
        setLocalStorage('user', user);
        
        setupUserInfo();

    } catch (error) {
        console.error('Error updating profile:', error);
        document.getElementById('profile-success').textContent = '';
        showNotification('Error updating profile', 'error');
    } finally {
        showLoading(false);
    }
}

async function handlePasswordChange(e) {
    e.preventDefault();

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    // Validate
    if (newPassword !== confirmPassword) {
        document.getElementById('password-error').textContent = 'Passwords do not match';
        return;
    }

    if (!validatePassword(newPassword)) {
        document.getElementById('password-error').textContent = 'Password must be at least 8 characters';
        return;
    }

    showLoading(true);

    try {
        await apiClient.changePassword(currentPassword, newPassword);
        
        showNotification('Password changed successfully', 'success');
        document.getElementById('password-form').reset();
        document.getElementById('password-success').textContent = '';
        document.getElementById('password-error').textContent = '';

    } catch (error) {
        console.error('Error changing password:', error);
        document.getElementById('password-error').textContent = error.message || 'Error changing password';
    } finally {
        showLoading(false);
    }
}

async function handleNotificationsUpdate(e) {
    e.preventDefault();

    const preferences = {
        notifyCritical: document.getElementById('notify-critical').checked,
        notifyHigh: document.getElementById('notify-high').checked,
        notifyNewIncident: document.getElementById('notify-new-incident').checked,
        notifyResolved: document.getElementById('notify-resolved').checked,
        notifyDailySummary: document.getElementById('notify-daily-summary').checked,
    };

    setLocalStorage('notificationPreferences', preferences);
    
    showNotification('Notification preferences updated', 'success');
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

// Add CSS for tab active state
const style = document.createElement('style');
style.textContent = `
    .tab-btn-active {
        background-color: #27ae60 !important;
        color: white !important;
    }
    
    .settings-tab-content {
        display: none;
    }
    
    .tab-active {
        display: block !important;
    }
    
    .tab-btn {
        padding: 0.75rem 1.5rem;
        border: none;
        background-color: #ecf0f1;
        color: var(--secondary-color);
        cursor: pointer;
        border-radius: 4px 4px 0 0;
        margin-right: 0.5rem;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    
    .tab-btn:hover {
        background-color: #ddd;
    }
    
    .settings-tabs {
        display: flex;
        border-bottom: 2px solid #ecf0f1;
        margin-bottom: 1.5rem;
    }
    
    .help-section {
        background: white;
        padding: 2rem;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }
    
    .help-links {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
    }
    
    .help-link {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.5rem;
        padding: 1rem;
        border: 2px solid #ecf0f1;
        border-radius: 8px;
        text-align: center;
        color: var(--secondary-color);
        transition: all 0.3s ease;
        text-decoration: none;
    }
    
    .help-link:hover {
        border-color: #27ae60;
        color: #27ae60;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    }
    
    .help-link .icon {
        font-size: 2rem;
    }
`;
document.head.appendChild(style);