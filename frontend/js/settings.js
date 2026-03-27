/**
 * Settings Page Handler
 */

const USER_TABS = ['profile', 'password', 'notifications'];

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
    setupFormHandlers();
    await loadUserSettings();
}

function setupFormHandlers() {
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

function setupTabHandlers() {
    const tabButtons = document.querySelectorAll('.tab-btn');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            activateTab(tabName);
        });
    });
}

function activateTab(tabName) {
    if (!USER_TABS.includes(tabName)) {
        return;
    }

    document.querySelectorAll('.settings-tab-content').forEach((tab) => {
        tab.classList.remove('tab-active');
    });

    document.querySelectorAll('.tab-btn').forEach((button) => {
        const buttonTab = button.getAttribute('data-tab');
        button.classList.toggle('tab-btn-active', buttonTab === tabName);
    });

    const targetTab = document.getElementById(`${tabName}-tab`);
    if (targetTab) {
        targetTab.classList.add('tab-active');
    }
}

async function loadUserSettings() {
    showLoading(true);

    try {
        const profileResponse = await apiClient.getProfile();
        const user = profileResponse?.user || profileResponse || {};
        setLocalStorage('user', user);
        setupUserInfo();
        
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

        activateTab('profile');

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