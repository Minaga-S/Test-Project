/**
 * Settings Page Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.
/**
 * SECTION GUIDE:
 * 1) Settings Boot: validates auth and loads user preferences.
 * 2) Tab Navigation: switches profile/password/security/notification sections.
 * 3) Form Submission: applies profile/password/2FA/notification updates.
 * 4) Feedback: displays success/error notifications for each update.
 */

const USER_TABS = ['profile', 'password', 'security', 'notifications'];
const PUSH_SERVICE_WORKER_PATH = '/service-worker.js';

let isTwoFactorEnabled = false;

document.addEventListener('DOMContentLoaded', () => {
    initializeSettings();
});

async function initializeSettings() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }

    setupUserInfo();
    setupLogoutButton();
    setupTabHandlers();
    setupFormHandlers();
    setupDepartmentSelects();
    setupTwoFactorCodeFormatting();
    setupPushNotificationHandlers();
    await loadUserSettings();
}

function setupDepartmentSelects() {
    populateDepartmentSelect('profile-department');
}

function populateDepartmentSelect(selectId) {
    const select = document.getElementById(selectId);
    if (!select) {
        return;
    }

    const departments = Array.isArray(window.APP_DEPARTMENTS) ? window.APP_DEPARTMENTS : [];
    const currentValue = select.value;

    select.innerHTML = [
        '<option value="">Select department</option>',
        ...departments.map((department) => `<option value="${department}">${department}</option>`),
    ].join('');

    select.value = departments.includes(currentValue) ? currentValue : '';
}

function setupTwoFactorCodeFormatting() {
    attachTwoFactorFormatter('settings-two-factor-code', 'settings-two-factor-setup-error');
    attachTwoFactorFormatter('settings-two-factor-disable-code', 'settings-two-factor-disable-error');
}

function attachTwoFactorFormatter(inputId, errorId) {
    const input = document.getElementById(inputId);
    if (!input) {
        return;
    }

    input.addEventListener('input', () => {
        input.value = formatTwoFactorCode(input.value);
        clearTwoFactorFieldError(inputId, errorId);
    });
}

function normalizeTwoFactorCode(value) {
    return String(value || '').replace(/\D/g, '').slice(0, 6);
}

function formatTwoFactorCode(value) {
    const digits = normalizeTwoFactorCode(value);
    if (digits.length <= 3) {
        return digits;
    }

    return `${digits.slice(0, 3)} ${digits.slice(3)}`;
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

    const twoFactorSetupForm = document.getElementById('two-factor-setup-form-settings');
    if (twoFactorSetupForm) {
        twoFactorSetupForm.addEventListener('submit', handleTwoFactorEnableFromSettings);
    }

    const twoFactorDisableForm = document.getElementById('two-factor-disable-form');
    if (twoFactorDisableForm) {
        twoFactorDisableForm.addEventListener('submit', handleTwoFactorDisableFromSettings);
    }

    const startTwoFactorSetupButton = document.getElementById('start-two-factor-setup-btn');
    if (startTwoFactorSetupButton) {
        startTwoFactorSetupButton.addEventListener('click', startTwoFactorSetupFromSettings);
    }

    const enablePushButton = document.getElementById('enable-browser-push-btn');
    if (enablePushButton) {
        enablePushButton.addEventListener('click', handleEnableBrowserNotifications);
    }

    const disablePushButton = document.getElementById('disable-browser-push-btn');
    if (disablePushButton) {
        disablePushButton.addEventListener('click', handleDisableBrowserNotifications);
    }

    const testPushButton = document.getElementById('test-browser-push-btn');
    if (testPushButton) {
        testPushButton.addEventListener('click', handleTestBrowserNotifications);
    }
}

function setupTabHandlers() {
    const tabButtons = document.querySelectorAll('.tab-btn');

    tabButtons.forEach((button) => {
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

        document.getElementById('profile-name').value = user.fullName || '';
        document.getElementById('profile-email').value = user.email || '';
        document.getElementById('profile-role').value = user.role || 'User';
        document.getElementById('profile-department').value = user.department || '';

        const preferences = getLocalStorage('notificationPreferences') || {};
        document.getElementById('notify-critical').checked = preferences.notifyCritical !== false;
        document.getElementById('notify-high').checked = preferences.notifyHigh !== false;
        document.getElementById('notify-new-incident').checked = preferences.notifyNewIncident !== false;
        document.getElementById('notify-resolved').checked = preferences.notifyResolved !== false;
        document.getElementById('notify-daily-summary').checked = preferences.notifyDailySummary !== false;

        isTwoFactorEnabled = Boolean(user.twoFactorEnabled);
        renderTwoFactorStatus();

        activateTab('profile');
        await loadPushNotificationState();
    } catch (error) {
        console.error('Error loading settings:', error);
        showNotification('Error loading settings', 'error');
    } finally {
        showLoading(false);
    }
}

function renderTwoFactorStatus() {
    const statusText = document.getElementById('two-factor-status-text');
    const startSetupButton = document.getElementById('start-two-factor-setup-btn');
    const setupPanel = document.getElementById('two-factor-setup-panel');
    const disableForm = document.getElementById('two-factor-disable-form');

    if (!statusText || !startSetupButton || !setupPanel || !disableForm) {
        return;
    }

    setupPanel.style.display = 'none';

    if (isTwoFactorEnabled) {
        statusText.textContent = '2FA is currently enabled for your account.';
        statusText.className = 'two-factor-status-enabled';
        startSetupButton.style.display = 'none';
        disableForm.style.display = 'flex';
    } else {
        statusText.textContent = '2FA is currently disabled for your account.';
        statusText.className = 'two-factor-status-disabled';
        startSetupButton.style.display = 'inline-flex';
        disableForm.style.display = 'none';
    }
}

async function startTwoFactorSetupFromSettings() {
    const setupPanel = document.getElementById('two-factor-setup-panel');
    const setupError = document.getElementById('settings-two-factor-setup-error');
    const qrImage = document.getElementById('settings-two-factor-qr-image');
    const manualKey = document.getElementById('settings-two-factor-manual-key');

    if (isTwoFactorEnabled) {
        showNotification('2FA is already enabled.', 'info');
        return;
    }

    setupError.textContent = '';
    showLoading(true);

    try {
        const setupResponse = await apiClient.getTwoFactorSetup();
        qrImage.src = setupResponse.qrCodeDataUrl;
        manualKey.textContent = setupResponse.manualEntryKey;
        setupPanel.style.display = 'block';
        setupPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        const codeInput = document.getElementById('settings-two-factor-code');
        if (codeInput) {
            codeInput.focus();
        }

        showNotification('2FA setup generated. Scan the QR code below.', 'success');
    } catch (error) {
        setupError.textContent = error.message || 'Could not start 2FA setup.';
    } finally {
        showLoading(false);
    }
}

async function handleTwoFactorEnableFromSettings(e) {
    e.preventDefault();

    const code = normalizeTwoFactorCode(document.getElementById('settings-two-factor-code').value);
    clearTwoFactorFieldError('settings-two-factor-code', 'settings-two-factor-setup-error');

    if (!/^\d{6}$/.test(code)) {
        setTwoFactorFieldError('settings-two-factor-code', 'settings-two-factor-setup-error', 'Enter a valid 6-digit code.');
        return;
    }

    showLoading(true);

    try {
        await apiClient.post('/auth/2fa/enable', { code });
        isTwoFactorEnabled = true;
        await refreshUserProfile();
        renderTwoFactorStatus();
        showNotification('2FA enabled successfully.', 'success');
    } catch (error) {
        setTwoFactorFieldError('settings-two-factor-code', 'settings-two-factor-setup-error', error.message || 'Could not enable 2FA.');
    } finally {
        showLoading(false);
    }
}

async function handleTwoFactorDisableFromSettings(e) {
    e.preventDefault();

    const code = normalizeTwoFactorCode(document.getElementById('settings-two-factor-disable-code').value);
    clearTwoFactorFieldError('settings-two-factor-disable-code', 'settings-two-factor-disable-error');

    if (!/^\d{6}$/.test(code)) {
        setTwoFactorFieldError('settings-two-factor-disable-code', 'settings-two-factor-disable-error', 'Enter a valid 6-digit code.');
        return;
    }

    showLoading(true);

    try {
        await apiClient.post('/auth/2fa/disable', { code });
        isTwoFactorEnabled = false;
        document.getElementById('two-factor-disable-form').reset();
        await refreshUserProfile();
        renderTwoFactorStatus();
        showNotification('2FA disabled successfully.', 'success');
    } catch (error) {
        setTwoFactorFieldError('settings-two-factor-disable-code', 'settings-two-factor-disable-error', error.message || 'Could not disable 2FA.');
    } finally {
        showLoading(false);
    }
}

async function refreshUserProfile() {
    const profileResponse = await apiClient.getProfile();
    const user = profileResponse?.user || profileResponse || {};

    setLocalStorage('user', user);
    isTwoFactorEnabled = Boolean(user.twoFactorEnabled);
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

function setTwoFactorFieldError(inputId, errorId, message) {
    const errorEl = document.getElementById(errorId);
    const input = document.getElementById(inputId);
    const formGroup = input ? input.closest('.form-group') : null;

    if (errorEl) {
        errorEl.textContent = message;
    }

    if (formGroup) {
        formGroup.classList.add('error');
    }
}

function clearTwoFactorFieldError(inputId, errorId) {
    const errorEl = document.getElementById(errorId);
    const input = document.getElementById(inputId);
    const formGroup = input ? input.closest('.form-group') : null;

    if (errorEl) {
        errorEl.textContent = '';
    }

    if (formGroup) {
        formGroup.classList.remove('error');
    }
}
function setupPushNotificationHandlers() {
    if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) {
        setPushNotificationStatus('Browser push notifications are not supported in this browser.', true);
        updatePushNotificationButtons(false);
        return;
    }

    updatePushNotificationButtons(false);
}

function updatePushNotificationButtons(isEnabled) {
    const enableButton = document.getElementById('enable-browser-push-btn');
    const disableButton = document.getElementById('disable-browser-push-btn');
    const testButton = document.getElementById('test-browser-push-btn');

    if (enableButton) {
        enableButton.disabled = isEnabled;
    }

    if (disableButton) {
        disableButton.disabled = !isEnabled;
    }

    if (testButton) {
        testButton.disabled = !isEnabled;
    }
}

function setPushNotificationStatus(message, isError = false) {
    const statusEl = document.getElementById('browser-push-status');
    if (!statusEl) {
        return;
    }

    statusEl.textContent = message;
    statusEl.className = isError ? 'error-message' : 'success-message';
}

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let index = 0; index < rawData.length; index += 1) {
        outputArray[index] = rawData.charCodeAt(index);
    }

    return outputArray;
}

async function registerPushServiceWorker() {
    return navigator.serviceWorker.register(PUSH_SERVICE_WORKER_PATH, { scope: '/' });
}

async function getActivePushSubscription() {
    const registration = await navigator.serviceWorker.getRegistration(PUSH_SERVICE_WORKER_PATH);
    if (!registration) {
        return null;
    }

    return registration.pushManager.getSubscription();
}

async function loadPushNotificationState() {
    if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) {
        setPushNotificationStatus('Browser push notifications are not supported in this browser.', true);
        updatePushNotificationButtons(false);
        return;
    }

    if (Notification.permission === 'denied') {
        setPushNotificationStatus('Notifications are blocked. Enable them in your browser settings first.', true);
        updatePushNotificationButtons(false);
        return;
    }

    const subscription = await getActivePushSubscription();
    if (subscription) {
        setPushNotificationStatus('Browser push notifications are enabled for this device.');
        updatePushNotificationButtons(true);
        return;
    }

    setPushNotificationStatus('Browser push notifications are currently disabled.');
    updatePushNotificationButtons(false);
}

async function handleEnableBrowserNotifications() {
    try {
        if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) {
            throw new Error('This browser does not support web push notifications.');
        }

        const permission = Notification.permission === 'default'
            ? await Notification.requestPermission()
            : Notification.permission;

        if (permission !== 'granted') {
            throw new Error('Notification permission is required to enable browser push alerts.');
        }

        const publicKeyResponse = await apiClient.get('/notifications/public-key');
        const publicKey = publicKeyResponse?.publicKey || ''; 
        if (!publicKey) {
            throw new Error('Push notifications are not configured on the server.');
        }

        const registration = await registerPushServiceWorker();
        const existingSubscription = await registration.pushManager.getSubscription();
        const subscription = existingSubscription || await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(publicKey),
        });

        await apiClient.post('/notifications/subscriptions', {
            subscription: subscription.toJSON(),
            deviceName: navigator.userAgentData?.platform || navigator.platform || 'Browser',
        });
        setPushNotificationStatus('Browser push notifications enabled for this device.');
        updatePushNotificationButtons(true);
        showNotification('Browser notifications enabled', 'success');
    } catch (error) {
        setPushNotificationStatus(error.message || 'Could not enable browser push notifications.', true);
        showNotification(error.message || 'Could not enable browser push notifications.', 'error');
    }
}

async function handleDisableBrowserNotifications() {
    try {
        const registration = await navigator.serviceWorker.getRegistration(PUSH_SERVICE_WORKER_PATH);
        if (!registration) {
            setPushNotificationStatus('Browser push notifications are currently disabled.', true);
            updatePushNotificationButtons(false);
            return;
        }

        const subscription = await registration.pushManager.getSubscription();

        if (subscription) {
            await apiClient.delete('/notifications/subscriptions', {
                body: { endpoint: subscription.endpoint },
            });
            await subscription.unsubscribe();
        }

        setPushNotificationStatus('Browser push notifications disabled for this device.');
        updatePushNotificationButtons(false);
        showNotification('Browser notifications disabled', 'success');
    } catch (error) {
        setPushNotificationStatus(error.message || 'Could not disable browser push notifications.', true);
        showNotification(error.message || 'Could not disable browser push notifications.', 'error');
    }
}

async function handleTestBrowserNotifications() {
    try {
        await apiClient.post('/notifications/test', {});
        setPushNotificationStatus('Test notification sent. Check your browser or phone notification tray.');
        showNotification('Test notification sent', 'success');
    } catch (error) {
        setPushNotificationStatus(error.message || 'Could not send a test notification.', true);
        showNotification(error.message || 'Could not send a test notification.', 'error');
    }
}