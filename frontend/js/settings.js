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

const USER_TABS = ['profile', 'password', 'security', 'local-scanner', 'notifications'];
const LOCAL_SCANNER_HEALTH_URL = 'http://127.0.0.1:47633/health';

let isTwoFactorEnabled = false;
let shouldShowTwoFactorRecoveryCodes = false;
let isTwoFactorSetupInProgress = false;

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
    setupTermsAndConditionsLink();
    setupFormHandlers();
    setupDepartmentSelects();
    setupTwoFactorCodeFormatting();
    setupPasswordToggles();
    setupPasswordGuidance();
    setupLocalScannerPanel();
    await loadUserSettings();
}

function setupLocalScannerPanel() {
    const refreshButton = document.getElementById('local-scanner-refresh-btn');
    if (refreshButton) {
        refreshButton.addEventListener('click', async () => {
            await refreshLocalScannerStatus();
        });
    }
}

function isLocalScannerFetchAllowed() {
    const host = String(window.location.hostname || '').toLowerCase();
    const isLoopbackHost = host === 'localhost' || host === '127.0.0.1';
    return window.isSecureContext || isLoopbackHost;
}

function getLocalScannerAddressSpace(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
            return 'loopback';
        }

        return 'local';
    } catch (error) {
        return 'local';
    }
}

function buildLocalScannerFetchOptions(options = {}) {
    const requestOptions = {
        ...options,
        mode: 'cors',
        credentials: 'omit',
    };

    if (window.isSecureContext) {
        requestOptions.targetAddressSpace = getLocalScannerAddressSpace(LOCAL_SCANNER_HEALTH_URL);
    }

    return requestOptions;
}

async function isLocalScannerReachable() {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 1800);

    try {
        const response = await fetch(LOCAL_SCANNER_HEALTH_URL, buildLocalScannerFetchOptions({
            method: 'GET',
            signal: controller.signal,
        }));

        if (!response.ok) {
            return false;
        }

        const payload = await response.json().catch(() => ({}));
        return payload?.status === 'ok';
    } catch (error) {
        return false;
    } finally {
        window.clearTimeout(timeoutId);
    }
}

async function refreshLocalScannerStatus() {
    const badge = document.getElementById('local-scanner-status-badge');
    const message = document.getElementById('local-scanner-health-message');
    if (!badge || !message) {
        return;
    }

    badge.textContent = 'Checking...';
    badge.className = 'local-scanner-status local-scanner-status-offline';

    if (!isLocalScannerFetchAllowed()) {
        badge.textContent = 'Unavailable';
        message.textContent = 'Use HTTPS (for example your Render URL) or localhost to enable local scanner connectivity checks.';
        return;
    }

    const isReachable = await isLocalScannerReachable();
    if (isReachable) {
        badge.textContent = 'Online';
        badge.className = 'local-scanner-status local-scanner-status-online';
        message.textContent = 'Scanner is running locally and ready to receive scan requests.';
        return;
    }

    badge.textContent = 'Offline';
    badge.className = 'local-scanner-status local-scanner-status-offline';
    message.textContent = 'Scanner is not reachable. Start the local scanner app and allow loopback/local network access in Chrome if prompted.';
}

function setupPasswordToggles() {
    const toggleButtons = document.querySelectorAll('.password-toggle');

    toggleButtons.forEach((button) => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-password-target');
            const input = document.getElementById(targetId);
            if (!input) {
                return;
            }

            const isMasked = input.type === 'password';
            input.type = isMasked ? 'text' : 'password';
            button.setAttribute('aria-label', isMasked ? 'Hide password' : 'Show password');

            const icon = button.querySelector('.material-symbols-rounded');
            if (icon) {
                icon.textContent = isMasked ? 'visibility_off' : 'visibility';
            }
        });
    });
}

function setupPasswordGuidance() {
    const newPasswordInput = document.getElementById('new-password');

    if (!newPasswordInput) {
        return;
    }

    const updateGuidance = () => {
        renderPasswordGuidance(newPasswordInput.value);
    };

    newPasswordInput.addEventListener('input', updateGuidance);
    updateGuidance();
}

function evaluatePasswordCriteria(password) {
    const value = String(password || '');

    const checks = {
        length: value.length >= 12,
        upper: /[A-Z]/.test(value),
        lower: /[a-z]/.test(value),
        number: /\d/.test(value),
        symbol: /[^A-Za-z0-9]/.test(value),
        space: !/\s/.test(value),
        common: !/(password|123456|qwerty)/i.test(value),
    };

    const score = Object.values(checks).filter(Boolean).length;

    return {
        checks,
        score,
        isStrong: score >= 7,
    };
}

function renderPasswordGuidance(password) {
    const { checks, score } = evaluatePasswordCriteria(password);
    const strengthEl = document.getElementById('settings-password-strength');

    const mapping = [
        ['settings-rule-length', checks.length],
        ['settings-rule-upper', checks.upper],
        ['settings-rule-lower', checks.lower],
        ['settings-rule-number', checks.number],
        ['settings-rule-symbol', checks.symbol],
        ['settings-rule-space', checks.space],
        ['settings-rule-common', checks.common],
    ];

    mapping.forEach(([id, isMet]) => {
        const el = document.getElementById(id);
        if (el) {
            el.classList.toggle('is-met', isMet);
        }
    });

    if (!strengthEl) {
        return;
    }

    if (score <= 3) {
        strengthEl.textContent = 'Strength: Weak';
        strengthEl.className = 'password-strength strength-weak';
        return;
    }

    if (score <= 6) {
        strengthEl.textContent = 'Strength: Fair';
        strengthEl.className = 'password-strength strength-fair';
        return;
    }

    strengthEl.textContent = 'Strength: Strong';
    strengthEl.className = 'password-strength strength-strong';
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

    const copyRecoveryCodesButton = document.getElementById('settings-two-factor-recovery-copy-btn');
    if (copyRecoveryCodesButton) {
        copyRecoveryCodesButton.addEventListener('click', async () => {
            const isCopied = await copyRecoveryCodesFromList('settings-two-factor-recovery-codes-list');
            if (isCopied) {
                showNotification('Recovery codes copied to clipboard.', 'success');
            }
        });
    }
}

function getInitialSettingsTab() {
    const params = new URLSearchParams(window.location.search);
    const requestedTab = String(params.get('tab') || '').trim().toLowerCase();
    return USER_TABS.includes(requestedTab) ? requestedTab : 'profile';
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

function setupTermsAndConditionsLink() {
    const termsBtn = document.getElementById('open-terms-from-settings-btn');
    const closeBtn = document.getElementById('close-terms-btn');
    const modal = document.getElementById('terms-and-conditions-modal');
    const overlay = modal?.querySelector('.modal-overlay');
    
    if (termsBtn) {
        termsBtn.addEventListener('click', () => {
            openTermsAndConditionsModalFromSettings();
        });
    }
    
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            closeTermsAndConditionsModal();
        });
    }
    
    if (overlay) {
        overlay.addEventListener('click', () => {
            closeTermsAndConditionsModal();
        });
    }
}

function openTermsAndConditionsModalFromSettings() {
    const modal = document.getElementById('terms-and-conditions-modal');
    if (!modal) {
        return;
    }
    
    const cancelBtn = document.getElementById('cancel-terms-btn');
    const agreeBtn = document.getElementById('complete-terms-btn');
    const closeBtn = document.getElementById('close-terms-btn');
    
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (agreeBtn) agreeBtn.style.display = 'none';
    if (closeBtn) closeBtn.style.display = 'block';
    
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

function closeTermsAndConditionsModal() {
    const modal = document.getElementById('terms-and-conditions-modal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
    }
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
        await refreshLocalScannerStatus();

        activateTab(getInitialSettingsTab());
    } catch (error) {
        console.error('Error loading settings:', error);
        showNotification('Error loading settings', 'error');
    }
}

function renderTwoFactorStatus() {
    const statusText = document.getElementById('two-factor-status-text');
    const startSetupButton = document.getElementById('start-two-factor-setup-btn');
    const setupPanel = document.getElementById('two-factor-setup-panel');
    const disableForm = document.getElementById('two-factor-disable-form');
    const recommendation = document.getElementById('security-recommendation');

    if (!statusText || !startSetupButton || !setupPanel || !disableForm) {
        return;
    }

    if (recommendation) {
        recommendation.classList.toggle('is-hidden', isTwoFactorEnabled);
    }

    setupPanel.style.display = shouldShowTwoFactorRecoveryCodes ? 'block' : 'none';

    if (isTwoFactorEnabled) {
        statusText.textContent = '2FA is currently enabled for your account.';
        statusText.className = 'two-factor-status-enabled';
        startSetupButton.style.display = 'none';
        disableForm.style.display = 'flex';
        isTwoFactorSetupInProgress = false;
    } else {
        statusText.textContent = '2FA is currently disabled for your account.';
        statusText.className = 'two-factor-status-disabled';
        startSetupButton.style.display = isTwoFactorSetupInProgress ? 'none' : 'inline-flex';
        disableForm.style.display = 'none';
    }
}

async function startTwoFactorSetupFromSettings() {
    const setupPanel = document.getElementById('two-factor-setup-panel');
    const setupError = document.getElementById('settings-two-factor-setup-error');
    const qrImage = document.getElementById('settings-two-factor-qr-image');
    const manualKey = document.getElementById('settings-two-factor-manual-key');
    const recoveryPanel = document.getElementById('settings-two-factor-recovery-codes-panel');
    const recoveryCodesList = document.getElementById('settings-two-factor-recovery-codes-list');
    const submitButton = document.querySelector('#two-factor-setup-panel button[type="submit"]');
    const codeInput = document.getElementById('settings-two-factor-code');

    if (isTwoFactorEnabled) {
        showNotification('2FA is already enabled.', 'info');
        return;
    }

    isTwoFactorSetupInProgress = true;
    const startSetupButton = document.getElementById('start-two-factor-setup-btn');
    if (startSetupButton) {
        startSetupButton.style.display = 'none';
    }

    setupError.textContent = '';
    if (recoveryPanel && recoveryCodesList) {
        recoveryPanel.style.display = 'none';
        recoveryCodesList.innerHTML = '';
    }

    shouldShowTwoFactorRecoveryCodes = false;

    if (submitButton) {
        submitButton.style.display = '';
    }

    if (codeInput) {
        codeInput.disabled = false;
        codeInput.required = true;
        codeInput.value = '';
    }

    showLoading(true);

    try {
        const setupResponse = await apiClient.getTwoFactorSetup();
        qrImage.src = setupResponse.qrCodeDataUrl;
        manualKey.textContent = setupResponse.manualEntryKey;
        setupPanel.style.display = 'block';
        setupPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        if (codeInput) {
            codeInput.focus();
        }

        showNotification('2FA setup generated. Scan the QR code below.', 'success');
    } catch (error) {
        isTwoFactorSetupInProgress = false;
        if (startSetupButton) {
            startSetupButton.style.display = 'inline-flex';
        }
        setupError.textContent = error.message || 'Could not start 2FA setup.';
    } finally {
        showLoading(false);
    }
}

async function handleTwoFactorEnableFromSettings(e) {
    e.preventDefault();

    const codeInput = document.getElementById('settings-two-factor-code');
    const recoveryPanel = document.getElementById('settings-two-factor-recovery-codes-panel');
    const recoveryCodesList = document.getElementById('settings-two-factor-recovery-codes-list');
    const submitButton = document.querySelector('#two-factor-setup-panel button[type="submit"]');
    const code = normalizeTwoFactorCode(codeInput.value);
    clearTwoFactorFieldError('settings-two-factor-code', 'settings-two-factor-setup-error');

    if (!/^\d{6}$/.test(code)) {
        setTwoFactorFieldError('settings-two-factor-code', 'settings-two-factor-setup-error', 'Enter a valid 6-digit code.');
        return;
    }

    showLoading(true);

    try {
        const enableResponse = await apiClient.post('/auth/2fa/enable', { code });
        if (Array.isArray(enableResponse.recoveryCodes) && enableResponse.recoveryCodes.length > 0) {
            shouldShowTwoFactorRecoveryCodes = true;
            renderRecoveryCodesInSettingsPanel(enableResponse.recoveryCodes, recoveryPanel, recoveryCodesList, codeInput, submitButton);
            showNotification('2FA enabled. Save your recovery codes before continuing.', 'success');
        } else {
            shouldShowTwoFactorRecoveryCodes = false;
            showNotification('2FA enabled successfully.', 'success');
        }

        isTwoFactorEnabled = true;
        isTwoFactorSetupInProgress = false;
        await refreshUserProfile();
        renderTwoFactorStatus();
    } catch (error) {
        setTwoFactorFieldError('settings-two-factor-code', 'settings-two-factor-setup-error', error.message || 'Could not enable 2FA.');
    } finally {
        showLoading(false);
    }
}

function renderRecoveryCodesInSettingsPanel(recoveryCodes, recoveryPanel, recoveryCodesList, codeInput, submitButton) {
    if (!recoveryPanel || !recoveryCodesList) {
        return;
    }

    recoveryCodesList.innerHTML = '';
    recoveryCodes.forEach((recoveryCode) => {
        const listItem = document.createElement('li');
        listItem.textContent = recoveryCode;
        recoveryCodesList.appendChild(listItem);
    });

    recoveryPanel.style.display = 'block';

    if (codeInput) {
        codeInput.disabled = true;
        codeInput.required = false;
    }

    if (submitButton) {
        submitButton.style.display = 'none';
    }
}

async function copyRecoveryCodesFromList(listId) {
    const recoveryCodesList = document.getElementById(listId);
    if (!recoveryCodesList) {
        return false;
    }

    const recoveryCodes = Array.from(recoveryCodesList.querySelectorAll('li'))
        .map((item) => item.textContent.trim())
        .filter((code) => code.length > 0);

    if (recoveryCodes.length === 0) {
        showNotification('No recovery codes available to copy yet.', 'info');
        return false;
    }

    const textToCopy = recoveryCodes.join('\n');

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(textToCopy);
            return true;
        }

        const fallbackTextarea = document.createElement('textarea');
        fallbackTextarea.value = textToCopy;
        fallbackTextarea.setAttribute('readonly', '');
        fallbackTextarea.style.position = 'fixed';
        fallbackTextarea.style.left = '-9999px';
        document.body.appendChild(fallbackTextarea);
        fallbackTextarea.select();

        const isCopied = document.execCommand('copy');
        document.body.removeChild(fallbackTextarea);

        if (!isCopied) {
            throw new Error('Clipboard copy command failed');
        }

        return true;
    } catch (error) {
        showNotification('Could not copy recovery codes. Please copy them manually.', 'error');
        return false;
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
        isTwoFactorSetupInProgress = false;
        shouldShowTwoFactorRecoveryCodes = false;
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

    const passwordEvaluation = evaluatePasswordCriteria(newPassword);
    if (!passwordEvaluation.isStrong) {
        document.getElementById('password-error').textContent = 'Use a stronger password that meets all requirements.';
        return;
    }

    showLoading(true);

    try {
        await apiClient.changePassword(currentPassword, newPassword);

        showNotification('Password changed successfully', 'success');
        document.getElementById('password-form').reset();
        document.getElementById('password-success').textContent = '';
        document.getElementById('password-error').textContent = '';
        renderPasswordGuidance('');
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



