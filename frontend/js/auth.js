/**
 * Authentication Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.
/**
 * SECTION GUIDE:
 * 1) Auth Boot: redirects authenticated users and wires forms.
 * 2) Login Flow: validates input and handles optional 2FA challenge popup.
 * 3) Signup Flow: creates user and transitions to dashboard.
 * 4) 2FA Enrollment Prompt: asks after sign-in and allows setup now or later.
 */

let pendingTwoFactorChallengeToken = '';

document.addEventListener('DOMContentLoaded', () => {
    initializeAuth();
});

function initializeAuth() {
    if (apiClient.isAuthenticated()) {
        window.location.href = 'dashboard.html';
    }

    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const toggleSignupBtn = document.getElementById('toggle-signup');
    const toggleLoginBtn = document.getElementById('toggle-login');
    const twoFactorLoginForm = document.getElementById('two-factor-login-form');
    const twoFactorSetupForm = document.getElementById('two-factor-setup-form');
    const forgotPasswordStartForm = document.getElementById('forgot-password-start-form');
    const passwordResetWithTwoFactorForm = document.getElementById('password-reset-with-2fa-form');

    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
    }

    if (twoFactorLoginForm) {
        twoFactorLoginForm.addEventListener('submit', handleTwoFactorLoginSubmit);
    }

    if (twoFactorSetupForm) {
        twoFactorSetupForm.addEventListener('submit', handleTwoFactorEnableSubmit);
    }

    if (forgotPasswordStartForm) {
        forgotPasswordStartForm.addEventListener('submit', handleForgotPasswordStart);
    }

    if (passwordResetWithTwoFactorForm) {
        passwordResetWithTwoFactorForm.addEventListener('submit', handleResetPasswordWithTwoFactor);
    }

    if (toggleSignupBtn) {
        toggleSignupBtn.addEventListener('click', (e) => {
            e.preventDefault();
            toggleForms();
        });
    }

    if (toggleLoginBtn) {
        toggleLoginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            toggleForms();
        });
    }

    setupPasswordToggles();
    setupDepartmentSelects();
    setupTwoFactorModalActions();
    setupRecoveryCodeCopyButtons();
    setupForgotPasswordActions();
    setupRememberMeCheckbox();
    setupTwoFactorCodeFormatting();
    setupPasswordGuidance();
    setupResetPasswordGuidance();
}

function setupRecoveryCodeCopyButtons() {
    const copyButton = document.getElementById('two-factor-recovery-copy-btn');
    if (!copyButton) {
        return;
    }

    copyButton.addEventListener('click', async () => {
        const isCopied = await copyRecoveryCodesFromList('two-factor-recovery-codes-list');
        if (isCopied) {
            showNotification('Recovery codes copied to clipboard.', 'success');
        }
    });
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

function setupRememberMeCheckbox() {
    const rememberCheckbox = document.getElementById('remember');
    if (!rememberCheckbox || !apiClient || typeof apiClient.getRememberSessionPreference !== 'function') {
        return;
    }

    rememberCheckbox.checked = Boolean(apiClient.getRememberSessionPreference());
}

function setupForgotPasswordActions() {
    const openLink = document.getElementById('open-forgot-password-link');
    const cancelButton = document.getElementById('cancel-forgot-password-btn');
    const backButton = document.getElementById('back-forgot-password-btn');

    if (openLink) {
        openLink.addEventListener('click', (event) => {
            event.preventDefault();
            openForgotPasswordModal();
        });
    }

    if (cancelButton) {
        cancelButton.addEventListener('click', () => {
            closeForgotPasswordModal();
        });
    }

    if (backButton) {
        backButton.addEventListener('click', () => {
            showForgotPasswordStep('start');
        });
    }
}

function setupDepartmentSelects() {
    populateDepartmentSelect('signup-department');
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

function setupPasswordGuidance() {
    const signupPasswordInput = document.getElementById('signup-password');
    const signupEmailInput = document.getElementById('signup-email');

    if (!signupPasswordInput) {
        return;
    }

    const updateGuidance = () => {
        const emailValue = signupEmailInput ? signupEmailInput.value : '';
        renderPasswordGuidance(signupPasswordInput.value, emailValue);
    };

    signupPasswordInput.addEventListener('input', updateGuidance);

    if (signupEmailInput) {
        signupEmailInput.addEventListener('input', updateGuidance);
    }

    updateGuidance();
}

function setupResetPasswordGuidance() {
    const resetPasswordInput = document.getElementById('reset-new-password');
    const resetEmailInput = document.getElementById('reset-password-email');
    const forgotEmailInput = document.getElementById('forgot-password-email');

    if (!resetPasswordInput) {
        return;
    }

    const updateGuidance = () => {
        const resetEmailValue = resetEmailInput ? resetEmailInput.value : '';
        const forgotEmailValue = forgotEmailInput ? forgotEmailInput.value : '';
        const emailValue = resetEmailValue || forgotEmailValue;
        renderPasswordGuidanceByPrefix('reset', 'reset-password-strength', resetPasswordInput.value, emailValue);
    };

    resetPasswordInput.addEventListener('input', updateGuidance);

    if (resetEmailInput) {
        resetEmailInput.addEventListener('input', updateGuidance);
    }

    if (forgotEmailInput) {
        forgotEmailInput.addEventListener('input', updateGuidance);
    }

    updateGuidance();
}

function evaluatePasswordCriteria(password, email) {
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

function renderPasswordGuidance(password, email) {
    renderPasswordGuidanceByPrefix('', 'signup-password-strength', password, email);
}

function renderPasswordGuidanceByPrefix(rulePrefix, strengthId, password, email) {
    const { checks, score } = evaluatePasswordCriteria(password, email);
    const strengthEl = document.getElementById(strengthId);
    const idPrefix = rulePrefix ? `${rulePrefix}-` : '';

    const mapping = [
        [`${idPrefix}rule-length`, checks.length],
        [`${idPrefix}rule-upper`, checks.upper],
        [`${idPrefix}rule-lower`, checks.lower],
        [`${idPrefix}rule-number`, checks.number],
        [`${idPrefix}rule-symbol`, checks.symbol],
        [`${idPrefix}rule-space`, checks.space],
        [`${idPrefix}rule-common`, checks.common],
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

function setupTwoFactorModalActions() {
    const skipButton = document.getElementById('skip-2fa-for-now-btn');
    const enableNowButton = document.getElementById('enable-2fa-now-btn');
    const cancelTwoFactorLoginButton = document.getElementById('cancel-two-factor-login-btn');
    const cancelTwoFactorSetupButton = document.getElementById('cancel-two-factor-setup-btn');

    if (skipButton) {
        skipButton.addEventListener('click', () => {
            closeEnableTwoFactorPromptModal();
            window.location.href = 'dashboard.html';
        });
    }

    if (enableNowButton) {
        enableNowButton.addEventListener('click', () => {
            openTwoFactorSetupModal();
        });
    }

    if (cancelTwoFactorLoginButton) {
        cancelTwoFactorLoginButton.addEventListener('click', () => {
            closeTwoFactorLoginModal();
            pendingTwoFactorChallengeToken = '';
        });
    }

    if (cancelTwoFactorSetupButton) {
        cancelTwoFactorSetupButton.addEventListener('click', () => {
            closeTwoFactorSetupModal();
            window.location.href = 'dashboard.html';
        });
    }
}

function setupTwoFactorCodeFormatting() {
    attachTwoFactorFormatter('two-factor-login-code', 'two-factor-login-error');
    attachTwoFactorFormatter('two-factor-setup-code', 'two-factor-setup-error');
    attachTwoFactorFormatter('reset-authenticator-code', 'password-reset-error');
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

function toggleForms() {
    const loginSection = document.getElementById('login-form-section');
    const signupSection = document.getElementById('signup-form-section');

    if (loginSection && signupSection) {
        const loginVisible = loginSection.style.display !== 'none';
        loginSection.style.display = loginVisible ? 'none' : 'block';
        signupSection.style.display = loginVisible ? 'block' : 'none';
    }
}

async function handleLogin(e) {
    e.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const rememberSession = Boolean(document.getElementById('remember')?.checked);

    clearFormError('email');
    clearFormError('password');
    clearFormError('form-error');

    if (!validateEmail(email)) {
        displayFormError('email', 'Please enter a valid email');
        return;
    }

    if (!password) {
        displayFormError('password', 'Password is required');
        return;
    }

    showLoading(true);

    try {
        const response = await apiClient.login(email, password, rememberSession);
        showLoading(false);

        if (response.requiresTwoFactor) {
            pendingTwoFactorChallengeToken = response.challengeToken;
            openTwoFactorLoginModal();
            return;
        }


        if (response.token && response.promptToEnableTwoFactor) {
            openEnableTwoFactorPromptModal();
            return;
        }

        if (response.token) {
            showNotification('Login successful!', 'success');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 500);
        }
    } catch (error) {
        showLoading(false);
        const rawMessage = String(error.message || '');
        const isCredentialError = /invalid|incorrect|unauthorized|credential/i.test(rawMessage);
        const errorMsg = isCredentialError
            ? 'Incorrect password or email. Please try again.'
            : 'Login failed. Please try again.';

        if (isCredentialError) {
            displayFormError('password', 'Incorrect password');
        }

        document.getElementById('form-error').textContent = errorMsg;
        showNotification(errorMsg, 'error');
    }
}

async function handleTwoFactorLoginSubmit(e) {
    e.preventDefault();

    const codeInput = document.getElementById('two-factor-login-code');
    const code = normalizeTwoFactorCode(codeInput.value);

    if (!/^\d{6}$/.test(code)) {
        setTwoFactorLoginError('Enter the 2FA code correctly.');
        return;
    }

    showLoading(true);

    try {
        const verifyResponse = await apiClient.post('/auth/2fa/verify-login', {
            challengeToken: pendingTwoFactorChallengeToken,
            code,
        });
        apiClient.setToken(verifyResponse.token);
        localStorage.setItem('user', JSON.stringify(verifyResponse.user));
        showLoading(false);
        closeTwoFactorLoginModal();
        showNotification('Login successful!', 'success');
        window.location.href = 'dashboard.html';
    } catch (error) {
        showLoading(false);
        setTwoFactorLoginError(error.message || 'Enter the 2FA code correctly.');
    }
}

async function openTwoFactorSetupModal() {
    closeEnableTwoFactorPromptModal();

    const qrImage = document.getElementById('two-factor-qr-image');
    const manualKey = document.getElementById('two-factor-manual-key');
    const errorEl = document.getElementById('two-factor-setup-error');
    const codeInput = document.getElementById('two-factor-setup-code');
    const recoveryPanel = document.getElementById('two-factor-recovery-codes-panel');
    const recoveryList = document.getElementById('two-factor-recovery-codes-list');
    const cancelButton = document.getElementById('cancel-two-factor-setup-btn');
    const submitButton = document.querySelector('#two-factor-setup-form button[type="submit"]');

    errorEl.textContent = '';
    qrImage.src = '';
    manualKey.textContent = '';
    codeInput.value = '';
    codeInput.disabled = false;
    codeInput.required = true;

    if (recoveryPanel && recoveryList) {
        recoveryPanel.style.display = 'none';
        recoveryList.innerHTML = '';
    }

    if (cancelButton) {
        cancelButton.textContent = 'Skip for Now';
    }

    if (submitButton) {
        submitButton.style.display = '';
    }

    showLoading(true);

    try {
        const setupResponse = await apiClient.post('/auth/2fa/setup', {});
        qrImage.src = setupResponse.qrCodeDataUrl;
        manualKey.textContent = setupResponse.manualEntryKey;
        showLoading(false);
        document.getElementById('two-factor-setup-modal').style.display = 'flex';
    } catch (error) {
        showLoading(false);
        showNotification(error.message || 'Could not initialize 2FA setup.', 'error');
        window.location.href = 'dashboard.html';
    }
}

async function handleTwoFactorEnableSubmit(e) {
    e.preventDefault();

    const codeInput = document.getElementById('two-factor-setup-code');
    const code = normalizeTwoFactorCode(codeInput.value);
    const errorEl = document.getElementById('two-factor-setup-error');

    errorEl.textContent = '';

    if (!/^\d{6}$/.test(code)) {
        errorEl.textContent = 'Enter a valid 6-digit code.';
        return;
    }

    showLoading(true);

    try {
        const response = await apiClient.post('/auth/2fa/enable', { code });
        const recoveryCodes = Array.isArray(response.recoveryCodes) ? response.recoveryCodes : [];
        showLoading(false);

        if (recoveryCodes.length === 0) {
            closeTwoFactorSetupModal();
            showNotification('2FA enabled successfully.', 'success');
            window.location.href = 'dashboard.html';
            return;
        }

        renderRecoveryCodesInSetupModal(recoveryCodes);
        showNotification('2FA enabled. Save your recovery codes before continuing.', 'success');
    } catch (error) {
        showLoading(false);
        errorEl.textContent = error.message || 'Could not enable 2FA.';
    }
}

function renderRecoveryCodesInSetupModal(codes) {
    const codeInput = document.getElementById('two-factor-setup-code');
    const recoveryPanel = document.getElementById('two-factor-recovery-codes-panel');
    const recoveryList = document.getElementById('two-factor-recovery-codes-list');
    const cancelButton = document.getElementById('cancel-two-factor-setup-btn');
    const submitButton = document.querySelector('#two-factor-setup-form button[type="submit"]');

    if (!recoveryPanel || !recoveryList) {
        showNotification('2FA enabled successfully.', 'success');
        window.location.href = 'dashboard.html';
        return;
    }

    recoveryList.innerHTML = '';
    codes.forEach((code) => {
        const listItem = document.createElement('li');
        listItem.textContent = code;
        recoveryList.appendChild(listItem);
    });

    recoveryPanel.style.display = 'block';
    codeInput.disabled = true;
    codeInput.required = false;

    if (submitButton) {
        submitButton.style.display = 'none';
    }

    if (cancelButton) {
        cancelButton.textContent = 'Continue to Dashboard';
    }
}

function openTwoFactorLoginModal() {
    const modal = document.getElementById('two-factor-login-modal');
    const codeInput = document.getElementById('two-factor-login-code');

    if (!modal) {
        return;
    }

    clearTwoFactorLoginError();
    codeInput.value = '';
    modal.style.display = 'flex';
    codeInput.focus();
}

function closeTwoFactorLoginModal() {
    const modal = document.getElementById('two-factor-login-modal');
    if (modal) {
        modal.style.display = 'none';
        clearTwoFactorLoginError();
    }
}

function setTwoFactorLoginError(message) {
    setTwoFactorFieldError('two-factor-login-code', 'two-factor-login-error', message);
}

function clearTwoFactorLoginError() {
    clearTwoFactorFieldError('two-factor-login-code', 'two-factor-login-error');
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

function openEnableTwoFactorPromptModal() {
    const modal = document.getElementById('two-factor-enable-prompt-modal');
    if (modal) {
        modal.style.display = 'flex';
    }
}

function closeEnableTwoFactorPromptModal() {
    const modal = document.getElementById('two-factor-enable-prompt-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function closeTwoFactorSetupModal() {
    const modal = document.getElementById('two-factor-setup-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function openForgotPasswordModal() {
    const modal = document.getElementById('forgot-password-modal');
    if (!modal) {
        return;
    }

    modal.style.display = 'flex';
    showForgotPasswordStep('start');
}

function closeForgotPasswordModal() {
    const modal = document.getElementById('forgot-password-modal');
    if (!modal) {
        return;
    }

    modal.style.display = 'none';
    document.getElementById('forgot-password-start-form')?.reset();
    document.getElementById('password-reset-with-2fa-form')?.reset();
    document.getElementById('forgot-password-start-error').textContent = '';
    document.getElementById('password-reset-error').textContent = '';
    renderPasswordGuidanceByPrefix('reset', 'reset-password-strength', '', '');
}

function showForgotPasswordStep(step) {
    const startForm = document.getElementById('forgot-password-start-form');
    const resetForm = document.getElementById('password-reset-with-2fa-form');

    if (!startForm || !resetForm) {
        return;
    }

    if (step === 'start') {
        startForm.style.display = 'block';
        resetForm.style.display = 'none';
        return;
    }

    startForm.style.display = 'none';
    resetForm.style.display = 'block';

    const resetPasswordInput = document.getElementById('reset-new-password');
    const resetEmailInput = document.getElementById('reset-password-email');
    const emailValue = resetEmailInput ? resetEmailInput.value : '';
    const passwordValue = resetPasswordInput ? resetPasswordInput.value : '';
    renderPasswordGuidanceByPrefix('reset', 'reset-password-strength', passwordValue, emailValue);
}

async function handleForgotPasswordStart(event) {
    event.preventDefault();

    const emailInput = document.getElementById('forgot-password-email');
    const errorEl = document.getElementById('forgot-password-start-error');
    const hiddenEmailInput = document.getElementById('reset-password-email');
    const email = String(emailInput?.value || '').trim();

    errorEl.textContent = '';

    if (!validateEmail(email)) {
        errorEl.textContent = 'Enter a valid email address.';
        return;
    }

    showLoading(true);

    try {
        await apiClient.forgotPassword(email);
        hiddenEmailInput.value = email;
        showLoading(false);
        showForgotPasswordStep('reset');
        renderPasswordGuidanceByPrefix('reset', 'reset-password-strength', document.getElementById('reset-new-password')?.value || '', email);
        showNotification('Verification step ready. Use your authenticator or recovery code to reset password.', 'info');
    } catch (error) {
        showLoading(false);
        errorEl.textContent = error.message || 'Unable to continue password reset.';
    }
}

async function handleResetPasswordWithTwoFactor(event) {
    event.preventDefault();

    const email = String(document.getElementById('reset-password-email').value || '').trim();
    const newPassword = String(document.getElementById('reset-new-password').value || '');
    const confirmPassword = String(document.getElementById('reset-confirm-password').value || '');
    const totpCode = normalizeTwoFactorCode(document.getElementById('reset-authenticator-code').value);
    const recoveryCode = String(document.getElementById('reset-recovery-code').value || '').trim();
    const errorEl = document.getElementById('password-reset-error');

    errorEl.textContent = '';

    if (newPassword !== confirmPassword) {
        errorEl.textContent = 'New password and confirmation must match.';
        return;
    }

    const passwordEvaluation = evaluatePasswordCriteria(newPassword, email);
    if (!passwordEvaluation.isStrong) {
        errorEl.textContent = 'Use a stronger password that meets all requirements.';
        return;
    }

    if (!/^\d{6}$/.test(totpCode) && !recoveryCode) {
        errorEl.textContent = 'Provide either a 6-digit authenticator code or a recovery code.';
        return;
    }

    showLoading(true);

    try {
        await apiClient.resetPassword({
            email,
            newPassword,
            totpCode,
            recoveryCode,
        });
        showLoading(false);
        showNotification('Password reset completed. Please sign in again.', 'success');
        closeForgotPasswordModal();
    } catch (error) {
        showLoading(false);
        errorEl.textContent = error.message || 'Password reset failed. Please verify your code and try again.';
    }
}

async function handleSignup(e) {
    e.preventDefault();

    const fullName = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm').value;
    const department = document.getElementById('signup-department').value;

    clearFormError('signup-error');
    clearFormError('signup-department');

    if (!fullName.trim()) {
        displayFormError('signup-name', 'Full name is required');
        return;
    }

    if (!validateEmail(email)) {
        displayFormError('signup-email', 'Please enter a valid email');
        return;
    }

    const passwordEvaluation = evaluatePasswordCriteria(password, email);
    if (!passwordEvaluation.isStrong) {
        displayFormError('signup-password', 'Use a stronger password. Follow the guidance below.');
        return;
    }

    if (password !== confirmPassword) {
        displayFormError('signup-confirm', 'Passwords do not match');
        return;
    }

    if (!department) {
        displayFormError('signup-department', 'Department is required');
        return;
    }

    showLoading(true);

    try {
        const registerResponse = await apiClient.register(email, password, fullName, department);
        apiClient.setToken(registerResponse.token);
        localStorage.setItem('user', JSON.stringify(registerResponse.user));
        showLoading(false);

        showNotification('Account created successfully!', 'success');
        document.getElementById('signup-form').reset();

        openEnableTwoFactorPromptModal();
    } catch (error) {
        showLoading(false);
        const errorMsg = error.message || 'Signup failed. Please try again.';
        document.getElementById('signup-error').textContent = errorMsg;
        showNotification(errorMsg, 'error');
    }
}

function logout() {
    apiClient.logout();
    window.location.href = 'login.html';
}











