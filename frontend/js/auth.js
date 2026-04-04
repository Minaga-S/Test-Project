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
    setupTwoFactorModalActions();
    setupTwoFactorCodeFormatting();
    setupPasswordGuidance();
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

function evaluatePasswordCriteria(password, email) {
    const value = String(password || '');
    const lowerValue = value.toLowerCase();
    const emailLocalPart = String(email || '').split('@')[0].toLowerCase();

    const checks = {
        length: value.length >= 12,
        upper: /[A-Z]/.test(value),
        lower: /[a-z]/.test(value),
        number: /\d/.test(value),
        symbol: /[^A-Za-z0-9]/.test(value),
        space: !/\s/.test(value),
        common: !/(password|123456|qwerty|letmein|admin|welcome)/i.test(value),
        emailPart: emailLocalPart.length < 3 || !lowerValue.includes(emailLocalPart),
    };

    const score = Object.values(checks).filter(Boolean).length;

    return {
        checks,
        score,
        isStrong: score >= 7 && checks.emailPart,
    };
}

function renderPasswordGuidance(password, email) {
    const { checks, score } = evaluatePasswordCriteria(password, email);
    const strengthEl = document.getElementById('signup-password-strength');

    const mapping = [
        ['rule-length', checks.length],
        ['rule-upper', checks.upper],
        ['rule-lower', checks.lower],
        ['rule-number', checks.number],
        ['rule-symbol', checks.symbol],
        ['rule-space', checks.space],
        ['rule-common', checks.common],
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
    attachTwoFactorFormatter('two-factor-login-code');
    attachTwoFactorFormatter('two-factor-setup-code');
}

function attachTwoFactorFormatter(inputId) {
    const input = document.getElementById(inputId);
    if (!input) {
        return;
    }

    input.addEventListener('input', () => {
        input.value = formatTwoFactorCode(input.value);
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
        const response = await apiClient.login(email, password);
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

    errorEl.textContent = '';
    qrImage.src = '';
    manualKey.textContent = '';

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
        await apiClient.post('/auth/2fa/enable', { code });
        showLoading(false);
        closeTwoFactorSetupModal();
        showNotification('2FA enabled successfully.', 'success');
        window.location.href = 'dashboard.html';
    } catch (error) {
        showLoading(false);
        errorEl.textContent = error.message || 'Could not enable 2FA.';
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
    const errorEl = document.getElementById('two-factor-login-error');
    const codeInput = document.getElementById('two-factor-login-code');
    const formGroup = codeInput ? codeInput.closest('.form-group') : null;

    if (errorEl) {
        errorEl.textContent = message;
    }

    if (formGroup) {
        formGroup.classList.add('error');
    }
}

function clearTwoFactorLoginError() {
    const errorEl = document.getElementById('two-factor-login-error');
    const codeInput = document.getElementById('two-factor-login-code');
    const formGroup = codeInput ? codeInput.closest('.form-group') : null;

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

async function handleSignup(e) {
    e.preventDefault();

    const fullName = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm').value;

    clearFormError('signup-error');

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

    showLoading(true);

    try {
        const registerResponse = await apiClient.register(email, password, fullName);
        apiClient.setToken(registerResponse.token);
        localStorage.setItem('user', JSON.stringify(registerResponse.user));

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