/**
 * Authentication Handler
 */

document.addEventListener('DOMContentLoaded', () => {
    initializeAuth();
});

function initializeAuth() {
    // Check if already logged in
    if (apiClient.isAuthenticated()) {
        window.location.href = 'dashboard.html';
    }

    // Setup form handlers
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const toggleSignupBtn = document.getElementById('toggle-signup');
    const toggleLoginBtn = document.getElementById('toggle-login');

    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
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

    // Clear previous errors
    clearFormError('email');
    clearFormError('password');
    clearFormError('form-error');

    // Validate
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
        
        if (response.token) {
            showNotification('Login successful!', 'success');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1000);
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

async function handleSignup(e) {
    e.preventDefault();

    const fullName = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm').value;

    // Clear previous errors
    clearFormError('signup-error');

    // Validate
    if (!fullName.trim()) {
        displayFormError('signup-name', 'Full name is required');
        return;
    }

    if (!validateEmail(email)) {
        displayFormError('signup-email', 'Please enter a valid email');
        return;
    }

    if (!validatePassword(password)) {
        displayFormError('signup-password', 'Password must be at least 8 characters');
        return;
    }

    if (password !== confirmPassword) {
        displayFormError('signup-confirm', 'Passwords do not match');
        return;
    }

    showLoading(true);

    try {
        const response = await apiClient.register(email, password, fullName);
        
        showNotification('Account created successfully! Please log in.', 'success');
        
        // Clear form
        document.getElementById('signup-form').reset();
        
        // Switch to login form
        setTimeout(() => {
            toggleForms();
        }, 1000);

    } catch (error) {
        showLoading(false);
        const errorMsg = error.message || 'Signup failed. Please try again.';
        document.getElementById('signup-error').textContent = errorMsg;
        showNotification(errorMsg, 'error');
    }
}

function logout() {
    apiClient.logout();
    window.location.href = 'index.html';
}