/**
 * API Client - Centralized API communication
 */
// NOTE: API helper: central place for HTTP requests, auth headers, and response normalization.
/**
 * SECTION GUIDE:
 * 1) Base URL Resolution: chooses local or deployed API endpoint.
 * 2) Request Layer: centralizes GET/POST/PUT/DELETE behavior and headers.
 * 3) Auth Session: stores tokens/user and injects auth into requests.
 * 4) Endpoint Methods: exposes app-specific calls used by page scripts.
 */

const PROD_API_BASE_URL = 'https://test-project-x7d2.onrender.com/api';
const LOCAL_API_BASE_URL = 'http://localhost:5000/api';
const SESSION_ACTIVITY_KEY = 'sessionLastActivityAt';
const SESSION_STARTED_KEY = 'sessionStartedAt';
const ACCESS_TOKEN_STORAGE_KEY = 'accessToken';
const REFRESH_TOKEN_STORAGE_KEY = 'refreshToken';
const DEFAULT_INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_ABSOLUTE_TIMEOUT_MS = 24 * 60 * 60 * 1000;

function resolveApiBaseUrl() {
    const overrideUrl = localStorage.getItem('apiBaseUrlOverride');
    if (overrideUrl) {
        return overrideUrl;
    }

    const host = window.location.hostname;
    const isLocalHost = host === 'localhost' || host === '127.0.0.1';

    return isLocalHost ? LOCAL_API_BASE_URL : (/^\d+\.\d+\.\d+\.\d+$/.test(host) ? `http://${host}:5000/api` : PROD_API_BASE_URL);
}

const API_BASE_URL = resolveApiBaseUrl();

class APIClient {
    constructor() {
        this.token = sessionStorage.getItem(ACCESS_TOKEN_STORAGE_KEY)
            || localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
        this.refreshToken = sessionStorage.getItem(REFRESH_TOKEN_STORAGE_KEY)
            || localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY);
        this.baseURL = API_BASE_URL;
        this.isSessionTrackingInitialized = false;

        // Backward-compatible migration: keep existing users logged in while moving
        // token persistence from localStorage to sessionStorage.
        if (this.token && localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY)) {
            localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
            sessionStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, this.token);
        }

        this.initializeSessionTracking();
    }

    setToken(token, refreshToken = null) {
        this.token = token;
        sessionStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, token);
        localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);

        if (refreshToken) {
            this.refreshToken = refreshToken;
            sessionStorage.setItem(REFRESH_TOKEN_STORAGE_KEY, refreshToken);
            localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
        }

        const now = String(Date.now());
        if (!localStorage.getItem(SESSION_STARTED_KEY)) {
            localStorage.setItem(SESSION_STARTED_KEY, now);
        }

        localStorage.setItem(SESSION_ACTIVITY_KEY, now);
    }

    getToken() {
        return sessionStorage.getItem(ACCESS_TOKEN_STORAGE_KEY)
            || localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
    }

    getRefreshToken() {
        return sessionStorage.getItem(REFRESH_TOKEN_STORAGE_KEY)
            || localStorage.getItem(REFRESH_TOKEN_STORAGE_KEY);
    }

    clearAuth() {
        sessionStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
        sessionStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
        localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
        localStorage.removeItem(REFRESH_TOKEN_STORAGE_KEY);
        localStorage.removeItem('user');
        localStorage.removeItem(SESSION_ACTIVITY_KEY);
        localStorage.removeItem(SESSION_STARTED_KEY);
        this.token = null;
        this.refreshToken = null;
    }

    getApiOrigin() {
        return this.baseURL.endsWith('/api')
            ? this.baseURL.slice(0, -4)
            : this.baseURL;
    }

    isSessionValid() {
        const token = this.getToken();
        if (!token) {
            return false;
        }

        const startedAt = Number.parseInt(localStorage.getItem(SESSION_STARTED_KEY) || '0', 10);
        const lastActivityAt = Number.parseInt(localStorage.getItem(SESSION_ACTIVITY_KEY) || '0', 10);
        const now = Date.now();

        // If legacy/session metadata is missing, avoid unexpected forced logout and
        // let the backend token validity remain the source of truth.
        if (!startedAt || !lastActivityAt) {
            return true;
        }

        const isInactiveExpired = (now - lastActivityAt) > DEFAULT_INACTIVITY_TIMEOUT_MS;
        const isAbsoluteExpired = (now - startedAt) > DEFAULT_ABSOLUTE_TIMEOUT_MS;

        return !isInactiveExpired && !isAbsoluteExpired;
    }

    markActivity() {
        if (this.getToken()) {
            localStorage.setItem(SESSION_ACTIVITY_KEY, String(Date.now()));
        }
    }

    initializeSessionTracking() {
        if (this.isSessionTrackingInitialized) {
            return;
        }

        ['click', 'keydown', 'mousemove', 'scroll', 'touchstart'].forEach((eventName) => {
            window.addEventListener(eventName, () => this.markActivity(), { passive: true });
        });

        this.isSessionTrackingInitialized = true;
    }

    handleSessionExpiry() {
        this.clearAuth();
        if (!window.location.pathname.endsWith('login.html')) {
            window.location.href = 'login.html';
        }
    }

    isAuthenticated() {
        const isValid = this.isSessionValid();
        if (!isValid && this.getToken()) {
            this.handleSessionExpiry();
        }

        return isValid;
    }

    async request(endpoint, options = {}) {
        const isAuthFreeEndpoint = endpoint.startsWith('/auth/login')
            || endpoint.startsWith('/auth/register')
            || endpoint.startsWith('/auth/forgot-password')
            || endpoint.startsWith('/auth/reset-password')
            || endpoint.startsWith('/auth/refresh');

        if (!isAuthFreeEndpoint && this.getToken() && !this.isSessionValid()) {
            this.handleSessionExpiry();
            return null;
        }

        const url = `${this.baseURL}${endpoint}`;
        const method = options.method || 'GET';
        const hasBody = options.body !== undefined && options.body !== null;
        const isJsonBody = hasBody && !(options.body instanceof FormData);

        const headers = {
            ...options.headers,
        };

        if (isJsonBody && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        if (this.token) {
            headers.Authorization = `Bearer ${this.token}`;
        }

        const config = {
            method,
            headers,
            ...options,
        };

        if (hasBody) {
            config.body = isJsonBody ? JSON.stringify(options.body) : options.body;
        }

        try {
            const response = await fetch(url, config);

            const hasAuthorizationHeader = Boolean(headers.Authorization);
            if (response.status === 401 && hasAuthorizationHeader) {
                if (!options.__retryAfterRefresh && this.getRefreshToken()) {
                    const refreshed = await this.refreshSession();
                    if (refreshed) {
                        return this.request(endpoint, { ...options, __retryAfterRefresh: true });
                    }
                }

                // Treat 401 on authenticated calls as hard session expiry to prevent
                // loops where stale tokens keep triggering unauthorized requests.
                this.handleSessionExpiry();
                return null;
            }

            if (!response.ok) {
                let errorPayload = {};

                try {
                    errorPayload = await response.json();
                } catch (parseError) {
                    errorPayload = {};
                }

                const fieldErrors = Array.isArray(errorPayload?.errors)
                    ? errorPayload.errors
                        .map((item) => {
                            if (item?.field && item?.message) {
                                return `${item.field}: ${item.message}`;
                            }

                            if (typeof item === 'string') {
                                return item;
                            }

                            return null;
                        })
                        .filter(Boolean)
                    : [];

                const detailedMessage = fieldErrors.length > 0
                    // Merge field-level validation details into one message so UI callers
                    // can surface actionable errors without endpoint-specific parsing.
                    ? `${errorPayload.message || 'Request failed'} - ${fieldErrors.join(', ')}`
                    : (errorPayload.message || `HTTP ${response.status}`);

                throw new Error(detailedMessage);
            }

            this.markActivity();
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    async refreshSession() {
        const refreshToken = this.getRefreshToken();
        if (!refreshToken) {
            return false;
        }

        try {
            const response = await fetch(`${this.baseURL}/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ refreshToken }),
            });

            if (!response.ok) {
                return false;
            }

            const payload = await response.json();
            if (payload?.token && payload?.refreshToken) {
                this.setToken(payload.token, payload.refreshToken);
                return true;
            }

            return false;
        } catch (error) {
            console.error('Refresh session error:', error);
            return false;
        }
    }

    get(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'GET' });
    }

    post(endpoint, body, options = {}) {
        return this.request(endpoint, { ...options, method: 'POST', body });
    }

    put(endpoint, body, options = {}) {
        return this.request(endpoint, { ...options, method: 'PUT', body });
    }

    delete(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'DELETE' });
    }

    async register(email, password, fullName, department, securityQuestions) {
        return this.post('/auth/register', {
            email,
            password,
            fullName,
            department,
            securityQuestions,
        });
    }

    async login(email, password) {
        const response = await this.post('/auth/login', {
            email,
            password,
        });

        if (response.token && !response.requiresTwoFactor) {
            this.setToken(response.token, response.refreshToken);
            localStorage.setItem('user', JSON.stringify(response.user));
        }

        return response;
    }

    async forgotPassword(email) {
        return this.post('/auth/forgot-password', { email });
    }

    async resetPassword(payload) {
        return this.post('/auth/reset-password', payload);
    }

    async verifyTwoFactorLogin(challengeToken, code) {
        const response = await this.post('/auth/2fa/verify-login', {
            challengeToken,
            code,
        });

        if (response.token) {
            this.setToken(response.token, response.refreshToken);
            localStorage.setItem('user', JSON.stringify(response.user));
        }

        return response;
    }

    async logout() {
        this.clearAuth();
        return { success: true };
    }

    async getProfile() {
        return this.get('/auth/profile');
    }

    async updateProfile(data) {
        return this.put('/auth/profile', data);
    }

    async getSecurityQuestions() {
        return this.get('/auth/security-questions');
    }

    async updateSecurityQuestions(securityQuestions) {
        return this.put('/auth/security-questions', { securityQuestions });
    }

    async changePassword(currentPassword, newPassword) {
        return this.post('/auth/change-password', {
            currentPassword,
            newPassword,
        });
    }

    async getTwoFactorSetup() {
        return this.post('/auth/2fa/setup', {});
    }

    async enableTwoFactor(code) {
        return this.post('/auth/2fa/enable', { code });
    }

    async disableTwoFactor(code) {
        return this.post('/auth/2fa/disable', { code });
    }

    async createAsset(assetData) {
        const response = await this.post('/assets', assetData);
        return response?.asset || response;
    }

    async getAssets() {
        const response = await this.get('/assets');
        return response?.assets || [];
    }

    async getAsset(id) {
        const response = await this.get(`/assets/${id}`);
        return response?.asset || response;
    }

    async updateAsset(id, assetData) {
        return this.put(`/assets/${id}`, assetData);
    }

    async deleteAsset(id) {
        return this.delete(`/assets/${id}`);
    }

    async searchAssets(query) {
        const encodedQuery = encodeURIComponent(String(query || ''));
        return this.get(`/assets/search?query=${encodedQuery}`);
    }

    async getAssetTypes() {
        return this.get('/assets/asset-types');
    }

    async requestLocalScannerScan(payload) {
        return this.post('/local-scanner/requests', payload);
    }

    async getAssetSecurityContext(assetId) {
        return this.get(`/assets/${assetId}/security-context`);
    }

    async getPushPublicKey() {
        const response = await this.get('/notifications/public-key');
        return response?.publicKey || '';
    }

    async subscribeToPushNotifications(subscription, deviceName = 'Browser') {
        return this.post('/notifications/subscriptions', {
            subscription,
            deviceName,
        });
    }

    async unsubscribeFromPushNotifications(endpoint) {
        return this.delete('/notifications/subscriptions', {
            body: { endpoint },
        });
    }

    async sendPushTest() {
        return this.post('/notifications/test', {});
    }

    async createIncident(incidentData) {
        const response = await this.post('/incidents', incidentData);
        return response?.incident || response;
    }

    async getIncidents() {
        const response = await this.get('/incidents');
        return response?.incidents || [];
    }

    async getIncident(id) {
        const response = await this.get(`/incidents/${id}`);
        return response?.incident || response;
    }

    async updateIncident(id, incidentData) {
        return this.put(`/incidents/${id}`, incidentData);
    }

    async deleteIncident(id) {
        return this.delete(`/incidents/${id}`);
    }

    async searchIncidents(query) {
        return this.get(`/incidents/search?query=${query}`);
    }

    async updateIncidentStatus(id, status) {
        return this.put(`/incidents/${id}/status`, { status });
    }

    async addIncidentNote(id, note) {
        return this.post(`/incidents/${id}/notes`, { note });
    }

    async analyzeThreat(description) {
        return this.post('/threats/analyze', {
            description,
        });
    }

    async getThreatKnowledgeBase() {
        return this.get('/threats/knowledge-base');
    }

    async getThreatCategories() {
        return this.get('/threats/categories');
    }

    async classifyThreat(description) {
        return this.post('/threats/classify', {
            description,
        });
    }

    async calculateRisk(likelihood, impact) {
        return this.post('/risk/calculate', {
            likelihood,
            impact,
        });
    }

    async getRiskAssessment(incidentId) {
        return this.get(`/risk/assessment/${incidentId}`);
    }

    async getRiskMatrix() {
        return this.get('/risk/matrix');
    }

    async getRiskTrends() {
        return this.get('/risk/trends');
    }

    async getRiskByAsset() {
        return this.get('/risk/by-asset');
    }

    async getNISTFunctions() {
        return this.get('/nist/functions');
    }

    async getNISTControls(threatType) {
        return this.get(`/nist/controls/${threatType}`);
    }

    async getNISTMapping(incidentId) {
        return this.get(`/nist/mapping/${incidentId}`);
    }

    async getNISTRecommendations(threatType) {
        return this.get(`/nist/recommendations/${threatType}`);
    }

    async getComplianceReport(format = 'json') {
        return this.get(`/nist/compliance-report?format=${encodeURIComponent(format)}`);
    }

    async getDashboardMetrics() {
        return this.get('/dashboard/metrics');
    }

    async getMetricsTrends() {
        return this.get('/dashboard/metrics/trends');
    }

    async getRiskDistributionChart() {
        return this.get('/dashboard/charts/risk-distribution');
    }

    async getThreatCategoriesChart() {
        return this.get('/dashboard/charts/threat-categories');
    }

    async getVulnerableAssetsChart() {
        return this.get('/dashboard/charts/vulnerable-assets');
    }

    async getRecentIncidents() {
        return this.get('/dashboard/recent-incidents');
    }

    async getAuditLogs(params = {}) {
        const searchParams = new URLSearchParams();
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null && String(value).trim() !== '') {
                searchParams.set(key, String(value));
            }
        });

        const queryString = searchParams.toString();
        const endpoint = queryString ? `/audit-logs?${queryString}` : '/audit-logs';
        return this.get(endpoint);
    }

    async getAuditLogSummary() {
        return this.get('/audit-logs/summary');
    }
}

const apiClient = new APIClient();
