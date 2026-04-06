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

function resolveApiBaseUrl() {
    const overrideUrl = localStorage.getItem('apiBaseUrlOverride');
    if (overrideUrl) {
        return overrideUrl;
    }

    const host = window.location.hostname;
    const isLocalHost = host === 'localhost' || host === '127.0.0.1';

    return isLocalHost ? LOCAL_API_BASE_URL : PROD_API_BASE_URL;
}

const API_BASE_URL = resolveApiBaseUrl();

class APIClient {
    constructor() {
        this.token = localStorage.getItem('accessToken');
        this.baseURL = API_BASE_URL;
    }

    /**
     * Set authentication token
     */
    setToken(token) {
        this.token = token;
        localStorage.setItem('accessToken', token);
    }

    /**
     * Get authentication token
     */
    getToken() {
        return localStorage.getItem('accessToken');
    }

    /**
     * Clear authentication
     */
    clearAuth() {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('user');
        this.token = null;
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.getToken();
    }

    /**
     * Make HTTP request
     */
    async request(endpoint, options = {}) {
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
                this.clearAuth();
                window.location.href = 'login.html';
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
                    ? `${errorPayload.message || 'Request failed'} - ${fieldErrors.join(', ')}`
                    : (errorPayload.message || `HTTP ${response.status}`);

                throw new Error(detailedMessage);
            }

            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    /**
     * GET request
     */
    get(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'GET' });
    }

    /**
     * POST request
     */
    post(endpoint, body, options = {}) {
        return this.request(endpoint, { ...options, method: 'POST', body });
    }

    /**
     * PUT request
     */
    put(endpoint, body, options = {}) {
        return this.request(endpoint, { ...options, method: 'PUT', body });
    }

    /**
     * DELETE request
     */
    delete(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'DELETE' });
    }

    // ============== AUTH ENDPOINTS ==============

    async register(email, password, fullName, department) {
        return this.post('/auth/register', {
            email,
            password,
            fullName,
            department,
        });
    }

    async login(email, password) {
        const response = await this.post('/auth/login', {
            email,
            password,
        });

        if (response.token && !response.requiresTwoFactor) {
            this.setToken(response.token);
            localStorage.setItem('user', JSON.stringify(response.user));
        }

        return response;
    }

    async verifyTwoFactorLogin(challengeToken, code) {
        const response = await this.post('/auth/2fa/verify-login', {
            challengeToken,
            code,
        });

        if (response.token) {
            this.setToken(response.token);
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

    // ============== ASSET ENDPOINTS ==============

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
        return this.get(`/assets/search?query=${query}`);
    }

    async getAssetTypes() {
        return this.get('/assets/asset-types');
    }

    async scanAssets(assetIds) {
        return this.post('/assets/scan', { assetIds });
    }

    async previewAssetScan(payload) {
        return this.post('/assets/scan-preview', payload);
    }

    async getAssetSecurityContext(assetId) {
        return this.get(`/assets/${assetId}/security-context`);
    }

    // ============== INCIDENT ENDPOINTS ==============

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

    // ============== THREAT ENDPOINTS ==============

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

    // ============== RISK ENDPOINTS ==============

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

    // ============== NIST CSF ENDPOINTS ==============

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

    // ============== DASHBOARD ENDPOINTS ==============

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
}

// Create singleton instance
const apiClient = new APIClient();










