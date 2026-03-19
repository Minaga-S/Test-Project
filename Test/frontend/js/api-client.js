/**
 * API Client - Centralized API communication
 */

const API_BASE_URL = 'http://localhost:5000/api';

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
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (this.token) {
            headers.Authorization = `Bearer ${this.token}`;
        }

        const config = {
            method: options.method || 'GET',
            headers,
            ...options,
        };

        if (options.body) {
            config.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(url, config);

            // Handle 401 - Unauthorized
            if (response.status === 401) {
                this.clearAuth();
                window.location.href = '/index.html';
                return null;
            }

            // Handle network errors
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || `HTTP ${response.status}`);
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

    async register(email, password, fullName) {
        return this.post('/auth/register', {
            email,
            password,
            fullName,
        });
    }

    async login(email, password) {
        const response = await this.post('/auth/login', {
            email,
            password,
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

    // ============== ASSET ENDPOINTS ==============

    async createAsset(assetData) {
        return this.post('/assets', assetData);
    }

    async getAssets() {
        return this.get('/assets');
    }

    async getAsset(id) {
        return this.get(`/assets/${id}`);
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
        return this.get('/asset-types');
    }

    // ============== INCIDENT ENDPOINTS ==============

    async createIncident(incidentData) {
        return this.post('/incidents', incidentData);
    }

    async getIncidents() {
        return this.get('/incidents');
    }

    async getIncident(id) {
        return this.get(`/incidents/${id}`);
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
