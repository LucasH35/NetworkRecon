/**
 * NetworkRecon - API Module
 * Handles all communication with the backend API
 */

const API_BASE = window.location.hostname === 'localhost'
    ? 'http://localhost:8000/api'
    : '/api';

/**
 * API Client class for NetworkRecon backend
 */
class NetworkReconAPI {
    constructor() {
        this.baseURL = API_BASE;
        this.loadingStates = {};
        this.listeners = {};
    }

    /**
     * Get loading state for a specific key
     */
    isLoading(key) {
        return this.loadingStates[key] || false;
    }

    /**
     * Set loading state and notify listeners
     */
    setLoading(key, state) {
        this.loadingStates[key] = state;
        this.notify('loading', { key, state });
    }

    /**
     * Subscribe to API events
     */
    on(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }

    /**
     * Notify listeners of an event
     */
    notify(event, data) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(cb => cb(data));
        }
    }

    /**
     * Generic fetch handler with error handling
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const loadingKey = options.loadingKey || endpoint;

        this.setLoading(loadingKey, true);

        try {
            const fetchOptions = {
                ...options,
                headers: {
                    ...options.headers,
                },
            };

            // Only set Content-Type for requests with a body
            if (options.body) {
                fetchOptions.headers['Content-Type'] = 'application/json';
            }

            const response = await fetch(url, fetchOptions);

            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                // Extract readable message from FastAPI validation errors
                let detail = error.detail || `Erreur HTTP ${response.status}`;
                if (Array.isArray(detail)) {
                    detail = detail.map(d => d.msg || JSON.stringify(d)).join(', ');
                } else if (typeof detail === 'object') {
                    detail = detail.msg || detail.message || JSON.stringify(detail);
                }
                throw new APIError(detail, response.status, error);
            }

            if (response.status === 204) {
                return null;
            }

            return await response.json();
        } catch (error) {
            if (error instanceof APIError) {
                throw error;
            }
            throw new APIError(
                error.message || 'Erreur de connexion au serveur',
                0,
                { originalError: error }
            );
        } finally {
            this.setLoading(loadingKey, false);
        }
    }

    /**
     * GET request
     */
    async get(endpoint, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        return this.request(url, { method: 'GET' });
    }

    /**
     * POST request with JSON body
     */
    async post(endpoint, data = {}, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    /**
     * POST request with query params only (no body)
     */
    async postWithParams(endpoint, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        return this.request(url, {
            method: 'POST',
        });
    }

    /**
     * PUT request
     */
    async put(endpoint, data = {}) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    /**
     * DELETE request
     */
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }

    // ===================== Campaigns API =====================

    async getCampaigns(params = {}) {
        return this.get('/scans/', params);
    }

    async getCampaign(id) {
        return this.get(`/scans/${id}`);
    }

    /**
     * Create a new campaign.
     * Backend target is hardcoded to 192.168.2.0/24.
     */
    async createCampaign({ name, description, scan_type, ports_range }) {
        const body = { name };
        if (description) body.description = description;
        if (scan_type) body.scan_type = scan_type;
        if (ports_range) body.ports_range = ports_range;

        return this.request('/scans/', {
            method: 'POST',
            body: JSON.stringify(body),
        });
    }

    async getCampaignStatus(id) {
        return this.get(`/scans/${id}/status`);
    }

    async pauseCampaign(id) {
        return this.postWithParams(`/scans/${id}/pause`);
    }

    async resumeCampaign(id) {
        return this.postWithParams(`/scans/${id}/resume`);
    }

    async cancelCampaign(id) {
        return this.postWithParams(`/scans/${id}/cancel`);
    }

    async deleteCampaign(id) {
        return this.delete(`/scans/${id}`);
    }

    // ===================== Hosts API =====================

    async getHosts(params = {}) {
        return this.get('/hosts/', params);
    }

    async getHost(ip) {
        return this.get(`/hosts/${ip}`);
    }

    async getHostPorts(ip) {
        return this.get(`/hosts/${ip}/ports`);
    }

    async getHostVulnerabilities(ip) {
        return this.get(`/hosts/${ip}/vulnerabilities`);
    }

    async getHostMitreMappings(ip) {
        return this.get(`/hosts/${ip}/mitre`);
    }

    async getHostAuthResults(ip) {
        return this.get(`/hosts/${ip}/auth-results`);
    }

    // ===================== Vulnerabilities API =====================

    async getVulnerabilities(params = {}) {
        return this.get('/vulnerabilities/', params);
    }

    async getVulnerabilitySummary() {
        return this.get('/vulnerabilities/summary');
    }

    async getCVE(cveId) {
        return this.get(`/vulnerabilities/${cveId}`);
    }

    async lookupCVE(service, version = '') {
        return this.post('/vulnerabilities/lookup', {}, { service, version });
    }

    // ===================== MITRE API =====================

    async getMITRETactics() {
        return this.get('/mitre/tactics');
    }

    async getMITRETechniques(params = {}) {
        return this.get('/mitre/techniques', params);
    }

    async getMITRETechniqueDetails(techniqueId) {
        return this.get(`/mitre/techniques/${techniqueId}`);
    }

    async getAttackPaths(params = {}) {
        return this.get('/mitre/attack-paths', params);
    }

    async exportSTIX() {
        return this.get('/mitre/export/stix');
    }

    // ===================== Auth Tests API =====================

    async getAuthTests(params = {}) {
        return this.get('/auth-tests/', params);
    }

    async getAuthTestCampaign(campaignId) {
        return this.get(`/auth-tests/${campaignId}`);
    }

    async runAuthTests(params = {}) {
        return this.post('/auth-tests/', {}, params);
    }

    async getAttackSuggestions(params = {}) {
        return this.get('/auth-tests/suggestions', params);
    }

    async launchFromSuggestion(params = {}) {
        return this.post('/auth-tests/launch-suggestion', {}, params);
    }

    async deleteAuthTestCampaign(campaignId) {
        return this.request(`/auth-tests/${campaignId}`, { method: 'DELETE' });
    }

    async sshExec(data) {
        return this.post('/auth-tests/ssh-exec', data);
    }

    async getCampaignProgress(campaignId) {
        return this.get(`/auth-tests/${campaignId}/progress`);
    }

    // ===================== SQLMap API =====================

    async getSqlmapCampaigns(params = {}) {
        return this.get('/sqlmap/', params);
    }

    async createSqlmapCampaign(data) {
        return this.post('/sqlmap/', data);
    }

    async getSqlmapCampaign(campaignId) {
        return this.get(`/sqlmap/${campaignId}`);
    }

    async deleteSqlmapCampaign(campaignId) {
        return this.request(`/sqlmap/${campaignId}`, { method: 'DELETE' });
    }

    async cancelSqlmapCampaign(campaignId) {
        return this.post(`/sqlmap/${campaignId}/cancel`);
    }

    // ===================== Reports API =====================

    async getReportCampaign(campaignId, params = {}) {
        return this.get(`/reports/campaign/${campaignId}`, params);
    }

    // ===================== Dashboard API =====================

    async getDashboardStats() {
        return this.get('/dashboard/stats');
    }

    // ===================== Health Check =====================

    async healthCheck() {
        try {
            const response = await fetch(`${this.baseURL.replace('/api', '')}/health`);
            return response.ok;
        } catch {
            return false;
        }
    }
}

/**
 * Custom API Error class
 */
class APIError extends Error {
    constructor(message, status, data) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.data = data;
    }
}

// Create singleton instance
const api = new NetworkReconAPI();
