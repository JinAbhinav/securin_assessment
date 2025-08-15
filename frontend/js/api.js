/**
 * API Module for CVE Assessment Dashboard
 * Handles all communication with the backend API
 */

const API = {
    // Base URL for the API
    baseURL: 'http://localhost:8000/api/v1',
    
    /**
     * Generic fetch wrapper with error handling
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        try {
            const response = await fetch(url, config);
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => null);
                throw new Error(errorData?.detail || `HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    },
    
    /**
     * Get CVE list with pagination and filtering
     * @param {Object} params - Query parameters
     * @param {number} params.page - Page number (default: 1)
     * @param {number} params.size - Page size (default: 10)
     * @param {string} params.sort - Sort field (default: 'last_modified')
     * @param {string} params.order - Sort order (default: 'desc')
     */
    async getCVEList(params = {}) {
        const queryParams = new URLSearchParams({
            page: params.page || 1,
            size: params.size || 10,
            sort: params.sort || 'last_modified',
            order: params.order || 'desc',
            ...params
        });
        
        return await this.request(`/cves?${queryParams}`);
    },
    
    /**
     * Get total CVE count
     */
    async getCVECount() {
        return await this.request('/cves/count');
    },
    
    /**
     * Get specific CVE by ID
     * @param {string} cveId - CVE ID (e.g., 'CVE-2023-12345')
     */
    async getCVEById(cveId) {
        return await this.request(`/cves/${encodeURIComponent(cveId)}`);
    },
    
    /**
     * Search CVEs by keyword
     * @param {string} keyword - Search keyword
     * @param {Object} params - Additional parameters
     */
    async searchCVEs(keyword, params = {}) {
        const queryParams = new URLSearchParams({
            keyword: keyword,
            page: params.page || 1,
            size: params.size || 10,
            sort: params.sort || 'last_modified',
            order: params.order || 'desc',
            ...params
        });
        
        return await this.request(`/cves?${queryParams}`);
    },
    
    /**
     * Get CVEs by year
     * @param {number} year - Publication year
     */
    async getCVEsByYear(year) {
        return await this.request(`/cves/year/${year}`);
    },
    
    /**
     * Get CVEs by score range
     * @param {number} minScore - Minimum CVSS score
     * @param {number} maxScore - Maximum CVSS score
     */
    async getCVEsByScore(minScore, maxScore) {
        return await this.request(`/cves/score/${minScore}/${maxScore}`);
    },
    
    /**
     * Get recently modified CVEs
     * @param {number} days - Number of days
     */
    async getRecentCVEs(days) {
        return await this.request(`/cves/modified/${days}`);
    },
    
    /**
     * Get CVE statistics
     */
    async getCVEStatistics() {
        return await this.request('/cves/statistics');
    },
    
    /**
     * Get CVEs modified in last N days
     * @param {number} days - Number of days to look back
     */
    async getCVEsModifiedInDays(days) {
        return await this.request(`/cves/modified/${days}`);
    },
    
    /**
     * Search CVEs by keyword
     * @param {string} keyword - Search keyword
     * @param {number} limit - Maximum results (default: 100)
     */
    async searchCVEsByKeyword(keyword, limit = 100) {
        const params = new URLSearchParams({
            q: keyword,
            limit: limit
        });
        return await this.request(`/cves/search/?${params}`);
    },
    
    /**
     * Get CVE statistics
     */
    async getCVEStatistics() {
        return await this.request('/cves/statistics/');
    },

    /**
     * Health check
     */
    async healthCheck() {
        return await this.request('/health', { baseURL: 'http://localhost:8000' });
    }
};

// Export for global use
window.API = API;
