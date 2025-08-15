/**
 * Utility Functions for CVE Assessment Dashboard
 * Contains formatting, navigation, and helper functions
 */

const Utils = {
    /**
     * Format date to the required format: "16 Dec 1999"
     * @param {string|Date} dateInput - Date string or Date object
     * @returns {string} Formatted date string
     */
    formatDate(dateInput) {
        if (!dateInput) return 'N/A';
        
        try {
            const date = new Date(dateInput);
            if (isNaN(date.getTime())) return 'Invalid Date';
            
            const options = { 
                day: 'numeric', 
                month: 'short', 
                year: 'numeric' 
            };
            
            return date.toLocaleDateString('en-GB', options);
        } catch (error) {
            console.error('Date formatting error:', error);
            return 'Invalid Date';
        }
    },
    
    /**
     * Format CVE status with appropriate styling class
     * @param {string} status - CVE status
     * @returns {Object} Object with formatted status and CSS class
     */
    formatStatus(status) {
        if (!status) return { text: 'Unknown', class: 'status-unknown' };
        
        const statusLower = status.toLowerCase();
        const statusMap = {
            'analyzed': { text: 'Analyzed', class: 'status-analyzed' },
            'modified': { text: 'Modified', class: 'status-modified' },
            'rejected': { text: 'Rejected', class: 'status-rejected' },
            'awaiting analysis': { text: 'Awaiting Analysis', class: 'status-pending' },
            'undergoing analysis': { text: 'Undergoing Analysis', class: 'status-pending' }
        };
        
        return statusMap[statusLower] || { text: status, class: 'status-unknown' };
    },
    
    /**
     * Format CVSS score with severity
     * @param {number} score - CVSS score
     * @returns {Object} Object with score and severity
     */
    formatCVSSScore(score) {
        if (score === null || score === undefined) {
            return { score: 'N/A', severity: 'Unknown', class: 'cvss-unknown' };
        }
        
        const numScore = parseFloat(score);
        if (isNaN(numScore)) {
            return { score: 'N/A', severity: 'Unknown', class: 'cvss-unknown' };
        }
        
        let severity, cssClass;
        if (numScore >= 9.0) {
            severity = 'CRITICAL';
            cssClass = 'cvss-critical';
        } else if (numScore >= 7.0) {
            severity = 'HIGH';
            cssClass = 'cvss-high';
        } else if (numScore >= 4.0) {
            severity = 'MEDIUM';
            cssClass = 'cvss-medium';
        } else if (numScore > 0) {
            severity = 'LOW';
            cssClass = 'cvss-low';
        } else {
            severity = 'NONE';
            cssClass = 'cvss-none';
        }
        
        return { 
            score: numScore.toFixed(1), 
            severity: severity, 
            class: cssClass 
        };
    },
    
    /**
     * Truncate text to specified length
     * @param {string} text - Text to truncate
     * @param {number} maxLength - Maximum length
     * @returns {string} Truncated text
     */
    truncateText(text, maxLength = 100) {
        if (!text) return '';
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength).trim() + '...';
    },
    
    /**
     * Extract CVE ID from text or URL
     * @param {string} input - Input string
     * @returns {string|null} CVE ID or null if not found
     */
    extractCVEId(input) {
        if (!input) return null;
        const cvePattern = /CVE-\d{4}-\d{4,}/i;
        const match = input.match(cvePattern);
        return match ? match[0].toUpperCase() : null;
    },
    
    /**
     * Validate CVE ID format
     * @param {string} cveId - CVE ID to validate
     * @returns {boolean} True if valid
     */
    isValidCVEId(cveId) {
        if (!cveId) return false;
        const cvePattern = /^CVE-\d{4}-\d{4,}$/i;
        return cvePattern.test(cveId);
    },
    
    /**
     * Build pagination info
     * @param {number} currentPage - Current page number
     * @param {number} totalItems - Total number of items
     * @param {number} pageSize - Items per page
     * @returns {Object} Pagination information
     */
    buildPaginationInfo(currentPage, totalItems, pageSize) {
        const totalPages = Math.ceil(totalItems / pageSize);
        const startItem = (currentPage - 1) * pageSize + 1;
        const endItem = Math.min(currentPage * pageSize, totalItems);
        
        return {
            currentPage,
            totalPages,
            totalItems,
            pageSize,
            startItem,
            endItem,
            hasPrevious: currentPage > 1,
            hasNext: currentPage < totalPages
        };
    },
    
    /**
     * Generate pagination buttons
     * @param {Object} paginationInfo - Pagination information
     * @param {Function} onPageChange - Page change callback
     * @returns {string} HTML for pagination buttons
     */
    generatePaginationHTML(paginationInfo, onPageChange) {
        const { currentPage, totalPages, hasPrevious, hasNext } = paginationInfo;
        
        let html = '<div class="pagination-container">';
        
        // Previous button
        html += `<button class="pagination-button" ${!hasPrevious ? 'disabled' : ''} 
                 onclick="${onPageChange}(${currentPage - 1})">Previous</button>`;
        
        // Page numbers (show max 5 pages around current)
        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, currentPage + 2);
        
        if (startPage > 1) {
            html += `<button class="pagination-button" onclick="${onPageChange}(1)">1</button>`;
            if (startPage > 2) {
                html += '<span class="pagination-info">...</span>';
            }
        }
        
        for (let i = startPage; i <= endPage; i++) {
            const activeClass = i === currentPage ? 'active' : '';
            html += `<button class="pagination-button ${activeClass}" 
                     onclick="${onPageChange}(${i})">${i}</button>`;
        }
        
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                html += '<span class="pagination-info">...</span>';
            }
            html += `<button class="pagination-button" onclick="${onPageChange}(${totalPages})">${totalPages}</button>`;
        }
        
        // Next button
        html += `<button class="pagination-button" ${!hasNext ? 'disabled' : ''} 
                 onclick="${onPageChange}(${currentPage + 1})">Next</button>`;
        
        html += '</div>';
        return html;
    },
    
    /**
     * Show loading state
     * @param {string} containerId - Container element ID
     * @param {string} message - Loading message
     */
    showLoading(containerId, message = 'Loading...') {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = `
                <div class="loading-container">
                    <div class="loading-spinner"></div>
                    <p>${message}</p>
                </div>
            `;
        }
    },
    
    /**
     * Show error state
     * @param {string} containerId - Container element ID
     * @param {string} message - Error message
     * @param {Error} error - Error object
     */
    showError(containerId, message = 'An error occurred', error = null) {
        const container = document.getElementById(containerId);
        if (container) {
            const errorDetails = error ? `<p class="text-sm mt-2">${error.message}</p>` : '';
            container.innerHTML = `
                <div class="error-container">
                    <div class="error-title">${message}</div>
                    ${errorDetails}
                </div>
            `;
        }
        console.error('Error:', message, error);
    },
    
    /**
     * Debounce function calls
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in milliseconds
     * @returns {Function} Debounced function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    /**
     * Get URL parameters
     * @returns {Object} URL parameters
     */
    getURLParams() {
        const params = new URLSearchParams(window.location.search);
        const result = {};
        for (const [key, value] of params) {
            result[key] = value;
        }
        return result;
    },
    
    /**
     * Set URL parameters without page reload
     * @param {Object} params - Parameters to set
     */
    setURLParams(params) {
        const url = new URL(window.location);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                url.searchParams.set(key, value);
            } else {
                url.searchParams.delete(key);
            }
        });
        window.history.replaceState({}, '', url);
    },
    
    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    escapeHTML(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    /**
     * Format large numbers with commas
     * @param {number} num - Number to format
     * @returns {string} Formatted number
     */
    formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return parseInt(num).toLocaleString();
    },
    
    /**
     * Parse CVSS v2 vector string into individual metrics
     * @param {string} vector - CVSS vector (e.g., "AV:L/AC:L/Au:N/C:C/I:C/A:C")
     * @returns {Object} Parsed metrics
     */
    parseCVSSv2Vector(vector) {
        if (!vector) return null;
        
        const metrics = {};
        const parts = vector.split('/');
        
        parts.forEach(part => {
            const [key, value] = part.split(':');
            if (key && value) {
                metrics[key] = value;
            }
        });
        
        return {
            accessVector: this.expandCVSSValue('AV', metrics.AV),
            accessComplexity: this.expandCVSSValue('AC', metrics.AC),
            authentication: this.expandCVSSValue('Au', metrics.Au),
            confidentialityImpact: this.expandCVSSValue('C', metrics.C),
            integrityImpact: this.expandCVSSValue('I', metrics.I),
            availabilityImpact: this.expandCVSSValue('A', metrics.A)
        };
    },
    
    /**
     * Expand CVSS abbreviated values to full text
     * @param {string} metric - Metric type
     * @param {string} value - Abbreviated value
     * @returns {string} Expanded value
     */
    expandCVSSValue(metric, value) {
        if (!value) return 'N/A';
        
        const expansions = {
            'AV': { 'L': 'LOCAL', 'A': 'ADJACENT NETWORK', 'N': 'NETWORK' },
            'AC': { 'L': 'LOW', 'M': 'MEDIUM', 'H': 'HIGH' },
            'Au': { 'N': 'NONE', 'S': 'SINGLE', 'M': 'MULTIPLE' },
            'C': { 'N': 'NONE', 'P': 'PARTIAL', 'C': 'COMPLETE' },
            'I': { 'N': 'NONE', 'P': 'PARTIAL', 'C': 'COMPLETE' },
            'A': { 'N': 'NONE', 'P': 'PARTIAL', 'C': 'COMPLETE' }
        };
        
        return expansions[metric] && expansions[metric][value] ? expansions[metric][value] : value;
    }
};

// Export for global use
window.Utils = Utils;
