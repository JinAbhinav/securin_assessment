/**
 * Main Application Logic for NVD API Dashboard
 * Handles routing, page management, and application state
 */

const App = {
    // Application state
    state: {
        currentPage: 1,
        pageSize: 10,
        totalRecords: 0,
        currentCVEList: [],
        sortField: 'last_modified',
        sortOrder: 'desc',
        totalPages: 0
            },
        
        // Handle sync button click
        async handleSync() {
            const syncBtn = document.getElementById('sync-btn');
            const syncIcon = document.getElementById('sync-icon');
            const syncText = document.getElementById('sync-text');
            const syncSelect = document.getElementById('sync-options');
            
            try {
                // Check if sync is already running
                const runningResponse = await API.request('/sync/running');
                if (runningResponse.is_running) {
                    alert('A sync is already running. Please wait for it to complete.');
                    return;
                }
                
                // Get selected sync type
                const selectedOption = syncSelect.value;
                const syncConfig = {
                    type: selectedOption,
                    displayName: selectedOption === 'full' ? 'Full Sync' : 'Incremental Sync'
                };
                
                // Start sync
                syncBtn.disabled = true;
                syncSelect.disabled = true;
                syncBtn.classList.add('syncing');
                syncText.textContent = `Starting ${syncConfig.displayName}...`;
                
                // Build sync request
                const syncRequest = {
                    sync_type: syncConfig.type,
                    force: false
                };
                
                const syncResponse = await API.request('/sync/', {
                    method: 'POST',
                    body: JSON.stringify(syncRequest)
                });
                
                // Update button to show syncing state
                syncText.textContent = `${syncConfig.displayName} Running...`;
                
                // Monitor sync progress
                this.monitorSyncProgress(syncResponse.sync_id, syncConfig);
                
            } catch (error) {
                console.error('Error starting sync:', error);
                alert('Failed to start sync. Please try again.');
                
                // Reset button state
                syncBtn.disabled = false;
                syncSelect.disabled = false;
                syncBtn.classList.remove('syncing');
                syncText.textContent = 'Sync';
            }
        },
        
        // Monitor sync progress
        async monitorSyncProgress(syncId, syncConfig) {
            const syncBtn = document.getElementById('sync-btn');
            const syncText = document.getElementById('sync-text');
            const syncSelect = document.getElementById('sync-options');
            
            const checkProgress = async () => {
                try {
                    const status = await API.request(`/sync/status/${syncId}`);
                    
                    if (status.status === 'running') {
                        const progress = status.processed_records || 0;
                        const total = status.total_records || 0;
                        
                        if (total > 0) {
                            syncText.textContent = `${syncConfig.displayName}: ${progress}/${total}`;
                        } else {
                            syncText.textContent = `${syncConfig.displayName}: ${progress} processed`;
                        }
                        
                        // Continue monitoring
                        setTimeout(checkProgress, 2000);
                    } else {
                        // Sync completed - reset controls
                        syncBtn.disabled = false;
                        syncSelect.disabled = false;
                        syncBtn.classList.remove('syncing');
                        
                        if (status.status === 'completed') {
                            const newRecords = status.new_records || 0;
                            const updatedRecords = status.updated_records || 0;
                            syncText.textContent = `✅ +${newRecords} new, ~${updatedRecords} updated`;
                            setTimeout(() => {
                                syncText.textContent = 'Sync';
                            }, 4000);
                        } else {
                            syncText.textContent = 'Sync Failed';
                            setTimeout(() => {
                                syncText.textContent = 'Sync';
                            }, 3000);
                        }
                    }
                } catch (error) {
                    console.error('Error checking sync status:', error);
                    syncBtn.disabled = false;
                    syncSelect.disabled = false;
                    syncBtn.classList.remove('syncing');
                    syncText.textContent = 'Sync';
                }
            };
            
            // Start monitoring
            setTimeout(checkProgress, 1000);
        },
        
        // Check sync status on page load
        async checkInitialSyncStatus() {
            try {
                const runningResponse = await API.request('/sync/running');
                if (runningResponse.is_running) {
                    // Get the latest sync status
                    const statusResponse = await API.request('/sync/status');
                    if (statusResponse) {
                        const syncBtn = document.getElementById('sync-btn');
                        const syncSelect = document.getElementById('sync-options');
                        const syncText = document.getElementById('sync-text');
                        
                        // Disable controls
                        syncBtn.disabled = true;
                        syncSelect.disabled = true;
                        syncBtn.classList.add('syncing');
                        
                        // Determine sync type from API response
                        const syncConfig = {
                            type: statusResponse.sync_type,
                            displayName: statusResponse.sync_type === 'full' ? 'Full Sync' : 'Incremental Sync'
                        };
                        
                        syncText.textContent = `${syncConfig.displayName} Running...`;
                        
                        // Monitor the existing sync
                        this.monitorSyncProgress(statusResponse.id, syncConfig);
                    }
                }
            } catch (error) {
                console.log('No active sync found or error checking sync status');
            }
        },
        
        // Initialize the application
        init() {
            console.log('NVD API Dashboard initializing...');
            this.router.init();
            
            // Check if sync is already running
            setTimeout(() => this.checkInitialSyncStatus(), 1000);
        },
    
    // Router module
    router: {
        routes: {
            '/cves/list': () => App.pages.list.render(),
            '/cves/': (cveId) => App.pages.detail.render(cveId)
        },
        
        init() {
            // Set up route handling with History API
            window.addEventListener('popstate', this.handleRoute.bind(this));
            
            // Handle initial route or default to list
            const initialRoute = window.location.pathname || '/cves/list';
            this.navigate(initialRoute, true);
        },
        
        navigate(path, replace = false) {
            if (replace) {
                window.history.replaceState(null, '', path);
            } else {
                window.history.pushState(null, '', path);
            }
            this.handleRoute();
        },
        
        handleRoute() {
            const path = window.location.pathname;
            
            // Check for CVE detail route pattern
            const cveDetailMatch = path.match(/^\/cves\/(.+)$/);
            if (cveDetailMatch && cveDetailMatch[1] !== 'list') {
                const cveId = decodeURIComponent(cveDetailMatch[1]);
                App.pages.detail.render(cveId);
                return;
            }
            
            // Handle exact list route
            if (path === '/cves/list') {
                App.pages.list.render();
                return;
            }
            
            // Redirect root to exact assessment route
            if (path === '/') {
                this.navigate('/cves/list', true);
                return;
            }
            
            // Default to list page for any other route
            this.navigate('/cves/list', true);
        }
    },
    
    // Page modules
    pages: {
        // CVE List Page
        list: {
            async render() {
                console.log('Rendering CVE list page...');
                
                // Update page title
                document.title = 'CVE List - NVD API Dashboard';
                
                // Show loading state
                Utils.showLoading('main-content', 'Loading CVE list...');
                
                try {
                    // Load CVE data
                    await this.loadCVEs();
                    
                    // Render the page
                    this.renderHTML();
                    
                    // Set up event listeners
                    this.setupEventListeners();
                    
                } catch (error) {
                    Utils.showError('main-content', 'Failed to load CVE list', error);
                }
            },
            
            async loadCVEs() {
                try {
                    // Get CVE list data
                    const response = await API.getCVEList({
                        page: App.state.currentPage,
                        size: App.state.pageSize,
                        sort: App.state.sortField,
                        order: App.state.sortOrder
                    });
                    
                    App.state.currentCVEList = response.items || [];
                    App.state.totalRecords = response.total || 0;
                    App.state.totalPages = Math.ceil(App.state.totalRecords / App.state.pageSize);
                    
                    console.log(`Loaded ${App.state.currentCVEList.length} CVEs (page ${App.state.currentPage}/${App.state.totalPages})`);
                    
                } catch (error) {
                    console.error('Failed to load CVEs:', error);
                    throw error;
                }
            },
            
            renderHTML() {
                const { currentCVEList, totalRecords, currentPage, pageSize, sortField, sortOrder, totalPages } = App.state;
                
                // Build pagination info
                const paginationInfo = Utils.buildPaginationInfo(currentPage, totalRecords, pageSize);
                
                const html = `
                    <div class="page-header">
                        <h1 class="page-title">NVD API Dashboard</h1>
                        <p class="page-subtitle">National Vulnerability Database API Interface</p>
                    </div>
                    
                    <div class="cve-list-container">
                        <!-- Search and Filter Panel -->
                        <div class="search-panel">
                            <h3 class="search-title">🔍 Search & Filter CVEs</h3>
                            <div class="search-grid">
                                <div class="search-group">
                                    <label for="search-cve-id">CVE ID</label>
                                    <input type="text" id="search-cve-id" placeholder="e.g., CVE-2023-12345" maxlength="20">
                                </div>
                                <div class="search-group">
                                    <label for="search-year">Year</label>
                                    <select id="search-year">
                                        <option value="">All Years</option>
                                        ${this.renderYearOptions()}
                                    </select>
                                </div>
                                <div class="search-group">
                                    <label for="search-min-score">Min CVSS Score</label>
                                    <select id="search-min-score">
                                        <option value="">Any</option>
                                        <option value="0">0.0</option>
                                        <option value="1">1.0</option>
                                        <option value="2">2.0</option>
                                        <option value="3">3.0</option>
                                        <option value="4">4.0</option>
                                        <option value="5">5.0</option>
                                        <option value="6">6.0</option>
                                        <option value="7">7.0</option>
                                        <option value="8">8.0</option>
                                        <option value="9">9.0</option>
                                    </select>
                                </div>
                                <div class="search-group">
                                    <label for="search-max-score">Max CVSS Score</label>
                                    <select id="search-max-score">
                                        <option value="">Any</option>
                                        <option value="1">1.0</option>
                                        <option value="2">2.0</option>
                                        <option value="3">3.0</option>
                                        <option value="4">4.0</option>
                                        <option value="5">5.0</option>
                                        <option value="6">6.0</option>
                                        <option value="7">7.0</option>
                                        <option value="8">8.0</option>
                                        <option value="9">9.0</option>
                                        <option value="10">10.0</option>
                                    </select>
                                </div>
                                <div class="search-group">
                                    <label for="search-modified-days">Modified in Last N Days</label>
                                    <select id="search-modified-days">
                                        <option value="">Any Time</option>
                                        <option value="1">1 Day</option>
                                        <option value="7">7 Days</option>
                                        <option value="30">30 Days</option>
                                        <option value="90">90 Days</option>
                                        <option value="365">1 Year</option>
                                    </select>
                                </div>
                                <div class="search-group">
                                    <label for="search-keyword">Keyword</label>
                                    <input type="text" id="search-keyword" placeholder="Search in descriptions">
                                </div>
                            </div>
                            <div class="search-actions">
                                <button class="search-btn" onclick="App.pages.list.performSearch()">🔍 Search</button>
                                <button class="clear-btn" onclick="App.pages.list.clearSearch()">🗑️ Clear</button>
                                <span class="search-status" id="search-status"></span>
                            </div>
                        </div>

                        <div class="list-controls">
                            <div class="control-group">
                                <div class="total-records">
                                    Total Records: <strong>${Utils.formatNumber(totalRecords)}</strong>
                                    <span class="page-info">
                                        Page ${currentPage} of ${totalPages}
                                    </span>
                                </div>
                                <div class="sort-info">
                                    Sort: <strong>${this.getSortDisplayName(sortField)}</strong> 
                                    ${sortOrder === 'desc' ? '↓' : '↑'}
                                </div>
                            </div>
                            <div class="results-per-page">
                                <label for="page-size-select">Results per page:</label>
                                <select id="page-size-select">
                                    <option value="10" ${pageSize === 10 ? 'selected' : ''}>10</option>
                                    <option value="50" ${pageSize === 50 ? 'selected' : ''}>50</option>
                                    <option value="100" ${pageSize === 100 ? 'selected' : ''}>100</option>
                                </select>
                            </div>
                        </div>
                        
                        <table class="cve-table">
                            <thead>
                                <tr>
                                    ${this.renderSortableHeader('cve_id', 'CVE ID')}
                                    <th>IDENTIFIER</th>
                                    ${this.renderSortableHeader('published', 'PUBLISHED DATE')}
                                    ${this.renderSortableHeader('last_modified', 'LAST MODIFIED DATE')}
                                    <th>STATUS</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${this.renderTableRows(currentCVEList)}
                            </tbody>
                        </table>
                        
                        ${this.renderEnhancedPagination()}
                    </div>
                `;
                
                document.getElementById('main-content').innerHTML = html;
            },
            
            renderYearOptions() {
                const currentYear = new Date().getFullYear();
                const startYear = 1999;
                let options = '';
                
                for (let year = currentYear; year >= startYear; year--) {
                    options += `<option value="${year}">${year}</option>`;
                }
                
                return options;
            },
            
            renderTableRows(cves) {
                if (!cves || cves.length === 0) {
                    return `
                        <tr>
                            <td colspan="5" class="text-center p-4">
                                No CVEs found matching your criteria.
                            </td>
                        </tr>
                    `;
                }
                
                return cves.map(cve => {
                    const status = Utils.formatStatus(cve.vuln_status);
                    
                    return `
                        <tr onclick="App.pages.list.navigateToCVE('${cve.cve_id}')" data-cve-id="${cve.cve_id}">
                            <td class="cve-id">${Utils.escapeHTML(cve.cve_id)}</td>
                            <td>${Utils.escapeHTML(cve.source_identifier || 'N/A')}</td>
                            <td>${Utils.formatDate(cve.published)}</td>
                            <td>${Utils.formatDate(cve.last_modified)}</td>
                            <td><span class="status-badge ${status.class}">${status.text}</span></td>
                        </tr>
                    `;
                }).join('');
            },
            
            setupEventListeners() {
                // Page size change handler
                const pageSizeSelect = document.getElementById('page-size-select');
                if (pageSizeSelect) {
                    pageSizeSelect.addEventListener('change', (e) => {
                        App.state.pageSize = parseInt(e.target.value);
                        App.state.currentPage = 1; // Reset to first page
                        this.render();
                    });
                }
            },
            
            async changePage(page) {
                App.state.currentPage = page;
                await this.render();
                
                // Scroll to top
                window.scrollTo({ top: 0, behavior: 'smooth' });
            },
            
            async performSearch() {
                const searchBtn = document.querySelector('.search-btn');
                const searchStatus = document.getElementById('search-status');
                
                try {
                    // Disable search button and show loading
                    searchBtn.disabled = true;
                    searchBtn.textContent = '🔄 Searching...';
                    searchStatus.textContent = 'Searching...';
                    searchStatus.className = 'search-status searching';
                    
                    // Get search values
                    const cveId = document.getElementById('search-cve-id').value.trim();
                    const year = document.getElementById('search-year').value;
                    const minScore = document.getElementById('search-min-score').value;
                    const maxScore = document.getElementById('search-max-score').value;
                    const modifiedDays = document.getElementById('search-modified-days').value;
                    const keyword = document.getElementById('search-keyword').value.trim();
                    
                    // Validate CVSS score range
                    if (minScore && maxScore && parseFloat(minScore) > parseFloat(maxScore)) {
                        throw new Error('Minimum score cannot be greater than maximum score');
                    }
                    
                    // If CVE ID is provided, search specifically for that CVE
                    if (cveId) {
                        if (!Utils.isValidCVEId(cveId)) {
                            throw new Error('Invalid CVE ID format. Use format: CVE-YYYY-NNNNN');
                        }
                        
                        try {
                            const cveData = await API.getCVEById(cveId.toUpperCase());
                            App.state.currentCVEList = [cveData];
                            App.state.totalRecords = 1;
                            App.state.totalPages = 1;
                            App.state.currentPage = 1;
                            
                            searchStatus.textContent = `Found CVE: ${cveId.toUpperCase()}`;
                            searchStatus.className = 'search-status success';
                        } catch (error) {
                            if (error.message.includes('404')) {
                                searchStatus.textContent = `CVE ${cveId.toUpperCase()} not found`;
                                searchStatus.className = 'search-status error';
                                App.state.currentCVEList = [];
                                App.state.totalRecords = 0;
                                App.state.totalPages = 0;
                            } else {
                                throw error;
                            }
                        }
                    } else {
                        // Build search parameters for list API
                        const searchParams = {
                            page: 1,
                            size: App.state.pageSize,
                            sort: App.state.sortField,
                            order: App.state.sortOrder
                        };
                        
                        if (year) searchParams.year = parseInt(year);
                        if (minScore) searchParams.min_score = parseFloat(minScore);
                        if (maxScore) searchParams.max_score = parseFloat(maxScore);
                        if (keyword) searchParams.keyword = keyword;
                        
                        // Handle modified days - convert to date
                        if (modifiedDays) {
                            const daysAgo = new Date();
                            daysAgo.setDate(daysAgo.getDate() - parseInt(modifiedDays));
                            searchParams.modified_since = daysAgo.toISOString();
                        }
                        
                        const response = await API.getCVEList(searchParams);
                        
                        App.state.currentCVEList = response.items || [];
                        App.state.totalRecords = response.total || 0;
                        App.state.totalPages = Math.ceil(App.state.totalRecords / App.state.pageSize);
                        App.state.currentPage = 1;
                        
                        searchStatus.textContent = `Found ${App.state.totalRecords} CVEs`;
                        searchStatus.className = 'search-status success';
                    }
                    
                    // Re-render the page with search results
                    this.renderHTML();
                    
                } catch (error) {
                    console.error('Search error:', error);
                    searchStatus.textContent = `Error: ${error.message}`;
                    searchStatus.className = 'search-status error';
                } finally {
                    // Re-enable search button
                    searchBtn.disabled = false;
                    searchBtn.textContent = '🔍 Search';
                }
            },
            
            async clearSearch() {
                // Clear all search inputs
                document.getElementById('search-cve-id').value = '';
                document.getElementById('search-year').value = '';
                document.getElementById('search-min-score').value = '';
                document.getElementById('search-max-score').value = '';
                document.getElementById('search-modified-days').value = '';
                document.getElementById('search-keyword').value = '';
                
                // Clear search status
                const searchStatus = document.getElementById('search-status');
                searchStatus.textContent = '';
                searchStatus.className = 'search-status';
                
                // Reset to original data view
                App.state.currentPage = 1;
                await this.loadCVEs();
                this.renderHTML();
            },
            
            navigateToCVE(cveId) {
                if (Utils.isValidCVEId(cveId)) {
                    App.router.navigate(`/cves/${encodeURIComponent(cveId)}`);
                } else {
                    console.error('Invalid CVE ID:', cveId);
                }
            },
            
            // Helper methods for enhanced UI
            renderSortableHeader(field, label) {
                const { sortField, sortOrder } = App.state;
                const isActive = sortField === field;
                const nextOrder = isActive && sortOrder === 'desc' ? 'asc' : 'desc';
                const arrow = isActive ? (sortOrder === 'desc' ? ' ↓' : ' ↑') : '';
                const className = isActive ? 'sortable-header active' : 'sortable-header';
                
                return `
                    <th class="${className}" onclick="App.pages.list.sortBy('${field}', '${nextOrder}')" title="Sort by ${label}">
                        ${label}${arrow}
                    </th>
                `;
            },
            
            getSortDisplayName(field) {
                const sortNames = {
                    'last_modified': 'Last Modified',
                    'published': 'Published Date',
                    'cve_id': 'CVE ID',
                    'cvss_v3_score': 'CVSS Score'
                };
                return sortNames[field] || field;
            },
            
            renderEnhancedPagination() {
                const { currentPage, totalPages, totalRecords, pageSize } = App.state;
                const startItem = (currentPage - 1) * pageSize + 1;
                const endItem = Math.min(currentPage * pageSize, totalRecords);
                
                if (totalPages <= 1) {
                    return `
                        <div class="pagination-container">
                            <div class="pagination-info">
                                Showing ${startItem} to ${endItem} of ${Utils.formatNumber(totalRecords)} results
                            </div>
                        </div>
                    `;
                }
                
                let html = '<div class="pagination-container">';
                
                // Previous button
                html += `<button class="pagination-button" ${currentPage === 1 ? 'disabled' : ''} 
                         onclick="App.pages.list.changePage(${currentPage - 1})">Previous</button>`;
                
                // Page numbers
                const startPage = Math.max(1, currentPage - 2);
                const endPage = Math.min(totalPages, currentPage + 2);
                
                if (startPage > 1) {
                    html += `<button class="pagination-button" onclick="App.pages.list.changePage(1)">1</button>`;
                    if (startPage > 2) {
                        html += '<span class="pagination-info">...</span>';
                    }
                }
                
                for (let i = startPage; i <= endPage; i++) {
                    const activeClass = i === currentPage ? 'active' : '';
                    html += `<button class="pagination-button ${activeClass}" 
                             onclick="App.pages.list.changePage(${i})">${i}</button>`;
                }
                
                if (endPage < totalPages) {
                    if (endPage < totalPages - 1) {
                        html += '<span class="pagination-info">...</span>';
                    }
                    html += `<button class="pagination-button" onclick="App.pages.list.changePage(${totalPages})">${totalPages}</button>`;
                }
                
                // Next button
                html += `<button class="pagination-button" ${currentPage === totalPages ? 'disabled' : ''} 
                         onclick="App.pages.list.changePage(${currentPage + 1})">Next</button>`;
                
                // Page info
                html += `
                    <div class="pagination-info">
                        Showing ${startItem} to ${endItem} of ${Utils.formatNumber(totalRecords)} results
                    </div>
                `;
                
                html += '</div>';
                return html;
            },
            
            async sortBy(field, order) {
                App.state.sortField = field;
                App.state.sortOrder = order;
                App.state.currentPage = 1; // Reset to first page when sorting
                
                console.log(`Sorting by ${field} ${order}`);
                await this.render();
            }
        },
        
        // CVE Detail Page
        detail: {
            async render(cveId) {
                console.log('Rendering CVE detail page for:', cveId);
                
                if (!cveId || !Utils.isValidCVEId(cveId)) {
                    Utils.showError('main-content', 'Invalid CVE ID provided');
                    return;
                }
                
                // Update page title
                document.title = `${cveId} - CVE Detail - NVD API Dashboard`;
                
                // Show loading state
                Utils.showLoading('main-content', 'Loading CVE details...');
                
                try {
                    // Load CVE data
                    const cveData = await API.getCVEById(cveId);
                    
                    // Render the page
                    this.renderHTML(cveData);
                    
                } catch (error) {
                    if (error.message.includes('404')) {
                        Utils.showError('main-content', `CVE ${cveId} not found`, new Error('The requested CVE does not exist in the database.'));
                    } else {
                        Utils.showError('main-content', 'Failed to load CVE details', error);
                    }
                }
            },
            
            renderHTML(cve) {
                const cvssV2 = Utils.formatCVSSScore(cve.cvss_v2_score);
                const cvssV3 = Utils.formatCVSSScore(cve.cvss_v3_score);
                
                const html = `
                    <a href="/cves/list" class="back-button" onclick="App.router.navigate('/cves/list'); return false;">
                        ← Back to CVE List
                    </a>
                    
                    <div class="cve-detail-container">
                        <div class="cve-header">
                            <h1>${Utils.escapeHTML(cve.cve_id)}</h1>
                            <div class="cve-meta">
                                <div class="cve-meta-item">
                                    <span class="cve-meta-label">Published</span>
                                    <span class="cve-meta-value">${Utils.formatDate(cve.published)}</span>
                                </div>
                                <div class="cve-meta-item">
                                    <span class="cve-meta-label">Last Modified</span>
                                    <span class="cve-meta-value">${Utils.formatDate(cve.last_modified)}</span>
                                </div>
                                <div class="cve-meta-item">
                                    <span class="cve-meta-label">Status</span>
                                    <span class="cve-meta-value">${Utils.escapeHTML(cve.vuln_status || 'Unknown')}</span>
                                </div>
                                <div class="cve-meta-item">
                                    <span class="cve-meta-label">Source</span>
                                    <span class="cve-meta-value">${Utils.escapeHTML(cve.source_identifier || 'N/A')}</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="cve-content">
                            ${this.renderDescriptionSection(cve)}
                            ${this.renderCVSSSection(cve, cvssV2, cvssV3)}
                            ${this.renderCVSSMetricsTable(cve)}
                            ${this.renderScoresSection(cve)}
                            ${this.renderCPESection(cve)}
                        </div>
                    </div>
                `;
                
                document.getElementById('main-content').innerHTML = html;
            },
            
            renderDescriptionSection(cve) {
                return `
                    <section class="cve-section">
                        <h2 class="section-title">Description</h2>
                        <div class="description-text">
                            ${Utils.escapeHTML(cve.description || 'No description available.')}
                        </div>
                    </section>
                `;
            },
            
            renderCVSSSection(cve, cvssV2, cvssV3) {
                const hasV2 = cve.cvss_v2_score !== null && cve.cvss_v2_score !== undefined;
                const hasV3 = cve.cvss_v3_score !== null && cve.cvss_v3_score !== undefined;
                
                if (!hasV2 && !hasV3) {
                    return `
                        <section class="cve-section">
                            <h2 class="section-title">CVSS Metrics</h2>
                            <p>No CVSS metrics available for this CVE.</p>
                        </section>
                    `;
                }
                
                return `
                    <section class="cve-section">
                        <h2 class="section-title">CVSS Metrics</h2>
                        <div class="cvss-container">
                            ${hasV3 ? `
                                <div class="cvss-score-box">
                                    <div class="cvss-score">${cvssV3.score}</div>
                                    <div class="cvss-severity">CVSS v3.x ${cvssV3.severity}</div>
                                </div>
                                ${cve.cvss_v3_vector ? `
                                    <div class="cvss-vector-box">
                                        <div class="cvss-vector-label">CVSS v3.x Vector:</div>
                                        <div class="cvss-vector-value">${Utils.escapeHTML(cve.cvss_v3_vector)}</div>
                                    </div>
                                ` : ''}
                            ` : ''}
                            
                            ${hasV2 ? `
                                <div class="cvss-score-box">
                                    <div class="cvss-score">${cvssV2.score}</div>
                                    <div class="cvss-severity">CVSS v2.0 ${cvssV2.severity}</div>
                                </div>
                                ${cve.cvss_v2_vector ? `
                                    <div class="cvss-vector-box">
                                        <div class="cvss-vector-label">CVSS v2.0 Vector:</div>
                                        <div class="cvss-vector-value">${Utils.escapeHTML(cve.cvss_v2_vector)}</div>
                                    </div>
                                ` : ''}
                            ` : ''}
                        </div>
                    </section>
                `;
            },
            
            renderCVSSMetricsTable(cve) {
                const hasV2 = cve.cvss_v2_vector && cve.cvss_v2_score;
                
                if (!hasV2) {
                    return `
                        <section class="cve-section">
                            <h2 class="section-title">CVSS Metrics Details</h2>
                            <p>No detailed CVSS v2 metrics available for this CVE.</p>
                        </section>
                    `;
                }
                
                // Parse CVSS v2 vector
                const cvssMetrics = Utils.parseCVSSv2Vector(cve.cvss_v2_vector);
                
                return `
                    <section class="cve-section">
                        <h2 class="section-title">CVSS V2 Metrics</h2>
                        <div class="cvss-summary">
                            <div class="cvss-summary-item">
                                <span class="cvss-label">Severity:</span>
                                <span class="cvss-value">${cve.cvss_v2_severity || 'N/A'}</span>
                            </div>
                            <div class="cvss-summary-item">
                                <span class="cvss-label">Score:</span>
                                <span class="cvss-value">${cve.cvss_v2_score || 'N/A'}</span>
                            </div>
                            <div class="cvss-summary-item">
                                <span class="cvss-label">Vector String:</span>
                                <span class="cvss-vector font-mono">${Utils.escapeHTML(cve.cvss_v2_vector || 'N/A')}</span>
                            </div>
                        </div>
                        
                        ${cvssMetrics ? `
                        <table class="data-table cvss-metrics-table">
                            <thead>
                                <tr>
                                    <th>Access Vector</th>
                                    <th>Access Complexity</th>
                                    <th>Authentication</th>
                                    <th>Confidentiality Impact</th>
                                    <th>Integrity Impact</th>
                                    <th>Availability Impact</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td class="cvss-metric-value">${cvssMetrics.accessVector}</td>
                                    <td class="cvss-metric-value">${cvssMetrics.accessComplexity}</td>
                                    <td class="cvss-metric-value">${cvssMetrics.authentication}</td>
                                    <td class="cvss-metric-value">${cvssMetrics.confidentialityImpact}</td>
                                    <td class="cvss-metric-value">${cvssMetrics.integrityImpact}</td>
                                    <td class="cvss-metric-value">${cvssMetrics.availabilityImpact}</td>
                                </tr>
                            </tbody>
                        </table>
                        ` : '<p>Unable to parse CVSS vector.</p>'}
                    </section>
                `;
            },
            
            renderScoresSection(cve) {
                const hasV2 = cve.cvss_v2_score;
                
                return `
                    <section class="cve-section">
                        <h2 class="section-title">Scores :</h2>
                        <div class="scores-container">
                            ${hasV2 ? `
                                <div class="score-item">
                                    <span class="score-label">CVSS v2.0 Base Score:</span>
                                    <span class="score-value">${cve.cvss_v2_score}</span>
                                </div>
                            ` : ''}
                            ${cve.cvss_v2_severity ? `
                                <div class="score-item">
                                    <span class="score-label">CVSS v2.0 Severity:</span>
                                    <span class="score-value">${cve.cvss_v2_severity}</span>
                                </div>
                            ` : ''}
                            ${cve.cvss_v3_score ? `
                                <div class="score-item">
                                    <span class="score-label">CVSS v3.x Base Score:</span>
                                    <span class="score-value">${cve.cvss_v3_score}</span>
                                </div>
                            ` : ''}
                            ${cve.cvss_v3_severity ? `
                                <div class="score-item">
                                    <span class="score-label">CVSS v3.x Severity:</span>
                                    <span class="score-value">${cve.cvss_v3_severity}</span>
                                </div>
                            ` : ''}
                            ${!hasV2 && !cve.cvss_v3_score ? '<p>No scoring information available.</p>' : ''}
                        </div>
                    </section>
                `;
            },
            
            renderCPESection(cve) {
                const configurations = cve.cpe_configurations;
                
                // Enhanced debug logging
                console.log(`🔍 CPE DEBUG for ${cve.cve_id}:`);
                console.log(`   - CPE configurations field exists: ${configurations !== undefined}`);
                console.log(`   - CPE configurations is array: ${Array.isArray(configurations)}`);
                console.log(`   - CPE configurations length: ${configurations ? configurations.length : 'null/undefined'}`);
                console.log(`   - Raw CPE configurations:`, configurations);
                if (configurations && configurations.length > 0) {
                    console.log(`   - First config:`, configurations[0]);
                    if (configurations[0].nodes && configurations[0].nodes[0]) {
                        console.log(`   - First node cpeMatch:`, configurations[0].nodes[0].cpeMatch);
                        console.log(`   - First node cpe_match:`, configurations[0].nodes[0].cpe_match);
                    }
                }
                
                if (!configurations || configurations.length === 0) {
                    return `
                        <section class="cve-section">
                            <h2 class="section-title">CPE Configurations</h2>
                            <p>No CPE configuration data available for this CVE.</p>
                        </section>
                    `;
                }
                
                // Extract CPE data from configurations
                let cpeRows = '';
                configurations.forEach(config => {
                    if (config.nodes && Array.isArray(config.nodes)) {
                        config.nodes.forEach(node => {
                            // Handle both camelCase (cpeMatch) and snake_case (cpe_match)
                            const cpeMatches = node.cpeMatch || node.cpe_match;
                            if (cpeMatches && Array.isArray(cpeMatches)) {
                                cpeMatches.forEach(cpe => {
                                    cpeRows += `
                                        <tr>
                                            <td class="font-mono text-sm">${Utils.escapeHTML(cpe.criteria || 'N/A')}</td>
                                            <td class="font-mono text-sm">${Utils.escapeHTML(cpe.matchCriteriaId || 'N/A')}</td>
                                            <td><span class="status-badge ${cpe.vulnerable ? 'status-analyzed' : 'status-rejected'}">${cpe.vulnerable ? 'Yes' : 'No'}</span></td>
                                        </tr>
                                    `;
                                });
                            }
                        });
                    }
                });
                
                if (!cpeRows) {
                    cpeRows = '<tr><td colspan="3" class="text-center">No CPE match criteria available.</td></tr>';
                }
                
                return `
                    <section class="cve-section">
                        <h2 class="section-title">CPE Configurations</h2>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Criteria</th>
                                    <th>Match Criteria ID</th>
                                    <th>Vulnerable</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${cpeRows}
                            </tbody>
                        </table>
                    </section>
                `;
            }
        }
    }
};

// Make changePage function globally accessible for pagination
window.changePage = function(page) {
    App.pages.list.changePage(page);
};

// Export for global use
window.App = App;
