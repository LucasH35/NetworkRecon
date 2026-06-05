/**
 * NetworkRecon - Vulnerabilities Module
 * Displays CVEs with severity, filtering, and details
 */

const Vulnerabilities = {
    currentSeverity: 'all',
    currentService: 'all',
    searchQuery: '',

    /**
     * Render the vulnerabilities list view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getListLoadingSkeleton();

        try {
            const [vulns, summary] = await Promise.all([
                api.getVulnerabilities({ limit: 200 }),
                api.getVulnerabilitySummary().catch(() => ({
                    total: 0,
                    by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    affected_hosts: 0,
                    top_cves: []
                }))
            ]);

            this.allVulns = vulns;
            app.innerHTML = this.getListHTML(vulns, summary);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Render CVE detail view
     */
    async renderDetail(cveId) {
        const app = document.getElementById('app');
        app.innerHTML = this.getDetailLoadingSkeleton();

        try {
            const cve = await api.getCVE(cveId);
            app.innerHTML = this.getDetailHTML(cve);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Get list loading skeleton
     */
    getListLoadingSkeleton() {
        return `
            <div class="animate-fade-in space-y-4">
                <div class="flex items-center justify-between mb-6">
                    <div class="loading-skeleton w-48 h-8"></div>
                    <div class="loading-skeleton w-64 h-10"></div>
                </div>
                <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
                    ${Array(5).fill('').map(() => `<div class="loading-skeleton h-20 rounded-xl"></div>`).join('')}
                </div>
                <div class="card">
                    <div class="card-body p-0">
                        ${Array(6).fill('').map(() => `
                            <div class="flex items-center gap-4 p-4 border-b border-surface-700 last:border-0">
                                <div class="loading-skeleton w-20 h-6 rounded-full"></div>
                                <div class="loading-skeleton w-32 h-5"></div>
                                <div class="flex-1"></div>
                                <div class="loading-skeleton w-16 h-5"></div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get list HTML
     */
    getListHTML(vulns, summary) {
        const filtered = this.filterVulns(vulns);
        const services = [...new Set(vulns.map(v => v.service).filter(Boolean))];

        return `
            <div class="animate-fade-in space-y-4">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <h2 class="text-xl font-bold text-white">Vulnérabilités (${summary.total || 0})</h2>
                </div>

                <!-- Summary Cards -->
                <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
                    <div class="stat-card cursor-pointer hover:border-red-500/50" onclick="Vulnerabilities.setSeverity('critical')">
                        <div class="flex items-center gap-2">
                            <div class="w-3 h-3 rounded-full bg-red-500"></div>
                            <span class="text-surface-400 text-sm">Critique</span>
                        </div>
                        <div class="stat-value text-white text-xl mt-2">${summary.by_severity?.critical || 0}</div>
                    </div>
                    <div class="stat-card cursor-pointer hover:border-orange-500/50" onclick="Vulnerabilities.setSeverity('high')">
                        <div class="flex items-center gap-2">
                            <div class="w-3 h-3 rounded-full bg-orange-500"></div>
                            <span class="text-surface-400 text-sm">Haute</span>
                        </div>
                        <div class="stat-value text-white text-xl mt-2">${summary.by_severity?.high || 0}</div>
                    </div>
                    <div class="stat-card cursor-pointer hover:border-yellow-500/50" onclick="Vulnerabilities.setSeverity('medium')">
                        <div class="flex items-center gap-2">
                            <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
                            <span class="text-surface-400 text-sm">Moyenne</span>
                        </div>
                        <div class="stat-value text-white text-xl mt-2">${summary.by_severity?.medium || 0}</div>
                    </div>
                    <div class="stat-card cursor-pointer hover:border-green-500/50" onclick="Vulnerabilities.setSeverity('low')">
                        <div class="flex items-center gap-2">
                            <div class="w-3 h-3 rounded-full bg-green-500"></div>
                            <span class="text-surface-400 text-sm">Basse</span>
                        </div>
                        <div class="stat-value text-white text-xl mt-2">${summary.by_severity?.low || 0}</div>
                    </div>
                    <div class="stat-card cursor-pointer hover:border-blue-500/50" onclick="Vulnerabilities.setSeverity('info')">
                        <div class="flex items-center gap-2">
                            <div class="w-3 h-3 rounded-full bg-blue-500"></div>
                            <span class="text-surface-400 text-sm">Info</span>
                        </div>
                        <div class="stat-value text-white text-xl mt-2">${summary.by_severity?.info || 0}</div>
                    </div>
                </div>

                <!-- Filters -->
                <div class="flex flex-wrap items-center gap-3">
                    <div class="relative flex-1 max-w-md">
                        <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                        <input type="text" placeholder="Rechercher CVE..." 
                            class="form-input pl-10 w-full"
                            oninput="Vulnerabilities.handleSearch(this.value)">
                    </div>
                    <select onchange="Vulnerabilities.setService(this.value)" class="form-select w-auto">
                        <option value="all">Tous les services</option>
                        ${services.map(s => `<option value="${s}">${s}</option>`).join('')}
                    </select>
                    <button onclick="Vulnerabilities.setSeverity('all')" class="filter-chip ${this.currentSeverity === 'all' ? 'active' : ''}">Toutes</button>
                </div>

                <!-- Vulnerabilities List -->
                <div class="card">
                    <div class="card-body p-0">
                        ${filtered.length ? `
                            <div class="divide-y divide-surface-700" id="vulns-list">
                                ${filtered.map(v => this.getVulnRow(v)).join('')}
                            </div>
                        ` : `
                            <div class="empty-state">
                                <svg class="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                </svg>
                                <h3>Aucune vulnérabilité trouvée</h3>
                                <p>Modifiez vos filtres ou lancez un scan de vulnérabilités.</p>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get a single vulnerability row
     */
    getVulnRow(vuln) {
        const cve = vuln.cve || {};

        return `
            <a href="#vulnerabilities/${cve.cve_id || ''}" class="flex items-center gap-4 p-4 hover:bg-surface-700/50 transition-colors">
                <span class="severity-badge severity-${cve.severity || 'info'}">${cve.severity || 'info'}</span>
                <div class="flex-1 min-w-0">
                    <div class="font-mono text-white font-medium">${cve.cve_id || 'N/A'}</div>
                    <div class="text-sm text-surface-400 truncate">${vuln.service || ''} ${vuln.host_ip ? `• ${vuln.host_ip}` : ''}</div>
                </div>
                <div class="text-right flex-shrink-0">
                    <div class="text-sm font-medium text-white">CVSS ${cve.cvss_score || '-'}</div>
                    ${cve.affected_products?.length ? `
                        <div class="text-xs text-surface-400">${cve.affected_products.length} produit(s)</div>
                    ` : ''}
                </div>
                <svg class="w-4 h-4 text-surface-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                </svg>
            </a>
        `;
    },

    /**
     * Get detail loading skeleton
     */
    getDetailLoadingSkeleton() {
        return `
            <div class="animate-fade-in space-y-6">
                <div class="flex items-center gap-4">
                    <div class="loading-skeleton w-10 h-10 rounded-lg"></div>
                    <div>
                        <div class="loading-skeleton w-48 h-7 mb-2"></div>
                        <div class="loading-skeleton w-32 h-4"></div>
                    </div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    ${Array(3).fill('').map(() => `<div class="loading-skeleton h-24 rounded-xl"></div>`).join('')}
                </div>
                <div class="loading-skeleton w-full h-48 rounded-xl"></div>
            </div>
        `;
    },

    /**
     * Get detail HTML
     */
    getDetailHTML(cve) {
        const cvssColor = this.getCVSSColor(cve.cvss_score);

        return `
            <div class="animate-fade-in space-y-6">
                <!-- Header -->
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-4">
                        <a href="#vulnerabilities" class="p-2 rounded-lg hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                            </svg>
                        </a>
                        <div>
                            <h2 class="text-xl font-bold text-white font-mono">${cve.cve_id}</h2>
                            <span class="severity-badge severity-${cve.severity}">${cve.severity}</span>
                        </div>
                    </div>
                </div>

                <!-- Score Card -->
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center gap-6">
                            <div class="text-center">
                                <div class="text-4xl font-bold ${cvssColor}">${cve.cvss_score || '-'}</div>
                                <div class="text-sm text-surface-400 mt-1">Score CVSS</div>
                            </div>
                            <div class="flex-1">
                                <div class="text-sm text-surface-400 mb-2">Niveau de sévérité</div>
                                <div class="progress-bar h-3">
                                    <div class="progress-bar-fill" style="width: ${(cve.cvss_score || 0) * 10}%; background: ${this.getCVSSBarColor(cve.cvss_score)}"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Description -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="font-semibold text-white">Description</h3>
                    </div>
                    <div class="card-body">
                        <p class="text-surface-300 leading-relaxed">${cve.description || 'Aucune description disponible.'}</p>
                    </div>
                </div>

                <!-- Affected Products -->
                ${cve.affected_products?.length ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Produits affectés</h3>
                        </div>
                        <div class="card-body">
                            <div class="flex flex-wrap gap-2">
                                ${cve.affected_products.map(p => `
                                    <span class="px-3 py-1.5 bg-surface-700 border border-surface-600 rounded-lg text-sm text-white">${this.escapeHtml(p)}</span>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                ` : ''}

                <!-- Remediation -->
                ${cve.remediation ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Remédiation</h3>
                        </div>
                        <div class="card-body">
                            <div class="flex items-start gap-3 p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                                <svg class="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                </svg>
                                <p class="text-surface-300">${this.escapeHtml(cve.remediation)}</p>
                            </div>
                        </div>
                    </div>
                ` : ''}

                <!-- External Links -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="font-semibold text-white">Liens externes</h3>
                    </div>
                    <div class="card-body">
                        <div class="flex flex-wrap gap-3">
                            <a href="https://nvd.nist.gov/vuln/detail/${cve.cve_id}" target="_blank" 
                                class="flex items-center gap-2 px-4 py-2 bg-surface-700 hover:bg-surface-600 rounded-lg text-sm text-white transition-colors">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                                </svg>
                                NVD
                            </a>
                            <a href="https://www.cvedetails.com/cve/${cve.cve_id}/" target="_blank" 
                                class="flex items-center gap-2 px-4 py-2 bg-surface-700 hover:bg-surface-600 rounded-lg text-sm text-white transition-colors">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                                </svg>
                                CVE Details
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Filter vulnerabilities
     */
    filterVulns(vulns) {
        let filtered = [...vulns];

        if (this.currentSeverity !== 'all') {
            filtered = filtered.filter(v => v.cve?.severity === this.currentSeverity);
        }

        if (this.currentService !== 'all') {
            filtered = filtered.filter(v => v.service === this.currentService);
        }

        if (this.searchQuery) {
            const query = this.searchQuery.toLowerCase();
            filtered = filtered.filter(v =>
                v.cve?.cve_id?.toLowerCase().includes(query) ||
                v.cve?.description?.toLowerCase().includes(query) ||
                v.host_ip?.toLowerCase().includes(query)
            );
        }

        return filtered;
    },

    /**
     * Handle search
     */
    handleSearch(query) {
        this.searchQuery = query;
        this.updateList();
    },

    /**
     * Set severity filter
     */
    setSeverity(severity) {
        this.currentSeverity = severity;
        this.updateList();
    },

    /**
     * Set service filter
     */
    setService(service) {
        this.currentService = service;
        this.updateList();
    },

    /**
     * Update the vulnerability list
     */
    updateList() {
        const list = document.getElementById('vulns-list');
        if (list && this.allVulns) {
            const filtered = this.filterVulns(this.allVulns);
            list.innerHTML = filtered.map(v => this.getVulnRow(v)).join('');

            if (!filtered.length) {
                list.innerHTML = `
                    <div class="empty-state">
                        <p>Aucune vulnérabilité ne correspond aux filtres</p>
                    </div>
                `;
            }
        }
    },

    /**
     * Get CVSS color class
     */
    getCVSSColor(score) {
        if (score >= 9) return 'text-red-500';
        if (score >= 7) return 'text-orange-500';
        if (score >= 4) return 'text-yellow-500';
        return 'text-green-500';
    },

    /**
     * Get CVSS bar color
     */
    getCVSSBarColor(score) {
        if (score >= 9) return '#dc2626';
        if (score >= 7) return '#f97316';
        if (score >= 4) return '#eab308';
        return '#22c55e';
    },

    /**
     * Get error HTML
     */
    getErrorHTML(error) {
        return `
            <div class="animate-fade-in flex flex-col items-center justify-center h-96">
                <svg class="w-16 h-16 text-red-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
                <h3 class="text-lg font-semibold text-white mb-2">Erreur de chargement</h3>
                <p class="text-surface-400 mb-4">${this.escapeHtml(error.message)}</p>
                <button onclick="Vulnerabilities.render()" class="btn btn-primary">Réessayer</button>
            </div>
        `;
    },

    /**
     * Escape HTML
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};
