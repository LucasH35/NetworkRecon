/**
 * NetworkRecon - Hosts Module
 * Displays discovered hosts with details, ports, and vulnerabilities
 */

const Hosts = {
    currentFilter: 'all',
    searchQuery: '',

    /**
     * Render the hosts list view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getListLoadingSkeleton();

        try {
            const hosts = await api.getHosts({ limit: 500 });
            app.innerHTML = this.getListHTML(hosts);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Render host detail view
     */
    async renderDetail(ip) {
        const app = document.getElementById('app');
        app.innerHTML = this.getDetailLoadingSkeleton();

        try {
            const [host, ports, vulns, mitreMappings] = await Promise.all([
                api.getHost(ip),
                api.getHostPorts(ip).catch(() => []),
                api.getHostVulnerabilities(ip).catch(() => []),
                api.getHostMitreMappings(ip).catch(() => [])
            ]);

            app.innerHTML = this.getDetailHTML(host, ports, vulns, mitreMappings);
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
                <div class="card">
                    <div class="card-body p-0">
                        <div class="p-4 border-b border-surface-700">
                            <div class="loading-skeleton w-full h-10"></div>
                        </div>
                        ${Array(8).fill('').map(() => `
                            <div class="flex items-center gap-4 p-4 border-b border-surface-700 last:border-0">
                                <div class="loading-skeleton w-3 h-3 rounded-full"></div>
                                <div class="loading-skeleton w-32 h-5"></div>
                                <div class="flex-1"></div>
                                <div class="loading-skeleton w-24 h-5"></div>
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
    getListHTML(hosts) {
        const filteredHosts = this.filterHosts(hosts);

        return `
            <div class="animate-fade-in space-y-4">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <h2 class="text-xl font-bold text-white">Hôtes découverts (${hosts.length})</h2>
                    <div class="flex items-center gap-3">
                        <div class="relative">
                            <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                            </svg>
                            <input type="text" id="host-search" placeholder="Rechercher par IP, hostname..." 
                                class="form-input pl-10 w-64"
                                oninput="Hosts.handleSearch(this.value)">
                        </div>
                        <div class="flex items-center gap-1 bg-surface-800 rounded-lg p-1">
                            <button onclick="Hosts.setFilter('all')" class="filter-chip ${this.currentFilter === 'all' ? 'active' : ''}">Tous</button>
                            <button onclick="Hosts.setFilter('up')" class="filter-chip ${this.currentFilter === 'up' ? 'active' : ''}">Actifs</button>
                            <button onclick="Hosts.setFilter('down')" class="filter-chip ${this.currentFilter === 'down' ? 'active' : ''}">Inactifs</button>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body p-0">
                        ${filteredHosts.length ? `
                            <div class="overflow-x-auto">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Statut</th>
                                            <th>Adresse IP</th>
                                            <th>Hostname</th>
                                            <th>Système</th>
                                            <th>Ports</th>
                                            <th>Dernière activité</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody id="hosts-table-body">
                                        ${filteredHosts.map(h => this.getHostRow(h)).join('')}
                                    </tbody>
                                </table>
                            </div>
                        ` : `
                            <div class="empty-state">
                                <svg class="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
                                </svg>
                                <h3>Aucun hôte trouvé</h3>
                                <p>Modifiez vos filtres ou lancez un nouveau scan.</p>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get a single host row
     */
    getHostRow(host) {
        const lastSeen = host.last_seen ? new Date(host.last_seen).toLocaleString('fr-FR') : '-';
        const portsCount = host.ports?.length || 0;

        return `
            <tr class="hover:bg-surface-700/50 cursor-pointer" onclick="Hosts.renderDetail('${host.ip_address}')">
                <td>
                    <span class="status-dot ${host.status}"></span>
                </td>
                <td>
                    <span class="font-mono text-white font-medium">${host.ip_address}</span>
                </td>
                <td>
                    <span class="text-surface-300">${host.hostname ? this.escapeHtml(host.hostname) : '-'}</span>
                </td>
                <td>
                    <span class="text-surface-400 text-sm">${host.os_detection ? this.escapeHtml(host.os_detection) : '-'}</span>
                </td>
                <td>
                    <span class="px-2 py-1 bg-surface-700 rounded text-xs font-medium">${portsCount}</span>
                </td>
                <td>
                    <span class="text-surface-400 text-sm">${lastSeen}</span>
                </td>
                <td>
                    <svg class="w-4 h-4 text-surface-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                    </svg>
                </td>
            </tr>
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
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    ${Array(4).fill('').map(() => `<div class="loading-skeleton h-24 rounded-xl"></div>`).join('')}
                </div>
                <div class="loading-skeleton w-full h-64 rounded-xl"></div>
            </div>
        `;
    },

    /**
     * Get detail HTML
     */
    getDetailHTML(host, ports, vulns, mitreMappings) {
        const lastSeen = host.last_seen ? new Date(host.last_seen).toLocaleString('fr-FR') : '-';
        const firstSeen = host.first_seen ? new Date(host.first_seen).toLocaleString('fr-FR') : '-';

        return `
            <div class="animate-fade-in space-y-6">
                <!-- Header -->
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-4">
                        <a href="#hosts" class="p-2 rounded-lg hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                            </svg>
                        </a>
                        <div>
                            <h2 class="text-xl font-bold text-white font-mono">${host.ip_address}</h2>
                            <div class="text-sm text-surface-400">${host.hostname ? this.escapeHtml(host.hostname) : 'Pas de hostname'}</div>
                        </div>
                    </div>
                    <span class="status-badge status-${host.status === 'up' ? 'completed' : 'failed'}">
                        <span class="status-dot ${host.status}"></span>
                        ${host.status === 'up' ? 'Actif' : 'Inactif'}
                    </span>
                </div>

                <!-- Info Cards -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div class="stat-card">
                        <div class="stat-label">Adresse MAC</div>
                        <div class="font-mono text-white text-sm mt-1">${host.mac_address || '-'}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Système</div>
                        <div class="text-white text-sm mt-1">${host.os_detection ? this.escapeHtml(host.os_detection) : '-'}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Ports ouverts</div>
                        <div class="stat-value text-white text-xl">${ports.length}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Vulnérabilités</div>
                        <div class="stat-value text-white text-xl">${vulns.length}</div>
                    </div>
                </div>

                <!-- Tabs -->
                <div class="flex items-center gap-1 bg-surface-800 rounded-lg p-1 w-fit">
                    <button onclick="Hosts.showTab('ports')" class="host-tab px-4 py-2 rounded-md text-sm font-medium bg-surface-700 text-white" data-tab="ports">Ports & Services</button>
                    <button onclick="Hosts.showTab('vulns')" class="host-tab px-4 py-2 rounded-md text-sm font-medium text-surface-400 hover:text-white" data-tab="vulns">Vulnérabilités (${vulns.length})</button>
                    <button onclick="Hosts.showTab('mitre')" class="host-tab px-4 py-2 rounded-md text-sm font-medium text-surface-400 hover:text-white" data-tab="mitre">MITRE (${mitreMappings.length})</button>
                </div>

                <!-- Ports Tab -->
                <div id="tab-ports" class="host-tab-content">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Ports & Services</h3>
                        </div>
                        <div class="card-body p-0">
                            ${ports.length ? `
                                <div class="overflow-x-auto">
                                    <table class="data-table">
                                        <thead>
                                            <tr>
                                                <th>Port</th>
                                                <th>Protocole</th>
                                                <th>État</th>
                                                <th>Service</th>
                                                <th>Version</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${ports.map(p => `
                                                <tr>
                                                    <td><span class="font-mono text-white font-medium">${p.number}</span></td>
                                                    <td><span class="text-surface-300 uppercase">${p.protocol}</span></td>
                                                    <td><span class="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">${p.state}</span></td>
                                                    <td><span class="text-white">${p.service ? this.escapeHtml(p.service) : '-'}</span></td>
                                                    <td><span class="text-surface-400 text-sm">${p.version ? this.escapeHtml(p.version) : '-'}</span></td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            ` : `
                                <div class="empty-state">
                                    <p>Aucun port détecté</p>
                                </div>
                            `}
                        </div>
                    </div>
                </div>

                <!-- Vulns Tab -->
                <div id="tab-vulns" class="host-tab-content hidden">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Vulnérabilités</h3>
                        </div>
                        <div class="card-body p-0">
                            ${vulns.length ? `
                                <div class="divide-y divide-surface-700">
                                    ${vulns.map(v => `
                                        <a href="#vulnerabilities/${v.cve?.cve_id || ''}" class="flex items-center gap-4 p-4 hover:bg-surface-700/50 transition-colors">
                                            <span class="severity-badge severity-${v.cve?.severity || 'info'}">${v.cve?.severity || 'info'}</span>
                                            <div class="flex-1">
                                                <div class="font-mono text-white font-medium">${v.cve?.cve_id || 'N/A'}</div>
                                                <div class="text-sm text-surface-400">${v.service || ''} ${v.port ? `(port ${v.port})` : ''}</div>
                                            </div>
                                            <div class="text-right">
                                                <div class="text-sm font-medium text-white">CVSS ${v.cve?.cvss_score || '-'}</div>
                                            </div>
                                        </a>
                                    `).join('')}
                                </div>
                            ` : `
                                <div class="empty-state">
                                    <p>Aucune vulnérabilité détectée</p>
                                </div>
                            `}
                        </div>
                    </div>
                </div>

                <!-- MITRE Tab -->
                <div id="tab-mitre" class="host-tab-content hidden">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Mappings MITRE ATT&CK</h3>
                        </div>
                        <div class="card-body p-0">
                            ${mitreMappings.length ? `
                                <div class="divide-y divide-surface-700">
                                    ${mitreMappings.map(m => `
                                        <div class="p-4">
                                            <div class="flex items-center gap-3 mb-2">
                                                <span class="px-2 py-1 bg-primary-500/15 text-primary-400 rounded text-xs font-mono font-medium">${m.technique_id}</span>
                                                <span class="text-white font-medium">${this.escapeHtml(m.technique_name)}</span>
                                            </div>
                                            <div class="text-sm text-surface-400 mb-2">Tactique: ${this.escapeHtml(m.tactic)}</div>
                                            <div class="text-sm text-surface-300">${this.escapeHtml(m.description || '')}</div>
                                            ${m.url ? `
                                                <a href="${m.url}" target="_blank" class="text-primary-400 hover:text-primary-300 text-xs mt-2 inline-flex items-center gap-1">
                                                    Voir sur MITRE ATT&CK
                                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                                                    </svg>
                                                </a>
                                            ` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            ` : `
                                <div class="empty-state">
                                    <p>Aucun mapping MITRE disponible</p>
                                </div>
                            `}
                        </div>
                    </div>
                </div>

                <!-- Timeline -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="font-semibold text-white">Informations</h3>
                    </div>
                    <div class="card-body">
                        <div class="grid grid-cols-2 gap-4 text-sm">
                            <div>
                                <span class="text-surface-400">Première détection:</span>
                                <div class="text-white mt-1">${firstSeen}</div>
                            </div>
                            <div>
                                <span class="text-surface-400">Dernière activité:</span>
                                <div class="text-white mt-1">${lastSeen}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Filter hosts
     */
    filterHosts(hosts) {
        let filtered = [...hosts];

        // Status filter
        if (this.currentFilter !== 'all') {
            filtered = filtered.filter(h => h.status === this.currentFilter);
        }

        // Search filter
        if (this.searchQuery) {
            const query = this.searchQuery.toLowerCase();
            filtered = filtered.filter(h =>
                h.ip_address?.toLowerCase().includes(query) ||
                h.hostname?.toLowerCase().includes(query) ||
                h.mac_address?.toLowerCase().includes(query)
            );
        }

        return filtered;
    },

    /**
     * Handle search input
     */
    async handleSearch(query) {
        this.searchQuery = query;
        const hosts = await api.getHosts({ limit: 500 });
        const tbody = document.getElementById('hosts-table-body');
        if (tbody) {
            const filtered = this.filterHosts(hosts);
            tbody.innerHTML = filtered.map(h => this.getHostRow(h)).join('');
        }
    },

    /**
     * Set status filter
     */
    async setFilter(filter) {
        this.currentFilter = filter;
        const hosts = await api.getHosts({ limit: 500 });
        const tbody = document.getElementById('hosts-table-body');
        if (tbody) {
            const filtered = this.filterHosts(hosts);
            tbody.innerHTML = filtered.map(h => this.getHostRow(h)).join('');
        }

        // Update filter buttons
        document.querySelectorAll('.filter-chip').forEach(btn => {
            btn.classList.remove('active');
        });
        event.target.classList.add('active');
    },

    /**
     * Show a tab
     */
    showTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.host-tab-content').forEach(tab => {
            tab.classList.add('hidden');
        });

        // Show selected tab
        const tab = document.getElementById(`tab-${tabName}`);
        if (tab) {
            tab.classList.remove('hidden');
        }

        // Update tab buttons
        document.querySelectorAll('.host-tab').forEach(btn => {
            btn.classList.remove('bg-surface-700', 'text-white');
            btn.classList.add('text-surface-400');
        });

        const activeBtn = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeBtn) {
            activeBtn.classList.add('bg-surface-700', 'text-white');
            activeBtn.classList.remove('text-surface-400');
        }
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
                <button onclick="Hosts.render()" class="btn btn-primary">Réessayer</button>
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
