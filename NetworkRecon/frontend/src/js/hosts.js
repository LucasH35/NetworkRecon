/**
 * NetworkRecon - Hosts Module
 * Displays discovered hosts with details, ports, and vulnerabilities
 */

const Hosts = {
    currentFilter: 'all',
    searchQuery: '',
    currentSort: 'ip_address',
    sortDirection: 'asc',

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
                                            <th class="cursor-pointer select-none hover:text-white" onclick="Hosts.sort('status')">
                                                Statut ${this.getSortIcon('status')}
                                            </th>
                                            <th class="cursor-pointer select-none hover:text-white" onclick="Hosts.sort('ip_address')">
                                                Adresse IP ${this.getSortIcon('ip_address')}
                                            </th>
                                            <th class="cursor-pointer select-none hover:text-white" onclick="Hosts.sort('hostname')">
                                                Hostname ${this.getSortIcon('hostname')}
                                            </th>
                                            <th class="cursor-pointer select-none hover:text-white" onclick="Hosts.sort('os_detection')">
                                                Système ${this.getSortIcon('os_detection')}
                                            </th>
                                            <th class="cursor-pointer select-none hover:text-white" onclick="Hosts.sort('ports')">
                                                Ports ${this.getSortIcon('ports')}
                                            </th>
                                            <th class="cursor-pointer select-none hover:text-white" onclick="Hosts.sort('last_seen')">
                                                Dernière activité ${this.getSortIcon('last_seen')}
                                            </th>
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

        // Grouper les mappings MITRE par tactique
        const tactics = {};
        mitreMappings.forEach(m => {
            const tac = m.tactic || 'Unknown';
            if (!tactics[tac]) tactics[tac] = [];
            tactics[tac].push(m);
        });

        return `
            <div class="animate-fade-in space-y-6">
                <!-- Back button -->
                <div class="flex items-center gap-3">
                    <a href="#hosts" onclick="event.preventDefault(); Router.navigate('hosts');" class="p-2 rounded-lg hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                        </svg>
                    </a>
                    <span class="text-surface-400 text-sm">Retour aux hôtes</span>
                </div>

                <!-- Banner hôte -->
                <div class="card border border-primary-500/30 bg-primary-500/5">
                    <div class="card-body">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-4">
                                <div class="w-12 h-12 rounded-xl bg-surface-700 flex items-center justify-center">
                                    <svg class="w-6 h-6 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/>
                                    </svg>
                                </div>
                                <div>
                                    <h2 class="text-2xl font-bold text-white font-mono">${host.ip_address}</h2>
                                    <div class="text-surface-400">${host.os_detection ? this.escapeHtml(host.os_detection) : 'Système non détecté'}</div>
                                </div>
                            </div>
                            <div class="flex items-center gap-3">
                                <span class="status-badge status-${host.status === 'up' ? 'completed' : 'failed'}">
                                    ${host.status === 'up' ? 'Actif' : 'Inactif'}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Tabs -->
                <div class="flex items-center gap-1 bg-surface-800 rounded-lg p-1 w-fit">
                    <button onclick="Hosts.showTab('vulns')" class="host-tab px-4 py-2 rounded-md text-sm font-medium ${vulns.length > 0 ? 'bg-red-500/15 text-red-400' : 'text-surface-400 hover:text-white'}" data-tab="vulns">
                        Vulnérabilités (${vulns.length})
                    </button>
                    <button onclick="Hosts.showTab('services')" class="host-tab px-4 py-2 rounded-md text-sm font-medium bg-surface-700 text-white" data-tab="services">
                        Services (${ports.length})
                    </button>
                    <button onclick="Hosts.showTab('mitre')" class="host-tab px-4 py-2 rounded-md text-sm font-medium text-surface-400 hover:text-white" data-tab="mitre">
                        MITRE ATT&CK (${mitreMappings.length})
                    </button>
                </div>

                <!-- Vulns Tab -->
                <div id="tab-vulns" class="host-tab-content ${vulns.length > 0 ? '' : 'hidden'}">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Vulnérabilités associées</h3>
                        </div>
                        <div class="card-body p-0">
                            ${vulns.length ? `
                                <div class="divide-y divide-surface-700">
                                    ${vulns.map(v => `
                                        <div class="flex items-center gap-4 p-4 hover:bg-surface-700/50 transition-colors">
                                            <span class="severity-badge severity-${v.cve?.severity || 'info'}">${v.cve?.severity || 'info'}</span>
                                            <div class="flex-1">
                                                <div class="font-mono text-white font-medium">${v.cve?.cve_id || 'N/A'}</div>
                                                <div class="text-sm text-surface-400">${v.service || ''} ${v.port ? `(port ${v.port})` : ''}</div>
                                            </div>
                                            <div class="text-right">
                                                <div class="text-sm font-medium text-white">CVSS ${v.cve?.cvss_score || '-'}</div>
                                            </div>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : `
                                <div class="empty-state">
                                    <svg class="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                    </svg>
                                    <h3>Aucune vulnérabilité détectée</h3>
                                    <p>Cet hôte semble sécurisé.</p>
                                </div>
                            `}
                        </div>
                    </div>
                </div>

                <!-- Services Tab -->
                <div id="tab-services" class="host-tab-content hidden">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Services découverts</h3>
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
                                                <th>Action</th>
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
                                                    <td>
                                                        ${Hosts.canAttackService(p.service) ? `
                                                            <button onclick="Hosts.attackService('${host.ip_address}', '${p.service || ''}', ${p.number})" class="px-3 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 hover:text-red-300 transition-colors text-xs font-medium flex items-center gap-1">
                                                                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                                                                </svg>
                                                                Attaquer
                                                            </button>
                                                        ` : ''}
                                                    </td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            ` : `
                                <div class="empty-state">
                                    <p>Aucun service détecté</p>
                                </div>
                            `}
                        </div>
                    </div>
                </div>

                <!-- MITRE Tab -->
                <div id="tab-mitre" class="host-tab-content hidden">
                    ${mitreMappings.length ? `
                        <div class="space-y-4">
                            <!-- Cyber Kill Chain -->
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="font-semibold text-white">Cyber Kill Chain</h3>
                                </div>
                                <div class="card-body">
                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                                        ${Object.entries(tactics).map(([tactic, techniques]) => `
                                            <div class="bg-surface-800 rounded-lg p-3 border border-surface-600">
                                                <div class="text-xs font-bold text-primary-400 uppercase tracking-wider mb-2">${tactic}</div>
                                                ${techniques.map(t => `
                                                    <div class="text-sm text-white mb-1 flex items-center gap-2">
                                                        <span class="w-1.5 h-1.5 rounded-full bg-primary-500 shrink-0"></span>
                                                        <span class="font-mono text-xs text-surface-300">${t.technique_id}</span>
                                                        <span class="truncate">${this.escapeHtml(t.technique_name)}</span>
                                                    </div>
                                                `).join('')}
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            </div>

                            <!-- Techniques détaillées -->
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="font-semibold text-white">Techniques détaillées</h3>
                                </div>
                                <div class="card-body p-0">
                                    <div class="divide-y divide-surface-700">
                                        ${mitreMappings.map(m => `
                                            <div class="p-4">
                                                <div class="flex items-center gap-3 mb-2">
                                                    <span class="px-2 py-1 bg-primary-500/15 text-primary-400 rounded text-xs font-mono font-medium">${m.technique_id}</span>
                                                    <span class="text-white font-medium">${this.escapeHtml(m.technique_name)}</span>
                                                </div>
                                                <div class="text-sm text-surface-400 mb-2">Tactique: ${this.escapeHtml(m.tactic)}</div>
                                                <div class="text-sm text-surface-300">${this.escapeHtml(m.description || '')}</div>
                                                <div class="flex items-center gap-3 mt-2">
                                                    ${m.url ? `
                                                        <a href="${m.url}" target="_blank" class="text-primary-400 hover:text-primary-300 text-xs inline-flex items-center gap-1">
                                                            Voir sur MITRE
                                                            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                                                            </svg>
                                                        </a>
                                                    ` : ''}
                                                </div>
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ` : `
                        <div class="card">
                            <div class="card-body">
                                <div class="empty-state">
                                    <svg class="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                                    </svg>
                                    <h3>Aucun mapping MITRE disponible</h3>
                                    <p>Lancez un scan de vulnérabilités pour générer les mappings.</p>
                                </div>
                            </div>
                        </div>
                    `}
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

        // Sort
        filtered.sort((a, b) => {
            let valA, valB;
            switch (this.currentSort) {
                case 'ip_address':
                    valA = this.ipToNumber(a.ip_address);
                    valB = this.ipToNumber(b.ip_address);
                    break;
                case 'hostname':
                    valA = (a.hostname || '').toLowerCase();
                    valB = (b.hostname || '').toLowerCase();
                    break;
                case 'os_detection':
                    valA = (a.os_detection || '').toLowerCase();
                    valB = (b.os_detection || '').toLowerCase();
                    break;
                case 'ports':
                    valA = a.ports?.length || 0;
                    valB = b.ports?.length || 0;
                    break;
                case 'last_seen':
                    valA = a.last_seen ? new Date(a.last_seen).getTime() : 0;
                    valB = b.last_seen ? new Date(b.last_seen).getTime() : 0;
                    break;
                case 'status':
                    valA = a.status || '';
                    valB = b.status || '';
                    break;
                default:
                    valA = a.ip_address || '';
                    valB = b.ip_address || '';
            }
            if (valA < valB) return this.sortDirection === 'asc' ? -1 : 1;
            if (valA > valB) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });

        return filtered;
    },

    /**
     * Convert IP address to number for proper numeric sorting
     */
    ipToNumber(ip) {
        if (!ip) return 0;
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
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
     * Sort hosts by field
     */
    async sort(field) {
        if (this.currentSort === field) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.currentSort = field;
            this.sortDirection = 'asc';
        }
        const hosts = await api.getHosts({ limit: 500 });
        const tbody = document.getElementById('hosts-table-body');
        if (tbody) {
            const filtered = this.filterHosts(hosts);
            tbody.innerHTML = filtered.map(h => this.getHostRow(h)).join('');
        }
    },

    /**
     * Get sort icon for column header
     */
    getSortIcon(field) {
        if (this.currentSort !== field) {
            return '<svg class="w-3 h-3 inline-block ml-1 text-surface-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"/></svg>';
        }
        const color = 'text-primary-400';
        if (this.sortDirection === 'asc') {
            return `<svg class="w-3 h-3 inline-block ml-1 ${color}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/></svg>`;
        }
        return `<svg class="w-3 h-3 inline-block ml-1 ${color}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>`;
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
     * Check if a service can be attacked
     */
    canAttackService(service) {
        if (!service) return false;
        const attackable = ['ssh', 'ftp', 'http', 'https', 'mysql', 'postgresql', 'rdp', 'smb', 'telnet', 'smtp', 'pop3', 'imap'];
        return attackable.includes(service.toLowerCase());
    },

    /**
     * Attack a service (redirect to auth tests)
     */
    attackService(ip, service, port) {
        Router.navigate(`auth-tests/${ip}`);
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
