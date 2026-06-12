/**
 * NetworkRecon - Hosts Module
 * Displays discovered hosts with details, ports, and vulnerabilities
 */

const Hosts = {
    currentFilter: 'all',
    searchQuery: '',
    currentSort: 'ip_address',
    sortDirection: 'asc',
    _attackCache: JSON.parse(localStorage.getItem('hosts_attack_cache') || '{}'),
    _sqlmapCache: JSON.parse(localStorage.getItem('hosts_sqlmap_cache') || '{}'),

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

            // Store for report generation
            this._currentHost = { host, ports, vulns, mitreMappings };

            app.innerHTML = this.getDetailHTML(host, ports, vulns, mitreMappings);

            // Auto-switch to services tab if no vulnerabilities
            if (vulns.length === 0) {
                this.showTab('services');
            }

            // Restore cached attack results
            ports.forEach(p => {
                const cacheKey = `${ip}:${p.number}`;
                if (this._attackCache[cacheKey]) {
                    const container = document.getElementById(`attack-result-${ip}-${p.number}`);
                    if (container) {
                        container.classList.remove('hidden');
                        this.showAttackResults(ip, p.number, this._attackCache[cacheKey]);
                    }
                }
                // Restore cached SQLMap results
                if (this._sqlmapCache[cacheKey]) {
                    const container = document.getElementById(`sqlmap-result-${ip}-${p.number}`);
                    if (container) {
                        container.classList.remove('hidden');
                        this.showSqlmapResults(ip, p.number, this._sqlmapCache[cacheKey]);
                    }
                }
            });
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
                    </div>
                </div>

                <div class="card">
                    <div class="card-body p-0">
                        ${filteredHosts.length ? `
                            <div class="overflow-x-auto">
                                <table class="data-table">
                                    <thead>
                                        <tr>
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
                                                Dernière détection ${this.getSortIcon('last_seen')}
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
                                <p>Modifiez votre recherche ou lancez un nouveau scan.</p>
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
                    <div class="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center">
                        <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                        </svg>
                    </div>
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
                    <button onclick="Hosts.showTab('vulns')" class="host-tab px-4 py-2 rounded-md text-sm font-medium bg-surface-700 text-white" data-tab="vulns">
                        Vulnérabilités (${vulns.length})
                    </button>
                    <button onclick="Hosts.showTab('services')" class="host-tab px-4 py-2 rounded-md text-sm font-medium text-surface-400 hover:text-white" data-tab="services">
                        Attaque des services (${ports.length})
                    </button>
                    <button onclick="Hosts.showTab('mitre')" class="host-tab px-4 py-2 rounded-md text-sm font-medium text-surface-400 hover:text-white" data-tab="mitre">
                        MITRE ATT&CK (${mitreMappings.length})
                    </button>
                </div>
                <button onclick="Hosts.generateReport()" class="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium flex items-center gap-2 transition-colors">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                    </svg>
                    Rapport
                </button>

                <!-- Vulns Tab -->
                <div id="tab-vulns" class="host-tab-content ${vulns.length > 0 ? '' : 'hidden'}">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Vulnérabilités associées (${vulns.length})</h3>
                        </div>
                        <div class="card-body p-0">
                            ${vulns.length ? `
                                <div class="divide-y divide-surface-700">
                                    ${vulns.map(v => {
                                        const cveId = v.cve?.cve_id || 'N/A';
                                        const severity = v.cve?.severity || 'info';
                                        const cvss = v.cve?.cvss_score || '-';
                                        const description = v.cve?.description || 'Aucune description disponible';
                                        const affectedProducts = v.cve?.affected_products || [];
                                        const mitreTechnique = v.mitre_mapping?.technique_id || '';
                                        const mitreTactic = v.mitre_mapping?.tactic || '';
                                        return `
                                            <div class="px-4 py-4 hover:bg-surface-700/30">
                                                <div class="flex items-start justify-between gap-4">
                                                    <div class="flex-1 min-w-0">
                                                        <div class="flex items-center gap-2 mb-1">
                                                            <span class="severity-badge severity-${severity} shrink-0">${severity}</span>
                                                            <span class="font-mono text-sm text-white font-medium">${cveId}</span>
                                                            ${v.service ? `
                                                                <span class="px-2 py-0.5 bg-surface-700 text-surface-300 rounded text-xs">
                                                                    ${this.escapeHtml(v.service)} ${v.port ? `(${v.port})` : ''}
                                                                </span>
                                                            ` : ''}
                                                            ${mitreTechnique ? `
                                                                <span class="px-2 py-0.5 bg-primary-500/15 text-primary-400 rounded text-xs font-mono">${mitreTechnique}</span>
                                                                <span class="text-xs text-surface-500">${this.escapeHtml(mitreTactic)}</span>
                                                            ` : ''}
                                                        </div>
                                                        <div class="text-sm text-surface-400 mb-1">${this.escapeHtml(description)}</div>
                                                        ${affectedProducts.length > 0 ? `
                                                            <div class="text-xs text-surface-500">
                                                                Produits affectés: ${affectedProducts.map(p => this.escapeHtml(p)).join(', ')}
                                                            </div>
                                                        ` : ''}
                                                    </div>
                                                    <div class="shrink-0 flex items-center gap-2">
                                                        <span class="text-sm font-medium text-white">CVSS ${cvss}</span>
                                                        ${cveId !== 'N/A' ? `
                                                            <a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank" onclick="event.stopPropagation()" class="px-2 py-1 bg-surface-700 hover:bg-surface-600 text-surface-300 hover:text-white rounded text-xs transition-colors flex items-center gap-1">
                                                                NVD
                                                                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                                                                </svg>
                                                            </a>
                                                        ` : ''}
                                                    </div>
                                                </div>
                                            </div>
                                        `;
                                    }).join('')}
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
                    ${ports.length ? `
                        <div class="space-y-4">
                            ${ports.map(p => {
                                const hasAttack = Hosts.canAttackService(p.service);
                                const attackInfo = Hosts.getAttackInfo(p.service);
                                return `
                                    <div class="card">
                                        <div class="card-header bg-surface-800">
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center gap-3">
                                                    <div class="w-10 h-10 rounded-lg bg-primary-500/15 flex items-center justify-center">
                                                        <svg class="w-5 h-5 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <h3 class="font-semibold text-white uppercase">${this.escapeHtml(p.service || 'Inconnu')}</h3>
                                                        <div class="text-sm text-surface-400">
                                                            Port <span class="font-mono text-white">${p.number}</span> / ${p.protocol}
                                                            ${p.version ? ` — ${this.escapeHtml(p.version)}` : ''}
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="flex items-center gap-2">
                                                    <span class="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">${p.state}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="card-body p-0">
                                            ${hasAttack ? `
                                                <div class="px-4 py-3">
                                                    <div class="flex items-center justify-between">
                                                        <div class="flex-1">
                                                            <div class="flex items-center gap-2 mb-1">
                                                                <span class="px-2 py-0.5 bg-red-500/15 text-red-400 rounded text-xs font-medium">${attackInfo.name}</span>
                                                                <span class="text-xs text-surface-500">•</span>
                                                                <span class="text-xs text-surface-500">Wordlist: ${attackInfo.wordlist}</span>
                                                                <span class="text-xs text-surface-500">•</span>
                                                                <span class="text-xs text-surface-500">Durée: ${attackInfo.duration}</span>
                                                            </div>
                                                            <div class="text-sm text-surface-400">${attackInfo.description}</div>
                                                        </div>
                                                        <div class="flex items-center gap-2 shrink-0 ml-4">
                                                            <button id="attack-btn-${host.ip_address}-${p.number}" onclick="Hosts.showBruteForceModal('${host.ip_address}', '${p.service || ''}', ${p.number})" class="px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white transition-colors text-sm font-medium flex items-center gap-2">
                                                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                                                                </svg>
                                                                Brute Force
                                                            </button>
                                                            ${(p.service === 'http' || p.service === 'https') ? `
                                                                <button onclick="Hosts.showSqlmapModal('${host.ip_address}', ${p.number}, '${p.service}')" class="px-4 py-2 rounded-lg bg-orange-500 hover:bg-orange-600 text-white transition-colors text-sm font-medium flex items-center gap-2">
                                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/>
                                                                    </svg>
                                                                    SQLMap
                                                                </button>
                                                            ` : ''}
                                                        </div>
                                                    </div>
                                                    <!-- Attack progress/results container -->
                                                    <div id="attack-result-${host.ip_address}-${p.number}" class="mt-3 hidden"></div>
                                                    <!-- SQLMap progress/results container -->
                                                    <div id="sqlmap-result-${host.ip_address}-${p.number}" class="mt-3 hidden"></div>
                                                </div>
                                            ` : `
                                                <div class="px-4 py-6 text-center">
                                                    <div class="text-sm text-surface-500">Aucune attaque disponible pour ce service</div>
                                                </div>
                                            `}
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    ` : `
                        <div class="card">
                            <div class="card-body">
                                <div class="empty-state">
                                    <p>Aucun service détecté</p>
                                </div>
                            </div>
                        </div>
                    `}
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
        const attackable = ['ssh', 'ftp', 'http', 'https', 'mysql', 'postgresql', 'rdp', 'smb', 'telnet', 'smtp', 'pop3', 'imap', 'redis', 'mongodb', 'vnc', 'ldap'];
        return attackable.includes(service.toLowerCase());
    },

    /**
     * Get attack info for a service
     */
    getAttackInfo(service) {
        const attacks = {
            'ssh': {
                name: 'Brute Force SSH',
                description: 'Tentative de connexion avec identifiants courants via protocole sécurisé',
                wordlist: 'rockyou.txt',
                duration: '~5 min par hôte',
            },
            'ftp': {
                name: 'Brute Force FTP',
                description: 'Authentification avec identifiants par défaut ou courants',
                wordlist: 'rockyou.txt',
                duration: '~3 min par hôte',
            },
            'smb': {
                name: 'Brute Force SMB',
                description: 'Accès aux partages réseau avec identifiants compromis',
                wordlist: 'rockyou.txt',
                duration: '~10 min par hôte',
            },
            'rdp': {
                name: 'Brute Force RDP',
                description: 'Accès distant Windows avec identifiants courants',
                wordlist: 'rockyou.txt',
                duration: '~8 min par hôte',
            },
            'http': {
                name: 'Brute Force HTTP',
                description: 'Attaque sur panneau d\'authentification web',
                wordlist: 'rockyou.txt',
                duration: '~5 min par hôte',
            },
            'https': {
                name: 'Brute Force HTTPS',
                description: 'Attaque sur panneau d\'authentification web sécurisé',
                wordlist: 'rockyou.txt',
                duration: '~5 min par hôte',
            },
            'mysql': {
                name: 'Brute Force MySQL',
                description: 'Accès à la base de données avec identifiants courants',
                wordlist: 'rockyou.txt',
                duration: '~4 min par hôte',
            },
            'postgresql': {
                name: 'Brute Force PostgreSQL',
                description: 'Accès à la base de données',
                wordlist: 'rockyou.txt',
                duration: '~4 min par hôte',
            },
            'redis': {
                name: 'Brute Force Redis',
                description: 'Accès au cache avec authentification optionnelle',
                wordlist: 'common_redis_passwords.txt',
                duration: '~1 min par hôte',
            },
            'mongodb': {
                name: 'Brute Force MongoDB',
                description: 'Accès à la base NoSQL',
                wordlist: 'rockyou.txt',
                duration: '~3 min par hôte',
            },
            'telnet': {
                name: 'Brute Force Telnet',
                description: 'Protocole non chiffré, credentials en clair',
                wordlist: 'rockyou.txt',
                duration: '~3 min par hôte',
            },
            'vnc': {
                name: 'Brute Force VNC',
                description: 'Accès graphique distant',
                wordlist: 'vnc_passwords.txt',
                duration: '~5 min par hôte',
            },
            'ldap': {
                name: 'Brute Force LDAP',
                description: 'Authentification annuaire Active Directory',
                wordlist: 'ad_passwords.txt',
                duration: '~10 min par hôte',
            },
            'smtp': {
                name: 'Brute Force SMTP',
                description: 'Authentification serveur mail sortant',
                wordlist: 'rockyou.txt',
                duration: '~5 min par hôte',
            },
            'pop3': {
                name: 'Brute Force POP3',
                description: 'Récupération emails avec identifiants courants',
                wordlist: 'rockyou.txt',
                duration: '~4 min par hôte',
            },
            'imap': {
                name: 'Brute Force IMAP',
                description: 'Accès boîte mail avec identifiants courants',
                wordlist: 'rockyou.txt',
                duration: '~4 min par hôte',
            },
        };

        const key = (service || '').toLowerCase();
        return attacks[key] || {
            name: `Attaque ${key.toUpperCase()}`,
            description: 'Tentative d\'authentification avec identifiants courants',
            wordlist: 'rockyou.txt',
            duration: '~5 min par hôte',
        };
    },

    /**
     * Show brute force config modal
     */
    showBruteForceModal(ip, service, port) {
        const attackInfo = this.getAttackInfo(service);

        const modal = document.createElement('div');
        modal.id = 'bruteforce-config-modal';
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/70';
        modal.innerHTML = `
            <div class="bg-surface-900 rounded-xl border border-surface-700 w-full max-w-md mx-4 p-6">
                <h3 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                    </svg>
                    Configuration Brute Force
                </h3>

                <div class="space-y-4">
                    <!-- Target info -->
                    <div class="bg-surface-800 rounded-lg p-3 text-sm">
                        <div class="flex items-center gap-2 mb-1">
                            <span class="text-surface-400">Attaque:</span>
                            <span class="text-red-400 font-medium">${attackInfo.name}</span>
                        </div>
                        <div class="flex items-center gap-2 mb-1">
                            <span class="text-surface-400">Cible:</span>
                            <span class="text-white font-mono">${ip}:${port}</span>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-surface-400">Description:</span>
                            <span class="text-surface-300">${attackInfo.description}</span>
                        </div>
                    </div>

                    <!-- Wordlist -->
                    <div class="bg-surface-800 rounded-lg p-3">
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-surface-400">Wordlist:</span>
                            <span class="text-white font-mono">${attackInfo.wordlist}</span>
                        </div>
                        <div class="flex items-center justify-between text-sm mt-1">
                            <span class="text-surface-400">Durée estimée:</span>
                            <span class="text-surface-300">${attackInfo.duration}</span>
                        </div>
                    </div>

                    <!-- Custom credentials file -->
                    <div>
                        <label class="block text-sm font-medium text-surface-300 mb-1.5">Fichier credentials custom (optionnel)</label>
                        <label class="flex items-center justify-center w-full h-24 border-2 border-dashed border-surface-600 rounded-lg cursor-pointer hover:border-red-500 hover:bg-surface-800/50 transition-colors" id="bf-dropzone">
                            <div class="text-center">
                                <svg class="w-8 h-8 text-surface-500 mx-auto mb-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                                </svg>
                                <span class="text-sm text-surface-400" id="bf-filename">Glissez un fichier JSON ou cliquez</span>
                                <input type="file" id="bf-file-input" class="hidden" accept=".json">
                            </div>
                        </label>
                        <p class="text-xs text-surface-500 mt-1">Format: <code>[{"user":"admin","pass":"1234"}]</code></p>
                    </div>
                </div>

                <!-- Buttons -->
                <div class="flex justify-end gap-3 pt-4 mt-4 border-t border-surface-700">
                    <button onclick="Hosts.closeBruteForceModal()" class="px-4 py-2 text-surface-300 hover:text-white hover:bg-surface-700 rounded-lg transition-colors text-sm font-medium">
                        Annuler
                    </button>
                    <button onclick="Hosts.confirmBruteForce('${ip}', '${service}', ${port})" class="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors text-sm font-medium flex items-center gap-2">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                        </svg>
                        Lancer l'attaque
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        // Handle file selection
        const fileInput = document.getElementById('bf-file-input');
        const filenameEl = document.getElementById('bf-filename');
        const dropzone = document.getElementById('bf-dropzone');

        if (fileInput && filenameEl) {
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    filenameEl.textContent = file.name;
                    filenameEl.classList.add('text-red-400');
                }
            });
        }

        // Close on ESC
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                Hosts.closeBruteForceModal();
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    },

    closeBruteForceModal() {
        const modal = document.getElementById('bruteforce-config-modal');
        if (modal) modal.remove();
    },

    /**
     * Confirm and launch brute force with config
     */
    async confirmBruteForce(ip, service, port) {
        const fileInput = document.getElementById('bf-file-input');
        const credentialsFile = fileInput?.files[0] || null;

        this.closeBruteForceModal();

        await this.attackService(ip, service, port, { credentialsFile });
    },

    /**
     * Attack a service - launch directly and show results inline
     */
    async attackService(ip, service, port, config = {}) {
        const resultContainer = document.getElementById(`attack-result-${ip}-${port}`);
        const attackBtn = document.getElementById(`attack-btn-${ip}-${port}`);

        if (!resultContainer) return;

        // Show loading state
        resultContainer.classList.remove('hidden');
        resultContainer.innerHTML = `
            <div class="bg-surface-800 rounded-lg p-4 border border-surface-700">
                <div class="flex items-center gap-3">
                    <svg class="animate-spin h-5 w-5 text-primary-400" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <div>
                        <div class="text-sm font-medium text-white">Lancement de l'attaque ${service.toUpperCase()}...</div>
                        <div class="text-xs text-surface-400">${ip}:${port}</div>
                    </div>
                </div>
            </div>
        `;

        // Disable button
        if (attackBtn) {
            attackBtn.disabled = true;
            attackBtn.classList.add('opacity-50', 'cursor-not-allowed');
        }

        try {
            const campaign = await api.launchFromSuggestion({
                host_ip: ip,
                service_type: service,
                port: port,
            }, config.credentialsFile);

            // Start polling for progress
            this._attackPollingIntervals = this._attackPollingIntervals || {};
            this._attackPollingIntervals[`${ip}-${port}`] = setInterval(
                () => this.updateAttackProgress(ip, port, campaign._id),
                1500
            );

        } catch (error) {
            resultContainer.innerHTML = `
                <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                    <div class="flex items-center gap-2">
                        <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <div class="text-sm text-red-400">Erreur: ${error.message || 'Échec du lancement'}</div>
                    </div>
                </div>
            `;
            if (attackBtn) {
                attackBtn.disabled = false;
                attackBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            }
        }
    },

    /**
     * Update attack progress inline
     */
    async updateAttackProgress(ip, port, campaignId) {
        const resultContainer = document.getElementById(`attack-result-${ip}-${port}`);
        if (!resultContainer) {
            // Container removed, stop polling
            this.stopAttackPolling(ip, port);
            return;
        }

        try {
            const progress = await api.getCampaignProgress(campaignId);
            const width = Math.max(0, Math.min(100, progress.percentage));

            if (progress.status === 'running' || progress.status === 'pending') {
                resultContainer.innerHTML = `
                    <div class="bg-surface-800 rounded-lg p-4 border border-surface-700">
                        <div class="flex items-center gap-3 mb-3">
                            <svg class="animate-spin h-5 w-5 text-primary-400" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            <div class="flex-1">
                                <div class="text-sm font-medium text-white">Attaque en cours...</div>
                                <div class="text-xs text-surface-400">${progress.tests_completed || 0}/${progress.total_tests || '?'} tests</div>
                            </div>
                            <div class="text-sm font-medium text-primary-400">${progress.percentage}%</div>
                        </div>
                        <div class="w-full bg-surface-700 rounded-full h-2">
                            <div class="h-full rounded-full bg-primary-500 transition-all duration-500" style="width: ${width}%"></div>
                        </div>
                    </div>
                `;
            } else if (progress.status === 'completed') {
                this.stopAttackPolling(ip, port);
                // Fetch full results
                const fullCampaign = await api.getAuthTestCampaign(campaignId);
                this.showAttackResults(ip, port, fullCampaign);
            } else if (progress.status === 'failed') {
                this.stopAttackPolling(ip, port);
                resultContainer.innerHTML = `
                    <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                        <div class="flex items-center gap-2">
                            <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                            </svg>
                            <div class="text-sm text-red-400">L'attaque a échoué</div>
                        </div>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Erreur polling attack:', error);
        }
    },

    /**
     * Show attack results inline
     */
    showAttackResults(ip, port, campaign) {
        const cacheKey = `${ip}:${port}`;
        this._attackCache[cacheKey] = campaign;
        localStorage.setItem('hosts_attack_cache', JSON.stringify(this._attackCache));

        const resultContainer = document.getElementById(`attack-result-${ip}-${port}`);
        if (!resultContainer) return;

        const results = campaign.results || [];
        const successes = results.filter(r => r.success);
        const failures = results.filter(r => !r.success);

        resultContainer.innerHTML = `
            <div class="bg-surface-800 rounded-lg border border-surface-700">
                <div class="px-4 py-3 border-b border-surface-700 flex items-center justify-between">
                    <div class="flex items-center gap-3">
                        <svg class="w-5 h-5 ${successes.length > 0 ? 'text-emerald-400' : 'text-surface-400'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <div>
                            <div class="text-sm font-medium text-white">Attaque terminée</div>
                            <div class="text-xs text-surface-400">${results.length} credentials testés</div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        ${successes.length > 0 ? `<span class="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded text-xs font-medium">${successes.length} succès</span>` : ''}
                        <span class="px-2 py-1 bg-surface-700 text-surface-300 rounded text-xs font-medium">${failures.length} échecs</span>
                    </div>
                </div>
                ${successes.length > 0 ? `
                    <div class="px-4 py-3 border-b border-surface-700 bg-emerald-500/5">
                        <div class="text-xs font-medium text-emerald-400 mb-2">Credentials valides trouvés:</div>
                        <div class="space-y-2">
                            ${successes.map((r, idx) => {
                                const creds = (r.credential_plain || '').split(':');
                                const u = creds[0] || r.username || '';
                                const p = creds[1] || '';
                                return `
                                <div class="flex items-center justify-between bg-surface-900 rounded-lg px-3 py-2">
                                    <div class="flex items-center gap-2">
                                        <span class="font-mono text-emerald-400">${this.escapeHtml(u)}</span>
                                        <span class="text-surface-500">:</span>
                                        <span class="font-mono text-surface-300">${this.escapeHtml(p || '***')}</span>
                                        ${r.service ? `<span class="text-surface-500">• ${r.service}:${r.port || ''}</span>` : ''}
                                    </div>
                                    <button onclick="Hosts.copySshCommand('${this.escapeHtml(ip)}', ${port}, '${this.escapeHtml(u)}')" class="copy-ssh-btn px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
                                        </svg>
                                        Copier SSH
                                    </button>
                                </div>
                            `}).join('')}
                        </div>
                    </div>
                ` : ''}
                <div class="px-4 py-3 max-h-40 overflow-y-auto">
                    <div class="text-xs font-medium text-surface-400 mb-2">Derniers essais:</div>
                    <div class="space-y-1">
                        ${results.slice(-10).reverse().map(r => `
                            <div class="flex items-center gap-2 text-xs">
                                <span class="w-2 h-2 rounded-full ${r.success ? 'bg-emerald-400' : 'bg-red-400'}"></span>
                                <span class="font-mono text-surface-300">${this.escapeHtml(r.username || '-')}</span>
                                <span class="text-surface-500">•</span>
                                <span class="${r.success ? 'text-emerald-400' : 'text-red-400'}">${r.success ? 'Succès' : 'Échec'}</span>
                                ${r.error_message && !r.success ? `<span class="text-surface-500 truncate">(${this.escapeHtml(r.error_message)})</span>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;

        // Re-enable button for retry
        const attackBtn = document.getElementById(`attack-btn-${ip}-${port}`);
        if (attackBtn) {
            attackBtn.disabled = false;
            attackBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        }
    },

    /**
     * Show SQLMap config modal
     */
    showSqlmapModal(ip, port, service) {
        const protocol = service === 'https' ? 'https' : 'http';
        const targetUrl = `${protocol}://${ip}:${port}/`;

        const modal = document.createElement('div');
        modal.id = 'sqlmap-config-modal';
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/70';
        modal.innerHTML = `
            <div class="bg-surface-900 rounded-xl border border-surface-700 w-full max-w-lg mx-4 p-6 max-h-[90vh] overflow-y-auto">
                <h3 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/>
                    </svg>
                    Configuration SQLMap
                </h3>

                <div class="space-y-4">
                    <!-- Target URL -->
                    <div>
                        <label class="block text-sm font-medium text-surface-300 mb-1.5">URL Cible</label>
                        <input type="text" id="sqlmap-target" value="${targetUrl}" readonly class="w-full px-3 py-2 bg-surface-800 border border-surface-600 rounded-lg text-surface-400 font-mono text-sm cursor-not-allowed">
                    </div>

                    <!-- Level & Risk -->
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-surface-300 mb-1.5">Level (1-5)</label>
                            <select id="sqlmap-level" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500">
                                <option value="1">1 - Basique</option>
                                <option value="2" selected>2 - Standard</option>
                                <option value="3">3 - Intermédiaire</option>
                                <option value="4">4 - Avancé</option>
                                <option value="5">5 - Maximum</option>
                            </select>
                            <p class="text-xs text-surface-500 mt-1">Profondeur des tests</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-surface-300 mb-1.5">Risk (1-3)</label>
                            <select id="sqlmap-risk" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500">
                                <option value="1" selected>1 - Sécurisé</option>
                                <option value="2">2 - Modéré</option>
                                <option value="3">3 - Agressif</option>
                            </select>
                            <p class="text-xs text-surface-500 mt-1">Niveau de risque des payloads</p>
                        </div>
                    </div>

                    <!-- Crawl & Threads -->
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-surface-300 mb-1.5">Crawl Depth (0-5)</label>
                            <select id="sqlmap-crawl" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500">
                                <option value="0">0 - Désactivé</option>
                                <option value="1">1 - Surface</option>
                                <option value="2" selected>2 - Standard</option>
                                <option value="3">3 - Profond</option>
                                <option value="4">4 - Très profond</option>
                                <option value="5">5 - Maximum</option>
                            </select>
                            <p class="text-xs text-surface-500 mt-1">Profondeur de crawl</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-surface-300 mb-1.5">Threads (1-10)</label>
                            <select id="sqlmap-threads" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500">
                                <option value="1" selected>1 - Séquentiel</option>
                                <option value="2">2</option>
                                <option value="3">3</option>
                                <option value="5">5</option>
                                <option value="10">10 - Maximum</option>
                            </select>
                            <p class="text-xs text-surface-500 mt-1">Connexions simultanées</p>
                        </div>
                    </div>

                    <!-- Techniques -->
                    <div>
                        <label class="block text-sm font-medium text-surface-300 mb-1.5">Techniques SQLi</label>
                        <div class="grid grid-cols-3 gap-2">
                            <label class="flex items-center gap-2 bg-surface-800 rounded-lg px-3 py-2 cursor-pointer hover:bg-surface-700">
                                <input type="checkbox" id="sqlmap-tech-b" checked class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                                <span class="text-sm text-surface-300"><span class="font-mono text-orange-400">B</span>oolean</span>
                            </label>
                            <label class="flex items-center gap-2 bg-surface-800 rounded-lg px-3 py-2 cursor-pointer hover:bg-surface-700">
                                <input type="checkbox" id="sqlmap-tech-e" checked class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                                <span class="text-sm text-surface-300"><span class="font-mono text-orange-400">E</span>rror</span>
                            </label>
                            <label class="flex items-center gap-2 bg-surface-800 rounded-lg px-3 py-2 cursor-pointer hover:bg-surface-700">
                                <input type="checkbox" id="sqlmap-tech-u" checked class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                                <span class="text-sm text-surface-300"><span class="font-mono text-orange-400">U</span>nion</span>
                            </label>
                            <label class="flex items-center gap-2 bg-surface-800 rounded-lg px-3 py-2 cursor-pointer hover:bg-surface-700">
                                <input type="checkbox" id="sqlmap-tech-s" class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                                <span class="text-sm text-surface-300"><span class="font-mono text-orange-400">S</span>tacked</span>
                            </label>
                            <label class="flex items-center gap-2 bg-surface-800 rounded-lg px-3 py-2 cursor-pointer hover:bg-surface-700">
                                <input type="checkbox" id="sqlmap-tech-t" checked class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                                <span class="text-sm text-surface-300"><span class="font-mono text-orange-400">T</span>ime</span>
                            </label>
                            <label class="flex items-center gap-2 bg-surface-800 rounded-lg px-3 py-2 cursor-pointer hover:bg-surface-700">
                                <input type="checkbox" id="sqlmap-tech-i" class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                                <span class="text-sm text-surface-300"><span class="font-mono text-orange-400">I</span>nline</span>
                            </label>
                        </div>
                    </div>

                    <!-- DBMS -->
                    <div>
                        <label class="block text-sm font-medium text-surface-300 mb-1.5">Forcer DBMS (optionnel)</label>
                        <select id="sqlmap-dbms" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500">
                            <option value="">Auto-détection</option>
                            <option value="mysql">MySQL</option>
                            <option value="postgresql">PostgreSQL</option>
                            <option value="mssql">Microsoft SQL Server</option>
                            <option value="oracle">Oracle</option>
                            <option value="sqlite">SQLite</option>
                            <option value="mongodb">MongoDB</option>
                            <option value="mariadb">MariaDB</option>
                        </select>
                    </div>

                    <!-- Tamper -->
                    <div>
                        <label class="block text-sm font-medium text-surface-300 mb-1.5">Scripts Tamper (optionnel)</label>
                        <input type="text" id="sqlmap-tamper" placeholder="ex: between,randomcase,space2comment" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white placeholder-surface-400 focus:outline-none focus:ring-2 focus:ring-orange-500">
                        <p class="text-xs text-surface-500 mt-1">Séparés par des virgules</p>
                    </div>

                    <!-- POST Data -->
                    <div>
                        <label class="block text-sm font-medium text-surface-300 mb-1.5">Données POST (optionnel)</label>
                        <textarea id="sqlmap-data" rows="2" placeholder="ex: user=admin&pass=123" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white placeholder-surface-400 focus:outline-none focus:ring-2 focus:ring-orange-500 resize-none font-mono text-sm"></textarea>
                    </div>

                    <!-- Cookie -->
                    <div>
                        <label class="block text-sm font-medium text-surface-300 mb-1.5">Cookie (optionnel)</label>
                        <input type="text" id="sqlmap-cookie" placeholder="ex: session=abc123" class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-white placeholder-surface-400 focus:outline-none focus:ring-2 focus:ring-orange-500 font-mono text-sm">
                    </div>

                    <!-- Options -->
                    <div class="flex items-center gap-4">
                        <label class="flex items-center gap-2 cursor-pointer">
                            <input type="checkbox" id="sqlmap-forms" checked class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                            <span class="text-sm text-surface-300">Tester les formulaires HTML</span>
                        </label>
                        <label class="flex items-center gap-2 cursor-pointer">
                            <input type="checkbox" id="sqlmap-random-agent" checked class="rounded bg-surface-700 border-surface-600 text-orange-500 focus:ring-orange-500">
                            <span class="text-sm text-surface-300">User-Agent aléatoire</span>
                        </label>
                    </div>
                </div>

                <!-- Buttons -->
                <div class="flex justify-end gap-3 pt-4 mt-4 border-t border-surface-700">
                    <button onclick="Hosts.closeSqlmapModal()" class="px-4 py-2 text-surface-300 hover:text-white hover:bg-surface-700 rounded-lg transition-colors text-sm font-medium">
                        Annuler
                    </button>
                    <button onclick="Hosts.confirmSqlmap('${ip}', ${port}, '${service}')" class="px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white rounded-lg transition-colors text-sm font-medium flex items-center gap-2">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                        </svg>
                        Lancer SQLMap
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        // Close on ESC
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                Hosts.closeSqlmapModal();
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    },

    closeSqlmapModal() {
        const modal = document.getElementById('sqlmap-config-modal');
        if (modal) modal.remove();
    },

    /**
     * Confirm and launch SQLMap with config
     */
    async confirmSqlmap(ip, port, service) {
        // Gather config BEFORE closing modal
        const techB = document.getElementById('sqlmap-tech-b')?.checked;
        const techE = document.getElementById('sqlmap-tech-e')?.checked;
        const techU = document.getElementById('sqlmap-tech-u')?.checked;
        const techS = document.getElementById('sqlmap-tech-s')?.checked;
        const techT = document.getElementById('sqlmap-tech-t')?.checked;
        const techI = document.getElementById('sqlmap-tech-i')?.checked;

        let techniques = '';
        if (techB) techniques += 'B';
        if (techE) techniques += 'E';
        if (techU) techniques += 'U';
        if (techS) techniques += 'S';
        if (techT) techniques += 'T';
        if (techI) techniques += 'I';
        if (!techniques) techniques = 'BEUST';

        const config = {
            level: parseInt(document.getElementById('sqlmap-level')?.value || '2'),
            risk: parseInt(document.getElementById('sqlmap-risk')?.value || '1'),
            depth_crawl: parseInt(document.getElementById('sqlmap-crawl')?.value || '2'),
            threads: parseInt(document.getElementById('sqlmap-threads')?.value || '1'),
            techniques: techniques,
            dbms: document.getElementById('sqlmap-dbms')?.value || null,
            tamper: document.getElementById('sqlmap-tamper')?.value || null,
            data: document.getElementById('sqlmap-data')?.value || null,
            cookie: document.getElementById('sqlmap-cookie')?.value || null,
            forms: document.getElementById('sqlmap-forms')?.checked ?? true,
            random_agent: document.getElementById('sqlmap-random-agent')?.checked ?? true,
        };

        // Now close modal
        this.closeSqlmapModal();

        await this.launchSqlmapWithConfig(ip, port, service, config);
    },

    /**
     * Launch SQLMap with custom config
     */
    async launchSqlmapWithConfig(ip, port, service, config) {
        const resultContainer = document.getElementById(`sqlmap-result-${ip}-${port}`);
        const protocol = service === 'https' ? 'https' : 'http';
        const targetUrl = `${protocol}://${ip}:${port}/`;

        if (resultContainer) {
            resultContainer.classList.remove('hidden');
            resultContainer.innerHTML = `
                <div class="bg-surface-800 rounded-lg p-4 border border-surface-700">
                    <div class="flex items-center gap-3">
                        <svg class="animate-spin h-5 w-5 text-orange-400" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        <div>
                            <div class="text-sm font-medium text-white">Lancement SQLMap...</div>
                            <div class="text-xs text-surface-400">${targetUrl}</div>
                            <div class="text-xs text-surface-500 mt-1">Level: ${config.level} | Risk: ${config.risk} | Forms: ${config.forms ? 'Oui' : 'Non'} | Crawl: ${config.depth_crawl} | Tech: ${config.techniques}</div>
                        </div>
                    </div>
                </div>
            `;
        }

        try {
            const campaign = await api.createSqlmapCampaign({
                name: `SQLMap ${ip}:${port}`,
                target_url: targetUrl,
                ...config,
            });

            const campaignId = campaign._id || campaign.id;

            // Start polling
            this._sqlmapPolling = this._sqlmapPolling || {};
            this._sqlmapPolling[`${ip}:${port}`] = setInterval(
                () => this.pollSqlmapResults(ip, port, campaignId),
                2000
            );

        } catch (error) {
            if (resultContainer) {
                resultContainer.innerHTML = `
                    <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                        <div class="flex items-center gap-2">
                            <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                            <div class="text-sm text-red-400">Erreur: ${error.message || 'Échec du lancement'}</div>
                        </div>
                    </div>
                `;
            }
        }
    },

    /**
     * Poll SQLMap campaign results
     */
    async pollSqlmapResults(ip, port, campaignId) {
        const resultContainer = document.getElementById(`sqlmap-result-${ip}-${port}`);
        if (!resultContainer) {
            this.stopSqlmapPolling(ip, port);
            return;
        }

        try {
            const campaign = await api.getSqlmapCampaign(campaignId);
            const status = campaign.status;
            const progress = campaign.urls_completed || 0;
            const total = campaign.total_urls || 1;

            if (status === 'running' || status === 'pending') {
                resultContainer.innerHTML = `
                    <div class="bg-surface-800 rounded-lg p-4 border border-surface-700">
                        <div class="flex items-center gap-3 mb-3">
                            <svg class="animate-spin h-5 w-5 text-orange-400" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            <div class="flex-1">
                                <div class="text-sm font-medium text-white">SQLMap en cours...</div>
                                <div class="text-xs text-surface-400">${progress}/${total} URLs analysées</div>
                            </div>
                            <div class="text-sm font-medium text-orange-400">${Math.round(progress/total*100)}%</div>
                        </div>
                        <div class="w-full bg-surface-700 rounded-full h-2">
                            <div class="h-full rounded-full bg-orange-500 transition-all duration-500" style="width: ${Math.round(progress/total*100)}%"></div>
                        </div>
                        <div class="text-xs text-surface-500 mt-2">${campaign.target_url}</div>
                    </div>
                `;
            } else if (status === 'completed' || status === 'failed') {
                this.stopSqlmapPolling(ip, port);
                this.showSqlmapResults(ip, port, campaign);
            }
        } catch (error) {
            console.error('Erreur polling SQLMap:', error);
        }
    },

    /**
     * Show SQLMap results inline
     */
    showSqlmapResults(ip, port, campaign) {
        // Cache for persistence across refreshes
        const cacheKey = `${ip}:${port}`;
        this._sqlmapCache[cacheKey] = campaign;
        localStorage.setItem('hosts_sqlmap_cache', JSON.stringify(this._sqlmapCache));

        const resultContainer = document.getElementById(`sqlmap-result-${ip}-${port}`);
        if (!resultContainer) return;

        const vulns = campaign.vulnerabilities || [];
        const databases = campaign.databases || [];
        const results = campaign.results || [];
        const isError = campaign.status === 'failed';
        const rawOutput = results[0]?.raw_output || '';
        const config = campaign.config || {};

        resultContainer.innerHTML = `
            <div class="bg-surface-800 rounded-lg border border-surface-700">
                <!-- Header -->
                <div class="px-4 py-3 border-b border-surface-700 flex items-center justify-between">
                    <div class="flex items-center gap-3">
                        <svg class="w-5 h-5 ${vulns.length > 0 ? 'text-orange-400' : isError ? 'text-red-400' : 'text-surface-400'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <div>
                            <div class="text-sm font-medium text-white">SQLMap ${isError ? 'échoué' : 'terminé'}</div>
                            <div class="text-xs text-surface-400">${campaign.target_url}</div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        ${vulns.length > 0 ? `<span class="px-2 py-1 bg-orange-500/15 text-orange-400 rounded text-xs font-medium">${vulns.length} injection(s)</span>` : ''}
                        ${databases.length > 0 ? `<span class="px-2 py-1 bg-blue-500/15 text-blue-400 rounded text-xs font-medium">${databases.length} base(s)</span>` : ''}
                        <span class="px-2 py-1 bg-surface-700 text-surface-300 rounded text-xs font-medium">${campaign.urls_completed || 0} URLs</span>
                    </div>
                </div>

                <!-- Config used -->
                <div class="px-4 py-2 border-b border-surface-700 bg-surface-900/50">
                    <div class="flex items-center gap-4 text-xs text-surface-500">
                        <span>Level: <span class="text-surface-300">${config.level || 1}</span></span>
                        <span>Risk: <span class="text-surface-300">${config.risk || 1}</span></span>
                        <span>Forms: <span class="text-surface-300">${config.forms ? 'Oui' : 'Non'}</span></span>
                        <span>Crawl: <span class="text-surface-300">${config.depth_crawl || 1}</span></span>
                        <span>Techniques: <span class="text-surface-300">${config.techniques || 'BEUST'}</span></span>
                    </div>
                </div>

                <!-- Vulnerabilities -->
                ${vulns.length > 0 ? `
                    <div class="px-4 py-3 border-b border-surface-700 bg-orange-500/5">
                        <div class="text-xs font-medium text-orange-400 mb-2">Vulnérabilités SQL Injection détectées:</div>
                        <div class="space-y-2">
                            ${vulns.map(v => `
                                <div class="bg-surface-900 rounded-lg px-3 py-2 border border-orange-500/20">
                                    <div class="flex items-center gap-2 mb-1">
                                        <span class="px-2 py-0.5 bg-orange-500/15 text-orange-400 rounded text-xs font-medium">${v.injection_type || 'SQLi'}</span>
                                        <span class="font-mono text-sm text-white font-medium">${v.parameter || 'N/A'}</span>
                                        ${v.dbms ? `<span class="text-xs text-surface-500">${v.dbms}</span>` : ''}
                                    </div>
                                    <div class="text-sm text-surface-300 mb-1">${v.title || ''}</div>
                                    ${v.payload ? `<div class="text-xs text-surface-500 font-mono mt-1 break-all bg-surface-950 rounded p-2">Payload: ${v.payload}</div>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}

                <!-- Databases -->
                ${databases.length > 0 ? `
                    <div class="px-4 py-3 border-b border-surface-700">
                        <div class="text-xs font-medium text-blue-400 mb-2">Bases de données découvertes:</div>
                        <div class="space-y-2">
                            ${databases.map(db => `
                                <div class="bg-surface-900 rounded-lg px-3 py-2">
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center gap-2">
                                            <svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/>
                                            </svg>
                                            <span class="font-mono text-sm text-white font-medium">${db.name || db}</span>
                                        </div>
                                        ${db.tables_count ? `<span class="text-xs text-surface-400">${db.tables_count} table(s)</span>` : ''}
                                    </div>
                                    ${db.tables && db.tables.length > 0 ? `
                                        <div class="mt-2 ml-6 space-y-1">
                                            ${db.tables.map(t => `
                                                <div class="flex items-center gap-2 text-xs">
                                                    <span class="text-surface-500">├─</span>
                                                    <span class="text-surface-300">${t.name || t}</span>
                                                    ${t.columns_count ? `<span class="text-surface-500">(${t.columns_count} colonnes)</span>` : ''}
                                                </div>
                                            `).join('')}
                                        </div>
                                    ` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}

                <!-- Error or No results -->
                ${isError ? `
                    <div class="px-4 py-3 bg-red-500/5">
                        <div class="flex items-center gap-2">
                            <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                            <div class="text-sm text-red-400">${campaign.error_message || 'Erreur inconnue'}</div>
                        </div>
                    </div>
                ` : ''}
                ${!isError && vulns.length === 0 ? `
                    <div class="px-4 py-3">
                        <div class="text-sm text-surface-400">Aucune injection SQL détectée avec cette configuration.</div>
                        <div class="text-xs text-surface-500 mt-1">Essayez d'augmenter le level (3-5) ou activez les forms pour un scan plus approfondi.</div>
                    </div>
                ` : ''}

                <!-- Raw output toggle -->
                <div class="px-4 py-2 border-t border-surface-700">
                    <button onclick="document.getElementById('sqlmap-raw-${ip}-${port}').classList.toggle('hidden')" class="text-xs text-surface-500 hover:text-surface-300 flex items-center gap-1">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                        </svg>
                        Sortie brute SQLMap
                    </button>
                    <div id="sqlmap-raw-${ip}-${port}" class="hidden mt-2">
                        <pre class="bg-surface-950 rounded p-3 text-xs text-surface-400 overflow-x-auto max-h-64 overflow-y-auto font-mono whitespace-pre-wrap">${rawOutput ? this.escapeHtml(rawOutput) : 'Aucune sortie disponible'}</pre>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Stop SQLMap polling
     */
    stopSqlmapPolling(ip, port) {
        this._sqlmapPolling = this._sqlmapPolling || {};
        const key = `${ip}:${port}`;
        if (this._sqlmapPolling[key]) {
            clearInterval(this._sqlmapPolling[key]);
            delete this._sqlmapPolling[key];
        }
    },

    /**
     * Stop attack polling
     */
    stopAttackPolling(ip, port) {
        this._attackPollingIntervals = this._attackPollingIntervals || {};
        const key = `${ip}-${port}`;
        if (this._attackPollingIntervals[key]) {
            clearInterval(this._attackPollingIntervals[key]);
            delete this._attackPollingIntervals[key];
        }
    },

    /**
     * Generate Word report for the current host
     */
    generateReport() {
        if (!this._currentHost) {
            alert('Aucune donnée hôte disponible');
            return;
        }

        const { host, ports, vulns, mitreMappings } = this._currentHost;
        const attackResults = this._attackCache[`${host.ip_address}:22`]
            || this._attackCache[`${host.ip_address}:21`]
            || this._attackCache[`${host.ip_address}:80`]
            || null;

        // Collect all attack results for this host
        const allAttackResults = [];
        Object.keys(this._attackCache).forEach(key => {
            if (key.startsWith(`${host.ip_address}:`)) {
                const c = this._attackCache[key];
                if (c.results) allAttackResults.push(...c.results);
            }
        });

        const successes = allAttackResults.filter(r => r.success);
        const now = new Date().toLocaleString('fr-FR');

        // Collect all SQLMap results for this host
        const allSqlmapResults = [];
        Object.keys(this._sqlmapCache).forEach(key => {
            if (key.startsWith(`${host.ip_address}-`)) {
                const c = this._sqlmapCache[key];
                allSqlmapResults.push(c);
            }
        });

        // Group MITRE by tactic
        const tactics = {};
        mitreMappings.forEach(m => {
            const tac = m.tactic || 'Non classifié';
            if (!tactics[tac]) tactics[tac] = [];
            tactics[tac].push(m);
        });

        // Cyber Kill Chain phases
        const killChainPhases = [
            { name: '1. Reconnaissance', mitreTactics: ['Reconnaissance'], description: 'Collecte d\'informations sur la cible' },
            { name: '2. Weaponization', mitreTactics: ['Resource Development'], description: 'Création des outils d\'attaque' },
            { name: '3. Delivery', mitreTactics: ['Initial Access'], description: 'Livraison du vecteur d\'attaque' },
            { name: '4. Exploitation', mitreTactics: ['Execution', 'Exploitation for Client Execution'], description: 'Exploitation de la vulnérabilité' },
            { name: '5. Installation', mitreTactics: ['Persistence', 'Defense Evasion'], description: 'Installation de la persistance' },
            { name: '6. Command & Control', mitreTactics: ['Command and Control'], description: 'Communication avec la machine compromise' },
            { name: '7. Actions on Objectives', mitreTactics: ['Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact'], description: 'Atteinte des objectifs finaux' }
        ];

        const tacticTechniques = {};
        mitreMappings.forEach(m => {
            const tac = m.tactic || '';
            if (!tacticTechniques[tac]) tacticTechniques[tac] = [];
            tacticTechniques[tac].push(m);
        });

        let html = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Rapport de Reconnaissance - ${host.ip_address}</title>
<style>
body { font-family: Calibri, sans-serif; margin: 40px; color: #333; }
h1 { color: #1a365d; border-bottom: 3px solid #2563eb; padding-bottom: 10px; }
h2 { color: #1e40af; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 30px; }
h3 { color: #1d4ed8; margin-top: 20px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
th { background-color: #1e40af; color: white; }
tr:nth-child(even) { background-color: #f3f4f6; }
.severity-critical { color: #dc2626; font-weight: bold; }
.severity-high { color: #ea580c; font-weight: bold; }
.severity-medium { color: #ca8a04; font-weight: bold; }
.severity-low { color: #16a34a; }
.severity-info { color: #6b7280; }
.phase { background-color: #eff6ff; border-left: 4px solid #2563eb; padding: 10px 15px; margin: 10px 0; }
.phase-active { background-color: #fef2f2; border-left-color: #dc2626; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; }
.badge-success { background: #dcfce7; color: #166534; }
.badge-fail { background: #fee2e2; color: #991b1b; }
.credential-box { background: #f0fdf4; border: 1px solid #86efac; border-radius: 6px; padding: 10px; margin: 5px 0; }
.footer { margin-top: 40px; padding-top: 10px; border-top: 1px solid #ccc; font-size: 0.85em; color: #666; }
</style>
</head>
<body>

<h1>Rapport de Reconnaissance R&eacute;seau</h1>
<p><strong>Cible:</strong> ${host.ip_address} (${host.hostname || 'N/A'})</p>
<p><strong>Date du rapport:</strong> ${now}</p>
<p><strong>G&eacute;n&eacute;r&eacute; par:</strong> NetworkRecon</p>

<h2>1. Informations sur la Machine Cible</h2>
<table>
    <tr><th width="200">Param&egrave;tre</th><th>Valeur</th></tr>
    <tr><td><strong>Adresse IP</strong></td><td>${host.ip_address}</td></tr>
    <tr><td><strong>Hostname</strong></td><td>${host.hostname || 'Non r&eacute;solu'}</td></tr>
    <tr><td><strong>Syst&egrave;me d\'exploitation</strong></td><td>${host.os_detection || 'Non d&eacute;tect&eacute;'}</td></tr>
    <tr><td><strong>Premi&egrave;re d&eacute;couverte</strong></td><td>${host.first_seen ? new Date(host.first_seen).toLocaleString('fr-FR') : '-'}</td></tr>
    <tr><td><strong>Derni&egrave;re d&eacute;couverte</strong></td><td>${host.last_seen ? new Date(host.last_seen).toLocaleString('fr-FR') : '-'}</td></tr>
    <tr><td><strong>Nombre de ports ouverts</strong></td><td>${ports.length}</td></tr>
    <tr><td><strong>Nombre de vuln&eacute;rabilit&eacute;s</strong></td><td>${vulns.length}</td></tr>
    <tr><td><strong>Techniques MITRE d&eacute;tect&eacute;es</strong></td><td>${mitreMappings.length}</td></tr>
</table>

<h2>2. Services D&eacute;couverts</h2>
<table>
    <tr><th>Port</th><th>Protocole</th><th>Service</th><th>&Eacute;tat</th><th>Version</th></tr>
    ${ports.map(p => `
        <tr>
            <td>${p.number}</td>
            <td>${p.protocol}</td>
            <td><strong>${p.service || 'Inconnu'}</strong></td>
            <td>${p.state}</td>
            <td>${p.version || '-'}</td>
        </tr>
    `).join('')}
</table>

<h2>3. Vuln&eacute;rabilit&eacute;s D&eacute;tect&eacute;es</h2>
${vulns.length > 0 ? `
<table>
    <tr><th>CVE</th><th>S&eacute;v&eacute;rit&eacute;</th><th>CVSS</th><th>Service</th><th>Description</th></tr>
    ${vulns.map(v => {
        const cveId = v.cve?.cve_id || 'N/A';
        const severity = v.cve?.severity || 'info';
        const cvss = v.cve?.cvss_score || '-';
        const desc = (v.cve?.description || 'N/A').substring(0, 150);
        return `
            <tr>
                <td><strong>${cveId}</strong></td>
                <td class="severity-${severity}">${severity.toUpperCase()}</td>
                <td>${cvss}</td>
                <td>${v.service || '-'} (${v.port || '-'})</td>
                <td>${desc}${desc.length >= 150 ? '...' : ''}</td>
            </tr>
        `;
    }).join('')}
</table>
` : '<p>Aucune vuln&eacute;rabilit&eacute; d&eacute;tect&eacute;e.</p>'}

<h2>4. Credentials Trouv&eacute;s</h2>
${successes.length > 0 ? `
<p><strong>${successes.length} credential(s) valide(s) trouv&eacute;(s):</strong></p>
${successes.map(r => {
    const creds = (r.credential_plain || '').split(':');
    return `
        <div class="credential-box">
            <strong>Utilisateur:</strong> ${creds[0] || r.username || 'N/A'}<br>
            <strong>Mot de passe:</strong> ${creds[1] || '***'}<br>
            <strong>Service:</strong> ${r.service || 'N/A'} (port ${r.port || 'N/A'})
        </div>
    `;
}).join('')}
` : '<p>Aucun credential valide trouv&eacute; lors des tests.</p>'}

<h2>5. SQLMap - Injections SQL D&eacute;tect&eacute;es</h2>
${allSqlmapResults.length > 0 ? `
${allSqlmapResults.map(sqlmap => {
    const vulns = sqlmap.vulnerabilities || [];
    const databases = sqlmap.databases || [];
    const config = sqlmap.config || {};
    return `
    <div style="background:#fffbeb; border-left:4px solid #f59e0b; padding:12px 15px; margin:10px 0;">
        <h3 style="color:#b45309; margin-top:0;">${sqlmap.target_url || 'N/A'}</h3>
        <p><strong>Configuration:</strong> Level ${config.level || 1} | Risk ${config.risk || 1} | Forms ${config.forms ? 'Activ&eacute;' : 'Désactiv&eacute;'} | Crawl ${config.depth_crawl || 1} | Techniques ${config.techniques || 'BEUST'}</p>
        ${vulns.length > 0 ? `
        <p><strong>${vulns.length} injection(s) SQL d&eacute;tect&eacute;(s):</strong></p>
        <table>
            <tr><th>Type</th><th>Param&egrave;tre</th><th>DBMS</th><th>Description</th><th>Payload</th></tr>
            ${vulns.map(v => `
                <tr>
                    <td><strong>${v.injection_type || 'SQLi'}</strong></td>
                    <td>${v.parameter || 'N/A'}</td>
                    <td>${v.dbms || '-'}</td>
                    <td>${(v.title || '').substring(0, 100)}${(v.title || '').length > 100 ? '...' : ''}</td>
                    <td style="font-size:0.8em; word-break:break-all;">${(v.payload || '-').substring(0, 150)}${(v.payload || '').length > 150 ? '...' : ''}</td>
                </tr>
            `).join('')}
        </table>
        ` : '<p>Aucune injection SQL d&eacute;tect&eacute;e.</p>'}
        ${databases.length > 0 ? `
        <p><strong>${databases.length} base(s) de donn&eacute;es d&eacute;couverte(s):</strong></p>
        <table>
            <tr><th>Nom de la base</th><th>Tables</th></tr>
            ${databases.map(db => `
                <tr>
                    <td><strong>${db.name || db}</strong></td>
                    <td>${db.tables && db.tables.length > 0 ? db.tables.map(t => t.name || t).join(', ') : (db.tables_count || 'N/A') + ' table(s)'}</td>
                </tr>
            `).join('')}
        </table>
        ` : ''}
    </div>
    `;
}).join('')}
` : '<p>Aucun r&eacute;sultat SQLMap disponible pour cet h&ocirc;te.</p>'}

<h2>6. Chain of Kill - Analyse Cyber Kill Chain</h2>
<p>Analyse de la cha&icirc;ne d\'attaque bas&eacute;e sur les donn&eacute;es collect&eacute;es:</p>

${killChainPhases.map(phase => {
    const matchedTactics = Object.keys(tacticTechniques).filter(t =>
        phase.mitreTactics.some(mt => t.toLowerCase().includes(mt.toLowerCase()))
    );
    const techniques = [];
    matchedTactics.forEach(t => techniques.push(...tacticTechniques[t]));
    const isActive = techniques.length > 0;

    return `
        <div class="phase ${isActive ? 'phase-active' : ''}">
            <h3>${phase.name} ${isActive ? '✅ Détecté' : '⏳ Non observé'}</h3>
            <p><em>${phase.description}</em></p>
            ${techniques.length > 0 ? `
                <table>
                    <tr><th>Technique</th><th>ID</th><th>Description</th></tr>
                    ${techniques.map(t => `
                        <tr>
                            <td><strong>${t.technique_name || t.technique || 'N/A'}</strong></td>
                            <td>${t.technique_id || 'N/A'}</td>
                            <td>${t.description || '-'}</td>
                        </tr>
                    `).join('')}
                </table>
            ` : '<p style="color:#666;">Aucune technique MITRE observ&eacute;e pour cette phase.</p>'}
        </div>
    `;
}).join('')}

<h2>7. Techniques MITRE ATT&CK - D&eacute;tail</h2>
${mitreMappings.length > 0 ? `
<table>
    <tr><th>Tactique</th><th>Technique</th><th>ID</th><th>Description</th></tr>
    ${mitreMappings.map(m => `
        <tr>
            <td>${m.tactic || 'N/A'}</td>
            <td><strong>${m.technique_name || m.technique || 'N/A'}</strong></td>
            <td>${m.technique_id || 'N/A'}</td>
            <td>${m.description || '-'}</td>
        </tr>
    `).join('')}
</table>
` : '<p>Aucune technique MITRE ATT&CK identifi&eacute;e.</p>'}

<div class="footer">
    <p>Rapport g&eacute;n&eacute;r&eacute; le ${now} par NetworkRecon</p>
    <p>Ce document est confidentiel. Destin&eacute; &agrave; un usage de s&eacute;curit&eacute; autoris&eacute; uniquement.</p>
</div>

</body>
</html>
        `;

        // Download as .doc
        const blob = new Blob([html], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `rapport-${host.ip_address}-${new Date().toISOString().slice(0, 10)}.doc`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showToast('Rapport téléchargé');
    },

    /**
     * Copy SSH connection command to clipboard
     */
    async copySshCommand(host, port, username) {
        const sshCmd = port === 22
            ? `ssh ${username}@${host}`
            : `ssh -p ${port} ${username}@${host}`;

        try {
            await navigator.clipboard.writeText(sshCmd);
            this.showToast(`Copié: ${sshCmd}`);
        } catch (e) {
            // Fallback for older browsers
            const ta = document.createElement('textarea');
            ta.value = sshCmd;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            this.showToast(`Copié: ${sshCmd}`);
        }
    },

    /**
     * Show a temporary toast notification
     */
    showToast(message) {
        const existing = document.getElementById('host-toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.id = 'host-toast';
        toast.className = 'fixed bottom-4 right-4 z-50 bg-emerald-600 text-white px-4 py-2 rounded-lg shadow-lg text-sm font-medium flex items-center gap-2';
        toast.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            ${message}
        `;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 2000);
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
