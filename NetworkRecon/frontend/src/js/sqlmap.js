/**
 * NetworkRecon - SQLMap Module
 * Gère les campagnes de test d'injection SQL via SQLMap.
 */

const Sqlmap = {
    campaigns: [],
    progressIntervals: {},

    /**
     * Render the main SQLMap view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getLoadingSkeleton();

        try {
            const campaigns = await api.getSqlmapCampaigns({ limit: 50 });
            this.campaigns = campaigns;
            app.innerHTML = this.getHTML(campaigns);
            this.startProgressPolling();
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Render campaign detail
     */
    async renderDetail(campaignId) {
        const app = document.getElementById('app');
        app.innerHTML = this.getLoadingSkeleton();

        try {
            const campaign = await api.getSqlmapCampaign(campaignId);
            app.innerHTML = this.getDetailHTML(campaign);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Start polling for running campaigns
     */
    startProgressPolling() {
        this.stopProgressPolling();

        const running = this.campaigns.filter(
            c => c.status === 'pending' || c.status === 'running'
        );

        running.forEach(campaign => {
            this.progressIntervals[campaign._id] = setInterval(
                () => this.refreshCampaign(campaign._id),
                3000
            );
        });
    },

    stopProgressPolling() {
        Object.values(this.progressIntervals).forEach(clearInterval);
        this.progressIntervals = {};
    },

    async refreshCampaign(campaignId) {
        try {
            const campaign = await api.getSqlmapCampaign(campaignId);
            const idx = this.campaigns.findIndex(c => c._id === campaignId);
            if (idx !== -1) this.campaigns[idx] = campaign;

            // Update DOM
            const el = document.getElementById(`sqlmap-row-${campaignId}`);
            if (el) {
                el.outerHTML = this.getCampaignRow(campaign);
            }

            if (campaign.status !== 'running' && campaign.status !== 'pending') {
                if (this.progressIntervals[campaignId]) {
                    clearInterval(this.progressIntervals[campaignId]);
                    delete this.progressIntervals[campaignId];
                }
            }
        } catch (e) {
            console.error('Erreur refresh SQLMap:', e);
        }
    },

    /**
     * Create a new campaign
     */
    async showCreateModal() {
        const app = document.getElementById('app');
        app.innerHTML = this.getCreateFormHTML();
    },

    async submitCampaign(formData) {
        try {
            const data = {
                name: formData.get('name'),
                target_url: formData.get('target_url'),
                level: parseInt(formData.get('level') || '1'),
                risk: parseInt(formData.get('risk') || '1'),
                techniques: formData.get('techniques') || 'BEUST',
                dbms: formData.get('dbms') || null,
                tamper: formData.get('tamper') || null,
                threads: parseInt(formData.get('threads') || '1'),
                depth_crawl: parseInt(formData.get('depth_crawl') || '1'),
                forms: formData.get('forms') === 'on',
                random_agent: formData.get('random_agent') !== 'off',
                data: formData.get('data') || null,
                cookie: formData.get('cookie') || null,
            };

            const campaign = await api.createSqlmapCampaign(data);
            this.campaigns.unshift(campaign);
            this.render();
        } catch (error) {
            alert('Erreur: ' + (error.message || 'Impossible de créer la campagne'));
        }
    },

    async deleteCampaign(campaignId) {
        if (!confirm('Supprimer cette campagne SQLMap ?')) return;
        try {
            await api.deleteSqlmapCampaign(campaignId);
            this.campaigns = this.campaigns.filter(c => c._id !== campaignId);
            if (this.progressIntervals[campaignId]) {
                clearInterval(this.progressIntervals[campaignId]);
                delete this.progressIntervals[campaignId];
            }
            this.render();
        } catch (error) {
            alert('Erreur: ' + error.message);
        }
    },

    async cancelCampaign(campaignId) {
        if (!confirm('Annuler cette campagne SQLMap ?')) return;
        try {
            await api.cancelSqlmapCampaign(campaignId);
            this.render();
        } catch (error) {
            alert('Erreur: ' + error.message);
        }
    },

    // ===================== HTML Generators =====================

    getLoadingSkeleton() {
        return `
            <div class="animate-fade-in space-y-4">
                <div class="flex items-center justify-between mb-6">
                    <div class="loading-skeleton w-48 h-8"></div>
                    <div class="loading-skeleton w-40 h-10"></div>
                </div>
                <div class="card">
                    <div class="card-body">
                        ${Array(3).fill('').map(() => `
                            <div class="flex items-center gap-4 p-4 border-b border-surface-700 last:border-0">
                                <div class="loading-skeleton w-3 h-3 rounded-full"></div>
                                <div class="flex-1">
                                    <div class="loading-skeleton w-48 h-5 mb-2"></div>
                                    <div class="loading-skeleton w-64 h-4"></div>
                                </div>
                                <div class="loading-skeleton w-20 h-6 rounded-full"></div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    getHTML(campaigns) {
        return `
            <div class="animate-fade-in space-y-4">
                <div class="flex items-center justify-between">
                    <div>
                        <h2 class="text-xl font-bold text-white">SQLMap - Injection SQL</h2>
                        <p class="text-sm text-surface-400 mt-1">Teste les paramètres URL/POST pour les vulnérabilités SQL injection</p>
                    </div>
                    <button onclick="Sqlmap.showCreateModal()" class="btn btn-primary">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                        </svg>
                        Nouvelle campagne
                    </button>
                </div>

                <div class="card">
                    <div class="card-body p-0">
                        ${campaigns.length ? `
                            <div class="divide-y divide-surface-700">
                                ${campaigns.map(c => this.getCampaignRow(c)).join('')}
                            </div>
                        ` : `
                            <div class="empty-state">
                                <svg class="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2 1 3 3 3h10c2 0 3-1 3-3V7c0-2-1-3-3-3H7C5 4 4 5 4 7z"/>
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-3-3v6"/>
                                </svg>
                                <h3>Aucune campagne SQLMap</h3>
                                <p>Lancez votre premier test d'injection SQL.</p>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        `;
    },

    getCampaignRow(c) {
        const statusColors = {
            pending: 'bg-surface-600 text-surface-300',
            running: 'bg-blue-500/20 text-blue-400',
            completed: 'bg-emerald-500/20 text-emerald-400',
            failed: 'bg-red-500/20 text-red-400',
        };
        const statusLabels = {
            pending: 'En attente',
            running: 'En cours',
            completed: 'Terminé',
            failed: 'Échoué',
        };

        const date = new Date(c.created_at).toLocaleString('fr-FR', {
            day: '2-digit', month: 'short', year: 'numeric',
            hour: '2-digit', minute: '2-digit',
        });

        const isRunning = c.status === 'running' || c.status === 'pending';
        const vulns = c.vulnerabilities_count || 0;
        const vulnColor = vulns > 0 ? 'text-red-400' : 'text-emerald-400';

        return `
            <div id="sqlmap-row-${c._id}" class="flex items-center gap-4 p-4 hover:bg-surface-700/30 transition-colors">
                <span class="w-3 h-3 rounded-full shrink-0 ${
                    c.status === 'completed' ? 'bg-emerald-500' :
                    c.status === 'running' ? 'bg-blue-500 animate-pulse' :
                    c.status === 'failed' ? 'bg-red-500' : 'bg-surface-500'
                }"></span>

                <div class="flex-1 min-w-0">
                    <div class="font-medium text-white truncate">${this.esc(c.name)}</div>
                    <div class="text-sm text-surface-400 font-mono truncate">${this.esc(c.target_url)}</div>
                    <div class="text-xs text-surface-500 mt-0.5">
                        ${date}
                        <span class="mx-1">•</span>
                        Niveau ${c.config?.level || 1} / Risque ${c.config?.risk || 1}
                        ${c.config?.dbms ? `<span class="mx-1">•</span>${c.config.dbms}` : ''}
                    </div>
                </div>

                ${isRunning ? `
                    <div class="text-right shrink-0">
                        <div class="text-xs text-blue-400 font-medium">En cours...</div>
                    </div>
                ` : `
                    <div class="text-right shrink-0">
                        <div class="text-sm font-medium ${vulnColor}">
                            ${vulns} vulnérabilité${vulns !== 1 ? 's' : ''}
                        </div>
                    </div>
                `}

                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusColors[c.status] || 'bg-surface-700 text-surface-400'}">
                    ${statusLabels[c.status] || c.status}
                </span>

                <div class="flex items-center gap-1 shrink-0">
                    ${isRunning ? `
                        <button onclick="Sqlmap.cancelCampaign('${c._id}')" class="p-1.5 rounded text-surface-400 hover:text-amber-400 hover:bg-amber-500/10 transition-colors" title="Annuler">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                            </svg>
                        </button>
                    ` : ''}
                    <button onclick="Sqlmap.deleteCampaign('${c._id}')" class="p-1.5 rounded text-surface-400 hover:text-red-400 hover:bg-red-500/10 transition-colors" title="Supprimer">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                        </svg>
                    </button>
                </div>
            </div>
        `;
    },

    getCreateFormHTML() {
        return `
            <div class="animate-fade-in max-w-2xl mx-auto">
                <div class="flex items-center gap-3 mb-6">
                    <a href="#sqlmap" class="p-2 rounded-lg hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                        </svg>
                    </a>
                    <h2 class="text-xl font-bold text-white">Nouvelle campagne SQLMap</h2>
                </div>

                <form onsubmit="event.preventDefault(); Sqlmap.submitCampaign(new FormData(this));" class="space-y-4">
                    <div class="card">
                        <div class="card-header"><h3 class="font-semibold text-white">Cible</h3></div>
                        <div class="card-body space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-surface-300 mb-1">Nom de la campagne *</label>
                                <input type="text" name="name" required class="form-input w-full" placeholder="Ex: Test injection SQL - Site interne">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-surface-300 mb-1">URL cible *</label>
                                <input type="url" name="target_url" required class="form-input w-full font-mono" placeholder="http://192.168.2.100/page?id=1">
                                <p class="text-xs text-surface-500 mt-1">Incluez les paramètres GET/POST à tester</p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-surface-300 mb-1">Données POST (optionnel)</label>
                                <input type="text" name="data" class="form-input w-full font-mono" placeholder="user=admin&pass=123">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-surface-300 mb-1">Cookie (optionnel)</label>
                                <input type="text" name="cookie" class="form-input w-full font-mono" placeholder="session=abc123; token=xyz">
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header"><h3 class="font-semibold text-white">Configuration SQLMap</h3></div>
                        <div class="card-body space-y-4">
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium text-surface-300 mb-1">Niveau (1-5)</label>
                                    <select name="level" class="form-input w-full">
                                        <option value="1" selected>1 - Basique</option>
                                        <option value="2">2 - Intermédiaire</option>
                                        <option value="3">3 - Avancé</option>
                                        <option value="4">4 - Expert</option>
                                        <option value="5">5 - Maximum</option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-surface-300 mb-1">Risque (1-3)</label>
                                    <select name="risk" class="form-input w-full">
                                        <option value="1" selected>1 - sûr</option>
                                        <option value="2">2 - moyen</option>
                                        <option value="3">3 - agressif</option>
                                    </select>
                                </div>
                            </div>

                            <div>
                                <label class="block text-sm font-medium text-surface-300 mb-1">Techniques</label>
                                <input type="text" name="techniques" class="form-input w-full" value="BEUST" placeholder="BEUST">
                                <p class="text-xs text-surface-500 mt-1">B=Boolean, E=Error, U=Union, S=Stacked, T=Time, I=Inline</p>
                            </div>

                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium text-surface-300 mb-1">DBMS (optionnel)</label>
                                    <select name="dbms" class="form-input w-full">
                                        <option value="">Auto-détection</option>
                                        <option value="mysql">MySQL</option>
                                        <option value="postgresql">PostgreSQL</option>
                                        <option value="mssql">Microsoft SQL Server</option>
                                        <option value="oracle">Oracle</option>
                                        <option value="sqlite">SQLite</option>
                                        <option value="mariadb">MariaDB</option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-surface-300 mb-1">Threads (1-10)</label>
                                    <input type="number" name="threads" class="form-input w-full" value="1" min="1" max="10">
                                </div>
                            </div>

                            <div>
                                <label class="block text-sm font-medium text-surface-300 mb-1">Scripts Tamper (optionnel)</label>
                                <input type="text" name="tamper" class="form-input w-full" placeholder="space2comment,between">
                                <p class="text-xs text-surface-500 mt-1">Séparés par des virgules</p>
                            </div>

                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium text-surface-300 mb-1">Crawl depth</label>
                                    <input type="number" name="depth_crawl" class="form-input w-full" value="1" min="0" max="5">
                                </div>
                                <div class="flex items-end gap-4 pb-1">
                                    <label class="flex items-center gap-2 cursor-pointer">
                                        <input type="checkbox" name="forms" class="w-4 h-4 rounded">
                                        <span class="text-sm text-surface-300">Tester les formulaires</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="flex gap-3 justify-end">
                        <a href="#sqlmap" class="btn btn-secondary">Annuler</a>
                        <button type="submit" class="btn btn-primary">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                            Lancer le scan
                        </button>
                    </div>
                </form>
            </div>
        `;
    },

    getDetailHTML(c) {
        const statusColors = {
            pending: 'bg-surface-600 text-surface-300',
            running: 'bg-blue-500/20 text-blue-400',
            completed: 'bg-emerald-500/20 text-emerald-400',
            failed: 'bg-red-500/20 text-red-400',
        };
        const statusLabels = {
            pending: 'En attente',
            running: 'En cours',
            completed: 'Terminé',
            failed: 'Échoué',
        };

        const result = c.results?.[0];
        const vulns = result?.vulnerabilities || [];
        const databases = result?.databases || [];

        return `
            <div class="animate-fade-in space-y-4">
                <div class="flex items-center gap-3 mb-2">
                    <a href="#sqlmap" class="p-2 rounded-lg hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                        </svg>
                    </a>
                    <h2 class="text-xl font-bold text-white">${this.esc(c.name)}</h2>
                    <span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusColors[c.status]}">
                        ${statusLabels[c.status]}
                    </span>
                </div>

                <div class="card">
                    <div class="card-body">
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div>
                                <div class="text-surface-400">URL cible</div>
                                <div class="text-white font-mono text-xs mt-1 break-all">${this.esc(c.target_url)}</div>
                            </div>
                            <div>
                                <div class="text-surface-400">Niveau / Risque</div>
                                <div class="text-white mt-1">${c.config?.level || 1} / ${c.config?.risk || 1}</div>
                            </div>
                            <div>
                                <div class="text-surface-400">Techniques</div>
                                <div class="text-white mt-1">${c.config?.techniques || 'BEUST'}</div>
                            </div>
                            <div>
                                <div class="text-surface-400">DBMS</div>
                                <div class="text-white mt-1">${result?.dbms || 'Non détecté'}</div>
                            </div>
                        </div>
                    </div>
                </div>

                ${vulns.length > 0 ? `
                    <div class="card border border-red-500/30">
                        <div class="card-header">
                            <h3 class="font-semibold text-red-400">Vulnérabilités SQL Injection (${vulns.length})</h3>
                        </div>
                        <div class="card-body p-0">
                            <div class="divide-y divide-surface-700">
                                ${vulns.map(v => `
                                    <div class="p-4 space-y-2">
                                        <div class="flex items-center gap-3">
                                            <svg class="w-5 h-5 text-red-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                                            </svg>
                                            <div>
                                                <span class="text-white font-medium">Paramètre: <code class="text-red-300">${this.esc(v.parameter)}</code></span>
                                                <span class="text-surface-400 ml-2">(${this.esc(v.injection_type)})</span>
                                            </div>
                                        </div>
                                        <div class="ml-8">
                                            <div class="text-sm text-surface-300">${this.esc(v.title)}</div>
                                            ${v.payload ? `<div class="text-xs text-surface-500 font-mono mt-1 break-all">Payload: ${this.esc(v.payload)}</div>` : ''}
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                ` : ''}

                ${databases.length > 0 ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Bases de données (${databases.length})</h3>
                        </div>
                        <div class="card-body p-0">
                            <div class="divide-y divide-surface-700">
                                ${databases.map(db => `
                                    <div class="flex items-center gap-3 p-4">
                                        <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2 1 3 3 3h10c2 0 3-1 3-3V7c0-2-1-3-3-3H7C5 4 4 5 4 7z"/>
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-3-3v6"/>
                                        </svg>
                                        <div>
                                            <div class="text-white font-medium">${this.esc(db.name)}</div>
                                            <div class="text-xs text-surface-400">${db.tables_count} table(s)</div>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                ` : ''}

                ${c.error_message ? `
                    <div class="card border border-red-500/30">
                        <div class="card-body">
                            <div class="flex items-center gap-3">
                                <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                </svg>
                                <div>
                                    <div class="text-red-400 font-medium">Erreur</div>
                                    <div class="text-sm text-surface-300">${this.esc(c.error_message)}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                ` : ''}

                ${result?.raw_output ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Sortie brute SQLMap</h3>
                        </div>
                        <div class="card-body">
                            <pre class="bg-surface-900 rounded p-4 text-xs text-surface-300 overflow-x-auto max-h-96 overflow-y-auto font-mono">${this.esc(result.raw_output)}</pre>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    },

    getErrorHTML(error) {
        return `
            <div class="animate-fade-in space-y-4">
                <div class="card border border-red-500/30">
                    <div class="card-body">
                        <div class="flex items-center gap-3">
                            <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                            <div>
                                <h3 class="font-semibold text-white">Erreur de chargement</h3>
                                <p class="text-sm text-surface-400">${error.message || 'Erreur inconnue'}</p>
                            </div>
                        </div>
                    </div>
                </div>
                <button onclick="Sqlmap.render()" class="btn btn-primary">Réessayer</button>
            </div>
        `;
    },

    esc(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    },
};
