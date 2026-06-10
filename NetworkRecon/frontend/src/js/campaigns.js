/**
 * NetworkRecon - Campaigns Module
 * Manages scan campaigns: list, create, view details, control
 */

const Campaigns = {
    refreshInterval: null,
    listRefreshInterval: null,
    currentCampaign: null,

    /**
     * Render the campaigns list view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getListLoadingSkeleton();

        try {
            const campaigns = await api.getCampaigns({ limit: 100 });
            this.campaigns = campaigns;
            app.innerHTML = this.getListHTML(campaigns);
            this.startListPolling();
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Start polling for list updates (running campaigns)
     */
    startListPolling() {
        this.stopListPolling();

        const runningCampaigns = this.campaigns?.filter(
            c => c.status === 'running' || c.status === 'pending'
        ) || [];

        if (runningCampaigns.length === 0) return;

        this.listRefreshInterval = setInterval(async () => {
            try {
                const campaigns = await api.getCampaigns({ limit: 100 });
                this.campaigns = campaigns;

                // Update each running campaign row
                for (const c of campaigns) {
                    const row = document.getElementById(`campaign-row-${c._id}`);
                    if (row) {
                        row.outerHTML = this.getCampaignRow(c);
                    }
                }

                // Stop polling if no more running
                const stillRunning = campaigns.filter(
                    c => c.status === 'running' || c.status === 'pending'
                );
                if (stillRunning.length === 0) {
                    this.stopListPolling();
                }
            } catch (e) {
                console.error('Erreur polling liste campagnes:', e);
            }
        }, 3000);
    },

    /**
     * Stop list polling
     */
    stopListPolling() {
        if (this.listRefreshInterval) {
            clearInterval(this.listRefreshInterval);
            this.listRefreshInterval = null;
        }
    },

    /**
     * Render a specific campaign detail view
     */
    async renderDetail(campaignId) {
        const app = document.getElementById('app');
        app.innerHTML = this.getDetailLoadingSkeleton();

        try {
            const campaign = await api.getCampaign(campaignId);
            this.currentCampaign = campaign;
            app.innerHTML = this.getDetailHTML(campaign);

            if (campaign.status === 'running') {
                this.startStatusPolling(campaignId);
            }
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Start polling for campaign status updates
     */
    startStatusPolling(campaignId) {
        this.stopStatusPolling();
        this.refreshInterval = setInterval(async () => {
            try {
                const status = await api.getCampaignStatus(campaignId);
                const progressBar = document.querySelector('#campaign-progress');
                const progressText = document.querySelector('#campaign-progress-text');
                const statusBadge = document.querySelector('#campaign-status-badge');

                if (progressBar) {
                    progressBar.style.width = `${status.progress}%`;
                }
                if (progressText) {
                    progressText.textContent = `${status.progress}%`;
                }
                if (statusBadge) {
                    statusBadge.innerHTML = `<span class="status-dot ${status.status}"></span> ${this.getStatusLabel(status.status)}`;
                }

                if (status.status !== 'running') {
                    this.stopStatusPolling();
                    this.renderDetail(campaignId);
                }
            } catch (error) {
                console.error('Error polling campaign status:', error);
            }
        }, 2000);
    },

    /**
     * Stop status polling
     */
    stopStatusPolling() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
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
                    <div class="loading-skeleton w-32 h-10"></div>
                </div>
                <div class="card">
                    <div class="card-body">
                        ${Array(5).fill('').map(() => `
                            <div class="flex items-center gap-4 p-4 border-b border-surface-700 last:border-0">
                                <div class="loading-skeleton w-3 h-3 rounded-full"></div>
                                <div class="flex-1">
                                    <div class="loading-skeleton w-48 h-5 mb-2"></div>
                                    <div class="loading-skeleton w-32 h-4"></div>
                                </div>
                                <div class="loading-skeleton w-20 h-6 rounded-full"></div>
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
    getListHTML(campaigns) {
        return `
            <div class="animate-fade-in space-y-4">
                <div class="flex items-center justify-between">
                    <h2 class="text-xl font-bold text-white">Campagnes de scan</h2>
                    <button onclick="showNewScanModal()" class="btn btn-primary">
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
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                                </svg>
                                <h3>Aucune campagne</h3>
                                <p>Créez votre première campagne de scan pour commencer.</p>
                                <button onclick="showNewScanModal()" class="btn btn-primary mt-4">Créer une campagne</button>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get a single campaign row
     */
    getCampaignRow(campaign) {
        const date = new Date(campaign.created_at).toLocaleDateString('fr-FR', {
            day: 'numeric',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });

        const target = campaign.targets?.[0]?.ip_range || 'N/A';
        const isRunning = campaign.status === 'running' || campaign.status === 'pending';
        const progress = campaign.progress || 0;

        return `
            <a id="campaign-row-${campaign._id}" href="#campaigns/${campaign._id}" onclick="event.preventDefault(); Router.navigate('campaigns/${campaign._id}');" class="flex items-center gap-4 p-4 hover:bg-surface-700/50 transition-colors cursor-pointer">
                <span class="status-dot ${campaign.status}"></span>
                <div class="flex-1 min-w-0">
                    <div class="font-medium text-white truncate">${this.escapeHtml(campaign.name)}</div>
                    <div class="text-sm text-surface-400 flex items-center gap-2">
                        <span class="font-mono">${this.escapeHtml(target)}</span>
                        <span>•</span>
                        <span>${date}</span>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    ${isRunning ? `
                        <div class="flex items-center gap-2">
                            <div class="w-16 h-1.5 bg-surface-700 rounded-full overflow-hidden">
                                <div class="h-full bg-blue-500 rounded-full transition-all duration-500" style="width: ${progress}%"></div>
                            </div>
                            <span class="text-xs font-mono text-blue-400 w-10 text-right">${Math.round(progress)}%</span>
                        </div>
                    ` : ''}
                    <span class="status-badge status-${campaign.status}">
                        ${this.getStatusLabel(campaign.status)}
                    </span>
                    <svg class="w-5 h-5 text-surface-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                    </svg>
                </div>
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
                        <div class="loading-skeleton w-64 h-7 mb-2"></div>
                        <div class="loading-skeleton w-32 h-4"></div>
                    </div>
                </div>
                <div class="loading-skeleton w-full h-32 rounded-xl"></div>
                <div class="loading-skeleton w-full h-64 rounded-xl"></div>
            </div>
        `;
    },

    /**
     * Get detail HTML
     */
    getDetailHTML(campaign) {
        const date = new Date(campaign.created_at).toLocaleString('fr-FR');
        const target = campaign.targets?.[0]?.ip_range || 'N/A';
        const scanType = campaign.config?.scan_type || 'full';
        const hostsFound = campaign.results?.reduce((sum, r) => sum + (r.hosts_found?.length || 0), 0) || 0;

        // Collecter tous les hôtes uniques depuis les résultats
        const hostsMap = new Map();
        if (campaign.results) {
            for (const r of campaign.results) {
                if (r.hosts_found) {
                    for (const h of r.hosts_found) {
                        const ip = h.ip_address || h.ip || h;
                        if (!hostsMap.has(ip)) {
                            hostsMap.set(ip, {
                                ip: ip,
                                hostname: h.hostname || '',
                                os: h.os_detection || h.os || '',
                                status: h.status || 'up',
                                ports: h.ports || [],
                            });
                        }
                    }
                }
            }
        }
        const hosts = Array.from(hostsMap.values());

        return `
            <div class="animate-fade-in space-y-6">
                <!-- Back button -->
                <div class="flex items-center gap-3">
                    <a href="#campaigns" onclick="event.preventDefault(); Router.navigate('campaigns');" class="p-2 rounded-lg hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                        </svg>
                    </a>
                    <span class="text-surface-400 text-sm">Retour aux campagnes</span>
                </div>

                <!-- Banner campagne -->
                <div class="card border border-primary-500/30 bg-primary-500/5">
                    <div class="card-body">
                        <div class="flex items-start justify-between">
                            <div class="space-y-3">
                                <div class="flex items-center gap-3">
                                    <h2 class="text-2xl font-bold text-white">${this.escapeHtml(campaign.name)}</h2>
                                    <span class="status-badge status-${campaign.status}">
                                        ${this.getStatusLabel(campaign.status)}
                                    </span>
                                </div>
                                ${campaign.description ? `
                                    <p class="text-surface-300 text-sm">${this.escapeHtml(campaign.description)}</p>
                                ` : ''}
                                <div class="flex flex-wrap gap-4 text-sm">
                                    <div class="flex items-center gap-2">
                                        <svg class="w-4 h-4 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                                        </svg>
                                        <span class="text-surface-400">Date:</span>
                                        <span class="text-white">${date}</span>
                                    </div>
                                    <div class="flex items-center gap-2">
                                        <svg class="w-4 h-4 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"/>
                                        </svg>
                                        <span class="text-surface-400">Cible:</span>
                                        <span class="text-white font-mono">${this.escapeHtml(target)}</span>
                                    </div>
                                    <div class="flex items-center gap-2">
                                        <svg class="w-4 h-4 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
                                        </svg>
                                        <span class="text-surface-400">Type:</span>
                                        <span class="text-white capitalize">${this.getScanTypeLabel(scanType)}</span>
                                    </div>
                                    <div class="flex items-center gap-2">
                                        <svg class="w-4 h-4 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/>
                                        </svg>
                                        <span class="text-surface-400">Hôtes:</span>
                                        <span class="text-white font-bold">${hostsFound}</span>
                                    </div>
                                </div>
                            </div>
                            <div class="flex items-center gap-2">
                                ${campaign.status === 'running' ? `
                                    <button onclick="Campaigns.pauseCampaign('${campaign._id || campaign.id}')" class="px-3 py-1.5 rounded-lg bg-surface-700 hover:bg-surface-600 text-surface-300 hover:text-white transition-colors text-sm">
                                        Pause
                                    </button>
                                    <button onclick="Campaigns.cancelCampaign('${campaign._id || campaign.id}')" class="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 hover:text-red-300 transition-colors text-sm">
                                        Annuler
                                    </button>
                                ` : ''}
                                ${campaign.status === 'paused' ? `
                                    <button onclick="Campaigns.resumeCampaign('${campaign._id || campaign.id}')" class="px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 hover:text-emerald-300 transition-colors text-sm">
                                        Reprendre
                                    </button>
                                ` : ''}
                                <button onclick="Campaigns.deleteCampaign('${campaign._id || campaign.id}')" class="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 hover:text-red-300 transition-colors text-sm">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Progress (si en cours) -->
                ${campaign.status === 'running' || campaign.status === 'paused' ? `
                    <div class="card">
                        <div class="card-body">
                            <div class="flex items-center gap-4">
                                <div class="progress-bar flex-1">
                                    <div id="campaign-progress" class="progress-bar-fill" style="width: ${campaign.progress || 0}%"></div>
                                </div>
                                <span id="campaign-progress-text" class="text-sm text-surface-400 font-medium">${Math.round(campaign.progress || 0)}%</span>
                            </div>
                        </div>
                    </div>
                ` : ''}

                <!-- Tableau des hôtes découverts -->
                ${hosts.length > 0 ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Hôtes découverts (${hosts.length})</h3>
                        </div>
                        <div class="card-body p-0">
                            <div class="overflow-x-auto">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>IP</th>
                                            <th>Hostname</th>
                                            <th>Système d'exploitation</th>
                                            <th>Statut</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${hosts.map(h => `
                                            <tr class="cursor-pointer hover:bg-surface-700/50" onclick="Router.navigate('hosts/${h.ip}')">
                                                <td class="font-mono text-sm text-white font-medium">${this.escapeHtml(h.ip)}</td>
                                                <td class="text-surface-300">${this.escapeHtml(h.hostname) || '<span class="text-surface-500 italic">N/A</span>'}</td>
                                                <td class="text-surface-300">${this.escapeHtml(h.os) || '<span class="text-surface-500 italic">Non détecté</span>'}</td>
                                                <td>
                                                    <span class="status-badge status-${h.status === 'up' ? 'completed' : 'failed'}">
                                                        ${h.status === 'up' ? 'Actif' : 'Inactif'}
                                                    </span>
                                                </td>
                                                <td>
                                                    <svg class="w-4 h-4 text-surface-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                                    </svg>
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                ` : `
                    <div class="card">
                        <div class="card-body">
                            <div class="empty-state">
                                <svg class="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/>
                                </svg>
                                <h3>Aucun hôte découvert</h3>
                                <p>En attente des résultats du scan...</p>
                            </div>
                        </div>
                    </div>
                `}
            </div>
        `;
    },

    /**
     * Pause a campaign
     */
    async pauseCampaign(id) {
        try {
            await api.pauseCampaign(id);
            this.renderDetail(id);
        } catch (error) {
            alert('Erreur: ' + error.message);
        }
    },

    /**
     * Resume a campaign
     */
    async resumeCampaign(id) {
        try {
            await api.resumeCampaign(id);
            this.renderDetail(id);
        } catch (error) {
            alert('Erreur: ' + error.message);
        }
    },

    /**
     * Cancel a campaign
     */
    async cancelCampaign(id) {
        if (!confirm('Êtes-vous sûr de vouloir annuler cette campagne ?')) return;
        try {
            await api.cancelCampaign(id);
            this.renderDetail(id);
        } catch (error) {
            alert('Erreur: ' + error.message);
        }
    },

    /**
     * Delete a campaign
     */
    async deleteCampaign(id) {
        if (!confirm('Êtes-vous sûr de vouloir supprimer cette campagne ? Cette action est irréversible.')) return;
        try {
            await api.deleteCampaign(id);
            window.location.hash = '#campaigns';
        } catch (error) {
            alert('Erreur: ' + error.message);
        }
    },

    /**
     * Get status label
     */
    getStatusLabel(status) {
        const labels = {
            pending: 'En attente',
            running: 'En cours',
            completed: 'Terminé',
            failed: 'Échoué',
            cancelled: 'Annulé',
            paused: 'En pause'
        };
        return labels[status] || status;
    },

    /**
     * Get scan type label
     */
    getScanTypeLabel(type) {
        const labels = {
            quick: 'Rapide',
            full: 'Complet',
            stealth: 'Furtif'
        };
        return labels[type] || type;
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
                <button onclick="Campaigns.render()" class="btn btn-primary">Réessayer</button>
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
