/**
 * NetworkRecon - Campaigns Module
 * Manages scan campaigns: list, create, view details, control
 */

const Campaigns = {
    refreshInterval: null,
    currentCampaign: null,

    /**
     * Render the campaigns list view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getListLoadingSkeleton();

        try {
            const campaigns = await api.getCampaigns({ limit: 100 });
            app.innerHTML = this.getListHTML(campaigns);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
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

        return `
            <a href="#campaigns/${campaign._id}" class="flex items-center gap-4 p-4 hover:bg-surface-700/50 transition-colors cursor-pointer">
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
        const resultsCount = campaign.results?.length || 0;
        const hostsFound = campaign.results?.reduce((sum, r) => sum + (r.hosts_found?.length || 0), 0) || 0;

        return `
            <div class="animate-fade-in space-y-6">
                <!-- Header -->
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-4">
                        <a href="#campaigns" class="p-2 rounded-lg hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                            </svg>
                        </a>
                        <div>
                            <h2 class="text-xl font-bold text-white">${this.escapeHtml(campaign.name)}</h2>
                            <div class="text-sm text-surface-400">${date}</div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        ${campaign.status === 'running' ? `
                            <button onclick="Campaigns.pauseCampaign('${campaign._id || campaign.id}')" class="btn btn-secondary btn-sm">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                </svg>
                                Pause
                            </button>
                            <button onclick="Campaigns.cancelCampaign('${campaign._id || campaign.id}')" class="btn btn-danger btn-sm">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                </svg>
                                Annuler
                            </button>
                        ` : ''}
                        ${campaign.status === 'paused' ? `
                            <button onclick="Campaigns.resumeCampaign('${campaign._id || campaign.id}')" class="btn btn-success btn-sm">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                </svg>
                                Reprendre
                            </button>
                        ` : ''}
                        <button onclick="Campaigns.deleteCampaign('${campaign._id || campaign.id}')" class="btn btn-danger btn-sm">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                            </svg>
                        </button>
                    </div>
                </div>

                <!-- Info Cards -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div class="stat-card">
                        <div class="stat-label">Cible</div>
                        <div class="font-mono text-white mt-1">${this.escapeHtml(target)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Type de scan</div>
                        <div class="text-white mt-1 capitalize">${this.getScanTypeLabel(scanType)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Hôtes découverts</div>
                        <div class="stat-value text-white text-xl">${hostsFound}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Résultats</div>
                        <div class="stat-value text-white text-xl">${resultsCount}</div>
                    </div>
                </div>

                <!-- Progress -->
                ${campaign.status === 'running' || campaign.status === 'paused' ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Progression</h3>
                            <span id="campaign-status-badge" class="status-badge status-${campaign.status}">
                                <span class="status-dot ${campaign.status}"></span>
                                ${this.getStatusLabel(campaign.status)}
                            </span>
                        </div>
                        <div class="card-body">
                            <div class="flex items-center gap-4">
                                <div class="progress-bar flex-1">
                                    <div id="campaign-progress" class="progress-bar-fill" style="width: 0%"></div>
                                </div>
                                <span id="campaign-progress-text" class="text-sm text-surface-400 font-medium">0%</span>
                            </div>
                        </div>
                    </div>
                ` : ''}

                <!-- Campaign Description -->
                ${campaign.description ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Description</h3>
                        </div>
                        <div class="card-body">
                            <p class="text-surface-300">${this.escapeHtml(campaign.description)}</p>
                        </div>
                    </div>
                ` : ''}

                <!-- Results -->
                ${campaign.results?.length ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Résultats des scans</h3>
                        </div>
                        <div class="card-body p-0">
                            <div class="overflow-x-auto">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Cible</th>
                                            <th>Hôtes</th>
                                            <th>Début</th>
                                            <th>Fin</th>
                                            <th>Statut</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${campaign.results.map(r => `
                                            <tr>
                                                <td class="font-mono text-sm">${this.escapeHtml(r.target)}</td>
                                                <td>${r.hosts_found?.length || 0}</td>
                                                <td class="text-surface-400 text-sm">${r.start_time ? new Date(r.start_time).toLocaleString('fr-FR') : '-'}</td>
                                                <td class="text-surface-400 text-sm">${r.end_time ? new Date(r.end_time).toLocaleString('fr-FR') : '-'}</td>
                                                <td><span class="status-badge status-${r.status}">${this.getStatusLabel(r.status)}</span></td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                ` : ''}
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
