/**
 * NetworkRecon - Auth Tests Module
 * Displays brute force attack suggestions based on discovered CVEs
 * and allows launching attacks with one click.
 */

const AuthTests = {
    suggestions: [],
    campaigns: [],
    progressIntervals: {},

    /**
     * Render the main auth tests view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getLoadingSkeleton();

        try {
            const [suggestions, campaigns] = await Promise.all([
                api.getAttackSuggestions(),
                api.getAuthTests({ limit: 20 }).catch(() => []),
            ]);

            this.suggestions = suggestions;
            this.campaigns = campaigns;
            app.innerHTML = this.getHTML(suggestions, campaigns);

            // Start polling for running campaigns
            this.startProgressPolling();
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Start polling progress for running campaigns
     */
    startProgressPolling() {
        // Clear existing intervals
        this.stopProgressPolling();

        // Find running campaigns
        const runningCampaigns = this.campaigns.filter(
            c => c.status === 'pending' || c.status === 'running'
        );

        runningCampaigns.forEach(campaign => {
            this.progressIntervals[campaign._id] = setInterval(
                () => this.updateCampaignProgress(campaign._id),
                1500 // Poll every 1.5 seconds
            );
        });
    },

    /**
     * Stop all progress polling
     */
    stopProgressPolling() {
        Object.values(this.progressIntervals).forEach(clearInterval);
        this.progressIntervals = {};
    },

    /**
     * Update a single campaign's progress in the DOM
     */
    async updateCampaignProgress(campaignId) {
        try {
            const progress = await api.getCampaignProgress(campaignId);
            const progressEl = document.getElementById(`progress-${campaignId}`);
            const progressBarEl = document.getElementById(`progress-bar-${campaignId}`);
            const statusEl = document.getElementById(`status-${campaignId}`);

            if (progressEl) {
                progressEl.textContent = `${progress.percentage}%`;
            }

            if (progressBarEl) {
                const width = Math.max(0, Math.min(100, progress.percentage));
                progressBarEl.style.width = `${width}%`;
                
                // Color based on status
                progressBarEl.className = 'h-full rounded-full transition-all duration-500';
                if (progress.status === 'completed') {
                    progressBarEl.classList.add('bg-emerald-500');
                } else if (progress.status === 'failed') {
                    progressBarEl.classList.add('bg-red-500');
                } else {
                    progressBarEl.classList.add('bg-blue-500');
                }
            }

            if (statusEl) {
                const statusLabels = {
                    pending: 'En attente',
                    running: 'En cours',
                    completed: 'Terminé',
                    failed: 'Échoué',
                };
                statusEl.textContent = statusLabels[progress.status] || progress.status;
            }

            // Update detail info
            const detailEl = document.getElementById(`detail-${campaignId}`);
            if (detailEl && progress.status === 'running') {
                detailEl.textContent = `Cible: ${progress.current_target || '-'} | ${progress.tests_completed}/${progress.total_tests} tests`;
                detailEl.classList.remove('hidden');
            }

            // Stop polling if completed or failed
            if (progress.status === 'completed' || progress.status === 'failed') {
                if (this.progressIntervals[campaignId]) {
                    clearInterval(this.progressIntervals[campaignId]);
                    delete this.progressIntervals[campaignId];
                }

                // Re-fetch la campagne complète pour avoir les résultats
                try {
                    const fullCampaign = await api.getAuthTestCampaign(campaignId);
                    const idx = this.campaigns.findIndex(c => c._id === campaignId);
                    if (idx !== -1) {
                        this.campaigns[idx] = fullCampaign;
                    }
                    // Re-render la ligne de la campagne
                    const rowEl = document.getElementById(`campaign-row-${campaignId}`);
                    if (rowEl) {
                        rowEl.outerHTML = this.getCampaignRow(fullCampaign);
                    }
                } catch (e) {
                    console.error('Erreur re-fetch campaign:', e);
                }
            }
        } catch (error) {
            console.error(`Erreur polling progress ${campaignId}:`, error);
        }
    },

    /**
     * Launch an attack from a suggestion
     */
    async launchAttack(suggestion) {
        const confirmed = confirm(
            `Lancer une attaque brute force ${suggestion.service.toUpperCase()} sur ${suggestion.host_ip}:${suggestion.port} ?\n\n` +
            `Raison: ${suggestion.reason}\n` +
            `CVE: ${suggestion.cve_ids.join(', ') || 'Aucune'}\n\n` +
            `Cette action enverra des tentatives de connexion.`
        );

        if (!confirmed) return;

        try {
            const btn = document.getElementById(`launch-${suggestion.host_ip}-${suggestion.port}`);
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = `
                    <svg class="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                    </svg>
                    Lancé...
                `;
            }

            const campaign = await api.launchFromSuggestion({
                host_ip: suggestion.host_ip,
                service_type: suggestion.service,
                port: suggestion.port,
            });

            // Add to campaigns list
            this.campaigns.unshift(campaign);
            this.updateCampaignsList();

            // Start polling for this new campaign
            this.progressIntervals[campaign._id] = setInterval(
                () => this.updateCampaignProgress(campaign._id),
                1500
            );

            if (btn) {
                btn.innerHTML = `
                    <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                    </svg>
                    Lancé
                `;
            }
        } catch (error) {
            alert('Erreur lors du lancement: ' + (error.message || 'Erreur inconnue'));
            const btn = document.getElementById(`launch-${suggestion.host_ip}-${suggestion.port}`);
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    Lancer
                `;
            }
        }
    },

    /**
     * Update the campaigns list in the DOM
     */
    updateCampaignsList() {
        const container = document.getElementById('campaigns-list');
        if (container) {
            container.innerHTML = this.campaigns.map(c => this.getCampaignRow(c)).join('');
        }
    },

    /**
     * Delete a campaign
     */
    async deleteCampaign(campaignId) {
        if (!confirm('Supprimer cette campagne ?')) return;
        try {
            await api.deleteAuthTestCampaign(campaignId);
            this.campaigns = this.campaigns.filter(c => c._id !== campaignId);
            // Stop polling if running
            if (this.progressIntervals[campaignId]) {
                clearInterval(this.progressIntervals[campaignId]);
                delete this.progressIntervals[campaignId];
            }
            this.updateCampaignsList();
        } catch (error) {
            console.error('Erreur suppression:', error);
        }
    },

    /**
     * Cancel a running campaign
     */
    async cancelCampaign(campaignId) {
        if (!confirm('Annuler cette campagne ?')) return;
        try {
            // Marquer comme annulé localement
            const campaign = this.campaigns.find(c => c._id === campaignId);
            if (campaign) {
                campaign.status = 'failed';
            }
            if (this.progressIntervals[campaignId]) {
                clearInterval(this.progressIntervals[campaignId]);
                delete this.progressIntervals[campaignId];
            }
            this.updateCampaignsList();
        } catch (error) {
            console.error('Erreur annulation:', error);
        }
    },

    /**
     * Get loading skeleton
     */
    getLoadingSkeleton() {
        return `
            <div class="animate-fade-in space-y-6">
                <div class="flex items-center justify-between">
                    <div class="loading-skeleton w-64 h-8"></div>
                    <div class="loading-skeleton w-32 h-10"></div>
                </div>
                <div class="loading-skeleton h-40 rounded-xl"></div>
                <div class="space-y-3">
                    ${Array(4).fill('').map(() => `
                        <div class="loading-skeleton h-24 rounded-xl"></div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    /**
     * Get main HTML
     */
    getHTML(suggestions, campaigns) {
        return `
            <div class="animate-fade-in space-y-6">
                <!-- Header -->
                <div class="flex items-center justify-between">
                    <h2 class="text-xl font-bold text-white">Tests d'authentification</h2>
                    <div class="flex items-center gap-2">
                        <span class="text-surface-400 text-sm">${suggestions.length} attaque(s) suggérée(s)</span>
                    </div>
                </div>

                <!-- Attack Suggestions -->
                ${suggestions.length > 0 ? this.getSuggestionsHTML(suggestions) : this.getNoSuggestionsHTML()}

                <!-- Campaign History -->
                <div class="mt-8">
                    <h3 class="text-lg font-semibold text-white mb-4">Campagnes récentes</h3>
                    <div id="campaigns-list" class="space-y-3">
                        ${campaigns.length > 0
                            ? campaigns.map(c => this.getCampaignRow(c)).join('')
                            : this.getNoCampaignsHTML()
                        }
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get suggestions section HTML
     */
    getSuggestionsHTML(suggestions) {
        // Group by host
        const byHost = {};
        suggestions.forEach(s => {
            if (!byHost[s.host_ip]) byHost[s.host_ip] = [];
            byHost[s.host_ip].push(s);
        });

        return `
            <div class="space-y-4">
                <div class="card border border-amber-500/30 bg-amber-500/5">
                    <div class="card-body">
                        <div class="flex items-center gap-3 mb-3">
                            <div class="w-10 h-10 rounded-lg bg-amber-500/20 flex items-center justify-center">
                                <svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>
                                </svg>
                            </div>
                            <div>
                                <h3 class="font-semibold text-white">Attaques suggérées par les CVE</h3>
                                <p class="text-sm text-surface-400">Basées sur les services ouverts et vulnérabilités détectées</p>
                            </div>
                        </div>
                    </div>
                </div>

                ${Object.entries(byHost).map(([ip, attacks]) => `
                    <div class="card">
                        <div class="card-body p-0">
                            <div class="p-4 border-b border-surface-700">
                                <div class="flex items-center gap-3">
                                    <div class="w-8 h-8 rounded-lg bg-surface-700 flex items-center justify-center">
                                        <svg class="w-4 h-4 text-surface-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/>
                                        </svg>
                                    </div>
                                    <div>
                                        <div class="font-mono text-white font-medium">${ip}</div>
                                        ${attacks[0].hostname ? `<div class="text-xs text-surface-400">${attacks[0].hostname}</div>` : ''}
                                    </div>
                                    <div class="ml-auto">
                                        <span class="px-2 py-1 bg-surface-700 rounded text-xs font-medium text-surface-300">
                                            ${attacks.length} attaque(s)
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div class="divide-y divide-surface-700">
                                ${attacks.map(a => this.getAttackRow(a)).join('')}
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    /**
     * Get a single attack suggestion row
     */
    getAttackRow(suggestion) {
        const severityColors = {
            critical: 'bg-red-500',
            high: 'bg-orange-500',
            medium: 'bg-yellow-500',
            low: 'bg-green-500',
        };
        const severityText = {
            critical: 'Critique',
            high: 'Haute',
            medium: 'Moyenne',
            low: 'Basse',
        };

        return `
            <div class="flex items-center gap-4 p-4 hover:bg-surface-700/30 transition-colors">
                <!-- Severity indicator -->
                <div class="flex-shrink-0">
                    <div class="w-3 h-3 rounded-full ${severityColors[suggestion.severity] || 'bg-surface-500'}" 
                         title="Sévérité: ${severityText[suggestion.severity] || suggestion.severity}"></div>
                </div>

                <!-- Service + Port -->
                <div class="flex-shrink-0 w-24">
                    <div class="flex items-center gap-2">
                        ${this.getServiceIcon(suggestion.service)}
                        <div>
                            <div class="font-mono text-white text-sm font-medium">${suggestion.service.toUpperCase()}</div>
                            <div class="text-xs text-surface-400">port ${suggestion.port}</div>
                        </div>
                    </div>
                </div>

                <!-- Description + CVEs -->
                <div class="flex-1 min-w-0">
                    <div class="text-sm text-white truncate">${suggestion.description}</div>
                    ${suggestion.cve_ids.length > 0 ? `
                        <div class="flex flex-wrap gap-1 mt-1">
                            ${suggestion.cve_ids.slice(0, 3).map(cve => `
                                <span class="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-xs font-mono">${cve}</span>
                            `).join('')}
                            ${suggestion.cve_ids.length > 3 ? `
                                <span class="px-1.5 py-0.5 bg-surface-700 text-surface-400 rounded text-xs">+${suggestion.cve_ids.length - 3}</span>
                            ` : ''}
                        </div>
                    ` : ''}
                </div>

                <!-- Duration -->
                <div class="flex-shrink-0 text-right hidden sm:block">
                    <div class="text-xs text-surface-400">${suggestion.estimated_duration || ''}</div>
                    <div class="text-xs text-surface-500">${suggestion.recommended_wordlist || ''}</div>
                </div>

                <!-- Launch button -->
                <div class="flex-shrink-0">
                    <button id="launch-${suggestion.host_ip}-${suggestion.port}"
                            onclick='AuthTests.launchAttack(${JSON.stringify(suggestion).replace(/'/g, "\\'")})'
                            class="btn-primary flex items-center gap-2 px-3 py-1.5 text-sm">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        Lancer
                    </button>
                </div>
            </div>
        `;
    },

    /**
     * Get service icon SVG
     */
    getServiceIcon(service) {
        const icons = {
            ssh: `<svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>`,
            ftp: `<svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>`,
            smb: `<svg class="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>`,
            rdp: `<svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>`,
            mysql: `<svg class="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>`,
            http: `<svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"/></svg>`,
        };
        return icons[service] || `<svg class="w-5 h-5 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>`;
    },

    /**
     * Get no suggestions HTML
     */
    getNoSuggestionsHTML() {
        return `
            <div class="card">
                <div class="card-body">
                    <div class="empty-state">
                        <svg class="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <h3>Aucune attaque suggérée</h3>
                        <p>Lancez d'abord un scan réseau pour découvrir les hôtes et vulnérabilités.</p>
                        <p class="text-sm text-surface-400 mt-2">Les attaques brute force seront proposées automatiquement en fonction des services ouverts et CVE détectées.</p>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get campaign row HTML
     */
    getCampaignRow(campaign) {
        const statusColors = {
            pending: 'bg-yellow-500/20 text-yellow-400',
            running: 'bg-blue-500/20 text-blue-400',
            completed: 'bg-emerald-500/20 text-emerald-400',
            failed: 'bg-red-500/20 text-red-400',
            cancelled: 'bg-surface-700 text-surface-400',
        };
        const statusLabels = {
            pending: 'En attente',
            running: 'En cours',
            completed: 'Terminé',
            failed: 'Échoué',
            cancelled: 'Annulé',
        };

        const created = campaign.created_at
            ? new Date(campaign.created_at).toLocaleString('fr-FR')
            : '-';

        const isRunning = campaign.status === 'pending' || campaign.status === 'running';

        return `
            <div id="campaign-row-${campaign._id}" class="card hover:bg-surface-700/30 transition-colors">
                <div class="card-body p-4">
                    <div class="flex items-center gap-4">
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center gap-3">
                                <div class="font-medium text-white truncate">${campaign.name || 'Sans nom'}</div>
                                <span id="status-${campaign._id}" class="px-2 py-0.5 rounded-full text-xs font-medium ${statusColors[campaign.status] || 'bg-surface-700 text-surface-400'}">
                                    ${statusLabels[campaign.status] || campaign.status}
                                </span>
                            </div>
                            <div class="text-sm text-surface-400 mt-1">
                                ${campaign.targets?.join(', ') || '-'}
                                <span class="mx-2">•</span>
                                ${campaign.config?.service_type?.toUpperCase() || '?'}
                                <span class="mx-2">•</span>
                                ${created}
                            </div>
                            ${campaign.status === 'completed' || campaign.status === 'failed' ? `
                                <div class="mt-2">
                                    ${this.getCampaignResultsHTML(campaign)}
                                </div>
                            ` : ''}
                            ${isRunning ? `
                                <div class="mt-3">
                                    <div class="flex items-center justify-between mb-1">
                                        <span id="detail-${campaign._id}" class="text-xs text-surface-400">Initialisation...</span>
                                        <span id="progress-${campaign._id}" class="text-xs font-mono text-blue-400 font-medium">0%</span>
                                    </div>
                                    <div class="w-full h-2 bg-surface-700 rounded-full overflow-hidden">
                                        <div id="progress-bar-${campaign._id}" class="h-full rounded-full transition-all duration-500 bg-blue-500" style="width: 0%"></div>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                        <div class="flex items-center gap-1 shrink-0">
                            ${isRunning ? `
                                <button
                                    onclick="AuthTests.cancelCampaign('${campaign._id}')"
                                    class="p-2 rounded text-surface-400 hover:text-amber-400 hover:bg-amber-500/10 transition-colors"
                                    title="Annuler"
                                >
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                    </svg>
                                </button>
                            ` : ''}
                            <button
                                onclick="AuthTests.deleteCampaign('${campaign._id}')"
                                class="p-2 rounded text-surface-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                                title="Supprimer"
                            >
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get detailed results HTML for a completed campaign
     */
    getCampaignResultsHTML(campaign) {
        const results = campaign.results || [];
        if (results.length === 0) return '<div class="text-xs text-surface-400">Aucun résultat</div>';

        // Classifier les résultats
        const successes = results.filter(r => r.success);
        const connectionErrors = results.filter(r => !r.success && (
            (r.error_message || '').includes('Erreur de connexion') ||
            (r.error_message || '').includes('Erreur SSH') ||
            (r.error_message || '').includes('Connection refused') ||
            (r.error_message || '').includes('Connection timed out') ||
            (r.error_message || '').includes('No route to host') ||
            (r.error_message || '').includes('Network is unreachable') ||
            (r.error_message || '').includes('Connection reset') ||
            (r.error_message || '').includes('Connection closed')
        ));
        const authFailures = results.filter(r => !r.success && !connectionErrors.includes(r));

        let html = '<div class="space-y-1.5">';

        // Succès
        if (successes.length > 0) {
            html += successes.map(r => {
                // Extraire le nom d'utilisateur du credential_used (format: "user:***")
                const credParts = (r.credential_used || '').split(':');
                const username = credParts[0] || 'unknown';
                return `
                    <div class="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3 space-y-2">
                        <div class="flex items-center gap-2">
                            <svg class="w-4 h-4 text-emerald-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                            </svg>
                            <span class="text-emerald-400 font-bold text-sm">IDENTIFIANTS TROUVÉS</span>
                        </div>
                        <div class="flex items-center gap-4 text-sm">
                            <div>
                                <span class="text-surface-400">Utilisateur:</span>
                                <span class="text-white font-mono font-medium ml-1">${this.esc(username)}</span>
                            </div>
                            <div>
                                <span class="text-surface-400">Mot de passe:</span>
                                <span class="text-white font-mono font-medium ml-1">${this.esc(r.credential_used?.split(':')[1] || '')}</span>
                            </div>
                        </div>
                        <div class="flex items-center gap-2 text-xs text-surface-400">
                            <span>${r.host_ip}:${r.port}</span>
                            <span>•</span>
                            <span>${r.service.toUpperCase()}</span>
                        </div>
                        <button
                            onclick="AuthTests.openTerminal('${this.esc(r.host_ip)}', ${r.port}, '${this.esc(username)}', '${this.esc((r.credential_plain || '').split(':')[1] || r.credential_used?.split(':')[1] || '')}')"
                            class="mt-2 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors"
                        >
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                            </svg>
                            Ouvrir le terminal
                        </button>
                    </div>
                `;
            }).join('');
        }

        // Erreurs de connexion
        if (connectionErrors.length > 0) {
            // Grouper par erreur unique
            const errorGroups = {};
            connectionErrors.forEach(r => {
                const msg = r.error_message || 'Erreur inconnue';
                if (!errorGroups[msg]) errorGroups[msg] = { count: 0, ips: new Set() };
                errorGroups[msg].count++;
                errorGroups[msg].ips.add(r.host_ip);
            });

            html += Object.entries(errorGroups).map(([msg, info]) => `
                <div class="flex items-start gap-2 text-xs">
                    <svg class="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <div>
                        <span class="text-red-400 font-medium">Erreur connexion</span>
                        <span class="text-surface-400">• ${info.count} tentative(s)</span>
                        <div class="text-surface-500 mt-0.5">${msg}</div>
                    </div>
                </div>
            `).join('');
        }

        // Échecs d'auth (juste les credential incorrects)
        if (authFailures.length > 0) {
            html += `
                <div class="flex items-center gap-2 text-xs">
                    <svg class="w-3.5 h-3.5 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>
                    </svg>
                    <span class="text-amber-400 font-medium">${authFailures.length} échec(s) auth</span>
                    <span class="text-surface-400">• identifiants incorrects</span>
                </div>
            `;
        }

        html += '</div>';
        return html;
    },

    /**
     * Get no campaigns HTML
     */
    getNoCampaignsHTML() {
        return `
            <div class="card">
                <div class="card-body">
                    <div class="empty-state">
                        <svg class="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <h3>Aucune campagne</h3>
                        <p>Lancez une attaque depuis les suggestions ci-dessus.</p>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get error HTML
     */
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
                <button onclick="AuthTests.render()" class="btn-primary">
                    Réessayer
                </button>
            </div>
        `;
    },

    // ── SSH Terminal ──────────────────────────────────────────────────

    /**
     * Open SSH terminal modal
     */
    openTerminal(host, port, username, password) {
        // Si pas de mot de passe réel, demander à l'utilisateur
        if (!password || password === '***') {
            const inputPwd = prompt(`Mot de passe SSH pour ${username}@${host}:${port} :`);
            if (inputPwd === null) return; // Annulé
            password = inputPwd;
        }

        // Créer le modal
        const modal = document.createElement('div');
        modal.id = 'ssh-terminal-modal';
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/70';
        modal.innerHTML = `
            <div class="bg-surface-900 rounded-xl border border-surface-700 w-full max-w-3xl mx-4 flex flex-col" style="height: 70vh;">
                <div class="flex items-center justify-between px-4 py-3 border-b border-surface-700">
                    <div class="flex items-center gap-3">
                        <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                        </svg>
                        <span class="text-white font-medium">SSH Terminal</span>
                        <span class="text-sm text-surface-400">${username}@${host}:${port}</span>
                    </div>
                    <button onclick="AuthTests.closeTerminal()" class="p-1.5 rounded hover:bg-surface-800 text-surface-400 hover:text-white transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
                <div id="ssh-terminal-output" class="flex-1 overflow-y-auto p-4 font-mono text-sm text-surface-300 bg-black/50">
                    <div class="text-emerald-400">Connexion à ${host}...</div>
                </div>
                <div class="flex items-center gap-2 px-4 py-3 border-t border-surface-700">
                    <span class="text-emerald-400 font-mono text-sm shrink-0">$</span>
                    <input
                        id="ssh-terminal-input"
                        type="text"
                        class="flex-1 bg-transparent border-none outline-none font-mono text-sm text-white placeholder-surface-500"
                        placeholder="Entrez une commande..."
                        autofocus
                    >
                    <button
                        onclick="AuthTests.execSSHCommand()"
                        class="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors"
                    >
                        Envoyer
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        // Stocker les credentials
        this._terminal = { host, port, username, password };

        // Focus input
        const input = document.getElementById('ssh-terminal-input');
        input.focus();
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.execSSHCommand();
            if (e.key === 'Escape') this.closeTerminal();
        });
    },

    closeTerminal() {
        const modal = document.getElementById('ssh-terminal-modal');
        if (modal) modal.remove();
        this._terminal = null;
    },

    async execSSHCommand() {
        const input = document.getElementById('ssh-terminal-input');
        const output = document.getElementById('ssh-terminal-output');
        if (!input || !output || !this._terminal) return;

        const command = input.value.trim();
        if (!command) return;

        const { host, port, username, password } = this._terminal;

        // Afficher la commande
        const cmdLine = document.createElement('div');
        cmdLine.innerHTML = `<span class="text-emerald-400">$</span> <span class="text-white">${this.esc(command)}</span>`;
        output.appendChild(cmdLine);

        input.value = '';
        input.disabled = true;

        // Charger le spinner
        const spinner = document.createElement('div');
        spinner.className = 'text-surface-500';
        spinner.textContent = 'Exécution...';
        output.appendChild(spinner);
        output.scrollTop = output.scrollHeight;

        try {
            const result = await api.sshExec({
                host_ip: host,
                port: port,
                username: username,
                password: password,
                command: command,
            });

            // Supprimer le spinner
            spinner.remove();

            // Afficher stdout
            if (result.stdout) {
                const outDiv = document.createElement('div');
                outDiv.className = 'text-surface-300 whitespace-pre-wrap';
                outDiv.textContent = result.stdout;
                output.appendChild(outDiv);
            }

            // Afficher stderr
            if (result.stderr) {
                const errDiv = document.createElement('div');
                errDiv.className = 'text-red-400 whitespace-pre-wrap';
                errDiv.textContent = result.stderr;
                output.appendChild(errDiv);
            }

            // Afficher le code de sortie si non nul
            if (result.exit_code !== 0) {
                const codeDiv = document.createElement('div');
                codeDiv.className = 'text-surface-500 text-xs';
                codeDiv.textContent = `(exit code: ${result.exit_code})`;
                output.appendChild(codeDiv);
            }
        } catch (error) {
            spinner.remove();
            const errDiv = document.createElement('div');
            errDiv.className = 'text-red-400';
            errDiv.textContent = `Erreur: ${error.message}`;
            output.appendChild(errDiv);
        }

        input.disabled = false;
        input.focus();
        output.scrollTop = output.scrollHeight;
    },

    /**
     * Escape HTML
     */
    esc(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    },
};
