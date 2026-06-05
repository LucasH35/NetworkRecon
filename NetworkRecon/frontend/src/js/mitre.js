/**
 * NetworkRecon - MITRE ATT&CK Module
 * Displays MITRE ATT&CK matrix with tactics and techniques
 */

const Mitre = {
    tactics: [],
    techniques: [],
    attackPaths: [],

    /**
     * Render the MITRE ATT&CK matrix view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getLoadingSkeleton();

        try {
            const [tactics, techniques, attackPaths] = await Promise.all([
                api.getMITRETactics(),
                api.getMITRETechniques(),
                api.getAttackPaths().catch(() => [])
            ]);

            this.tactics = tactics;
            this.techniques = techniques;
            this.attackPaths = attackPaths;

            app.innerHTML = this.getHTML(tactics, techniques, attackPaths);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Render technique detail modal
     */
    async showTechniqueDetail(techniqueId) {
        const modal = document.getElementById('technique-modal');
        if (!modal) return;

        modal.innerHTML = this.getTechniqueLoadingSkeleton();
        modal.classList.remove('hidden');

        try {
            const details = await api.getMITRETechniqueDetails(techniqueId);
            modal.innerHTML = this.getTechniqueDetailHTML(details);
        } catch (error) {
            modal.innerHTML = this.getTechniqueErrorHTML(error);
        }
    },

    /**
     * Close technique modal
     */
    closeTechniqueModal() {
        const modal = document.getElementById('technique-modal');
        if (modal) {
            modal.classList.add('hidden');
        }
    },

    /**
     * Get loading skeleton
     */
    getLoadingSkeleton() {
        return `
            <div class="animate-fade-in space-y-6">
                <div class="flex items-center justify-between mb-6">
                    <div class="loading-skeleton w-64 h-8"></div>
                </div>
                <div class="grid grid-cols-4 md:grid-cols-7 gap-3">
                    ${Array(14).fill('').map(() => `
                        <div class="loading-skeleton h-12 rounded-lg"></div>
                    `).join('')}
                </div>
                <div class="loading-skeleton w-full h-96 rounded-xl"></div>
            </div>
        `;
    },

    /**
     * Get main HTML
     */
    getHTML(tactics, techniques, attackPaths) {
        const tacticNames = [
            'Reconnaissance',
            'Resource Development',
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Command and Control',
            'Exfiltration',
            'Impact'
        ];

        // Group techniques by tactic
        const techniquesByTactic = {};
        techniques.forEach(t => {
            if (!techniquesByTactic[t.tactic]) {
                techniquesByTactic[t.tactic] = [];
            }
            techniquesByTactic[t.tactic].push(t);
        });

        return `
            <div class="animate-fade-in space-y-6">
                <div class="flex items-center justify-between">
                    <h2 class="text-xl font-bold text-white">MITRE ATT&CK Matrix</h2>
                    <div class="flex items-center gap-3">
                        <span class="text-sm text-surface-400">${techniques.length} techniques identifiées</span>
                    </div>
                </div>

                <!-- Legend -->
                <div class="flex flex-wrap items-center gap-4 text-sm">
                    <div class="flex items-center gap-2">
                        <div class="w-3 h-3 rounded bg-blue-500"></div>
                        <span class="text-surface-400">Technique disponible</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <div class="w-3 h-3 rounded bg-emerald-500"></div>
                        <span class="text-surface-400">Vulnérabilité associée</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <div class="w-3 h-3 rounded bg-surface-600"></div>
                        <span class="text-surface-400">Non détecté</span>
                    </div>
                </div>

                <!-- Matrix -->
                <div class="card overflow-x-auto">
                    <div class="card-body p-4">
                        <div class="grid grid-cols-7 md:grid-cols-14 gap-2 min-w-[800px]">
                            ${tacticNames.map(tactic => {
                                const tacticTechniques = techniquesByTactic[tactic] || [];
                                return `
                                    <div class="mitre-tactic">
                                        <div class="p-2 bg-surface-700 border-b border-surface-600 text-center">
                                            <div class="text-xs font-semibold text-white leading-tight">${tactic}</div>
                                        </div>
                                        <div class="p-2 space-y-1 min-h-[200px]">
                                            ${tacticTechniques.length ? tacticTechniques.map(t => `
                                                <div class="mitre-technique ${this.getTechniqueClass(t)}" 
                                                    onclick="Mitre.showTechniqueDetail('${t.technique_id}')"
                                                    title="${t.technique_name}">
                                                    <div class="font-mono text-[10px] opacity-70">${t.technique_id}</div>
                                                    <div class="truncate">${this.escapeHtml(t.technique_name)}</div>
                                                </div>
                                            `).join('') : `
                                                <div class="text-center text-xs text-surface-500 py-4">
                                                    Aucune technique
                                                </div>
                                            `}
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                </div>

                <!-- Attack Paths -->
                ${attackPaths.length ? `
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Parcours d'attaque identifiés</h3>
                        </div>
                        <div class="card-body p-0">
                            <div class="divide-y divide-surface-700">
                                ${attackPaths.map(path => `
                                    <div class="p-4 hover:bg-surface-700/50 transition-colors">
                                        <div class="flex items-center justify-between mb-2">
                                            <div class="font-medium text-white">${this.escapeHtml(path.name)}</div>
                                            <span class="text-sm text-surface-400">${path.count || 0} occurrence(s)</span>
                                        </div>
                                        <div class="text-sm text-surface-400 mb-3">${this.escapeHtml(path.description || '')}</div>
                                        <div class="flex flex-wrap gap-2">
                                            ${path.techniques?.map(t => `
                                                <span class="px-2 py-1 bg-primary-500/15 text-primary-400 rounded text-xs font-mono">${t}</span>
                                            `).join('') || ''}
                                        </div>
                                        ${path.hosts?.length ? `
                                            <div class="mt-2 text-xs text-surface-500">
                                                Hôtes affectés: ${path.hosts.join(', ')}
                                            </div>
                                        ` : ''}
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                ` : ''}

                <!-- All Techniques Table -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="font-semibold text-white">Toutes les techniques</h3>
                        <div class="relative">
                            <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                            </svg>
                            <input type="text" placeholder="Rechercher..." 
                                class="form-input pl-10 w-48"
                                oninput="Mitre.filterTechniques(this.value)">
                        </div>
                    </div>
                    <div class="card-body p-0">
                        <div class="overflow-x-auto">
                            <table class="data-table" id="techniques-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Nom</th>
                                        <th>Tactique</th>
                                        <th>Description</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${techniques.map(t => `
                                        <tr class="technique-row">
                                            <td><span class="font-mono text-primary-400">${t.technique_id}</span></td>
                                            <td class="font-medium text-white">${this.escapeHtml(t.technique_name)}</td>
                                            <td><span class="text-surface-400">${this.escapeHtml(t.tactic)}</span></td>
                                            <td class="text-surface-300 text-sm max-w-xs truncate">${this.escapeHtml(t.description || '')}</td>
                                            <td>
                                                <button onclick="Mitre.showTechniqueDetail('${t.technique_id}')" class="text-primary-400 hover:text-primary-300">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                                                    </svg>
                                                </button>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Technique Detail Modal -->
            <div id="technique-modal" class="fixed inset-0 z-50 hidden">
                <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" onclick="Mitre.closeTechniqueModal()"></div>
                <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg mx-4">
                    <div class="bg-surface-800 rounded-xl shadow-2xl border border-surface-700 max-h-[80vh] overflow-y-auto">
                        <!-- Content loaded dynamically -->
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get technique CSS class based on available data
     */
    getTechniqueClass(technique) {
        // In a real app, check if technique has associated vulnerabilities
        return '';
    },

    /**
     * Get technique loading skeleton
     */
    getTechniqueLoadingSkeleton() {
        return `
            <div class="p-6">
                <div class="loading-skeleton w-48 h-6 mb-4"></div>
                <div class="loading-skeleton w-full h-4 mb-2"></div>
                <div class="loading-skeleton w-full h-4 mb-2"></div>
                <div class="loading-skeleton w-3/4 h-4"></div>
            </div>
        `;
    },

    /**
     * Get technique detail HTML
     */
    getTechniqueDetailHTML(details) {
        return `
            <div class="p-6">
                <div class="flex items-center justify-between mb-4">
                    <div>
                        <span class="font-mono text-primary-400 text-sm">${details.technique_id}</span>
                        <h3 class="text-lg font-bold text-white mt-1">${this.escapeHtml(details.technique_name)}</h3>
                    </div>
                    <button onclick="Mitre.closeTechniqueModal()" class="p-1 rounded-lg hover:bg-surface-700 text-surface-400">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>

                <div class="space-y-4">
                    <div>
                        <div class="text-sm text-surface-400 mb-1">Tactique</div>
                        <div class="text-white">${this.escapeHtml(details.tactic)}</div>
                    </div>

                    ${details.description ? `
                        <div>
                            <div class="text-sm text-surface-400 mb-1">Description</div>
                            <p class="text-surface-300 text-sm">${this.escapeHtml(details.description)}</p>
                        </div>
                    ` : ''}

                    ${details.related_services?.length ? `
                        <div>
                            <div class="text-sm text-surface-400 mb-2">Services associés</div>
                            <div class="flex flex-wrap gap-2">
                                ${details.related_services.map(s => `
                                    <span class="px-2 py-1 bg-surface-700 rounded text-xs text-white">${s}</span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}

                    ${details.url ? `
                        <a href="${details.url}" target="_blank" 
                            class="flex items-center gap-2 text-primary-400 hover:text-primary-300 text-sm">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                            </svg>
                            Voir sur MITRE ATT&CK
                        </a>
                    ` : ''}
                </div>
            </div>
        `;
    },

    /**
     * Get technique error HTML
     */
    getTechniqueErrorHTML(error) {
        return `
            <div class="p-6 text-center">
                <svg class="w-12 h-12 text-red-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
                <p class="text-surface-400">${error.message}</p>
                <button onclick="Mitre.closeTechniqueModal()" class="btn btn-primary mt-4">Fermer</button>
            </div>
        `;
    },

    /**
     * Filter techniques in table
     */
    filterTechniques(query) {
        const rows = document.querySelectorAll('.technique-row');
        const lowerQuery = query.toLowerCase();

        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(lowerQuery) ? '' : 'none';
        });
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
                <button onclick="Mitre.render()" class="btn btn-primary">Réessayer</button>
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
