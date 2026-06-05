/**
 * NetworkRecon - Reports Module
 * Generate and download reports in various formats
 */

const Reports = {
    /**
     * Render the reports view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getLoadingSkeleton();

        try {
            const [campaigns, hosts, vulnSummary] = await Promise.all([
                api.getCampaigns({ limit: 50 }),
                api.getHosts({ limit: 500 }),
                api.getVulnerabilitySummary().catch(() => ({
                    total: 0,
                    by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    affected_hosts: 0,
                    top_cves: []
                }))
            ]);

            app.innerHTML = this.getHTML(campaigns, hosts, vulnSummary);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Get loading skeleton
     */
    getLoadingSkeleton() {
        return `
            <div class="animate-fade-in space-y-4">
                <div class="loading-skeleton w-48 h-8 mb-6"></div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    ${Array(3).fill('').map(() => `
                        <div class="card">
                            <div class="card-body">
                                <div class="loading-skeleton w-16 h-16 rounded-xl mb-4"></div>
                                <div class="loading-skeleton w-32 h-6 mb-2"></div>
                                <div class="loading-skeleton w-full h-4 mb-4"></div>
                                <div class="loading-skeleton w-24 h-10"></div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    /**
     * Get main HTML
     */
    getHTML(campaigns, hosts, vulnSummary) {
        return `
            <div class="animate-fade-in space-y-6">
                <h2 class="text-xl font-bold text-white">Rapports</h2>

                <!-- Report Types -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <!-- PDF Report -->
                    <div class="card">
                        <div class="card-body text-center">
                            <div class="w-16 h-16 bg-red-500/10 rounded-xl flex items-center justify-center mx-auto mb-4">
                                <svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>
                                </svg>
                            </div>
                            <h3 class="font-semibold text-white mb-2">Rapport PDF</h3>
                            <p class="text-sm text-surface-400 mb-4">Rapport complet avec graphiques et détails visuels</p>
                            <button onclick="Reports.generatePDF()" class="btn btn-primary w-full">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                </svg>
                                Générer PDF
                            </button>
                        </div>
                    </div>

                    <!-- CSV Export -->
                    <div class="card">
                        <div class="card-body text-center">
                            <div class="w-16 h-16 bg-emerald-500/10 rounded-xl flex items-center justify-center mx-auto mb-4">
                                <svg class="w-8 h-8 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                                </svg>
                            </div>
                            <h3 class="font-semibold text-white mb-2">Export CSV</h3>
                            <p class="text-sm text-surface-400 mb-4">Données tabulaires pour analyse dans Excel</p>
                            <button onclick="Reports.generateCSV()" class="btn btn-primary w-full">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                </svg>
                                Exporter CSV
                            </button>
                        </div>
                    </div>

                    <!-- JSON Export -->
                    <div class="card">
                        <div class="card-body text-center">
                            <div class="w-16 h-16 bg-blue-500/10 rounded-xl flex items-center justify-center mx-auto mb-4">
                                <svg class="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                                </svg>
                            </div>
                            <h3 class="font-semibold text-white mb-2">Export JSON</h3>
                            <p class="text-sm text-surface-400 mb-4">Données structurées pour intégration API</p>
                            <button onclick="Reports.generateJSON()" class="btn btn-primary w-full">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                </svg>
                                Exporter JSON
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Summary Preview -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="font-semibold text-white">Aperçu du rapport</h3>
                    </div>
                    <div class="card-body">
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-6">
                            <div>
                                <div class="text-sm text-surface-400 mb-1">Campagnes</div>
                                <div class="text-2xl font-bold text-white">${campaigns.length}</div>
                            </div>
                            <div>
                                <div class="text-sm text-surface-400 mb-1">Hôtes découverts</div>
                                <div class="text-2xl font-bold text-white">${hosts.length}</div>
                            </div>
                            <div>
                                <div class="text-sm text-surface-400 mb-1">Vulnérabilités</div>
                                <div class="text-2xl font-bold text-white">${vulnSummary.total || 0}</div>
                            </div>
                            <div>
                                <div class="text-sm text-surface-400 mb-1">Critiques</div>
                                <div class="text-2xl font-bold text-red-400">${vulnSummary.by_severity?.critical || 0}</div>
                            </div>
                        </div>

                        <!-- Severity Breakdown -->
                        <div class="mt-6 pt-6 border-t border-surface-700">
                            <h4 class="text-sm font-medium text-surface-400 mb-3">Répartition par sévérité</h4>
                            <div class="flex items-center gap-4">
                                <div class="flex-1">
                                    <div class="progress-bar h-4 rounded-lg overflow-hidden flex">
                                        ${this.getSeverityBar(vulnSummary)}
                                    </div>
                                </div>
                            </div>
                            <div class="flex flex-wrap gap-4 mt-3 text-sm">
                                <div class="flex items-center gap-2">
                                    <div class="w-3 h-3 rounded bg-red-500"></div>
                                    <span class="text-surface-400">Critique: ${vulnSummary.by_severity?.critical || 0}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <div class="w-3 h-3 rounded bg-orange-500"></div>
                                    <span class="text-surface-400">Haute: ${vulnSummary.by_severity?.high || 0}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <div class="w-3 h-3 rounded bg-yellow-500"></div>
                                    <span class="text-surface-400">Moyenne: ${vulnSummary.by_severity?.medium || 0}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <div class="w-3 h-3 rounded bg-green-500"></div>
                                    <span class="text-surface-400">Basse: ${vulnSummary.by_severity?.low || 0}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <div class="w-3 h-3 rounded bg-blue-500"></div>
                                    <span class="text-surface-400">Info: ${vulnSummary.by_severity?.info || 0}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Reports -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="font-semibold text-white">Rapports récents</h3>
                    </div>
                    <div class="card-body p-0">
                        <div class="empty-state">
                            <svg class="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                            </svg>
                            <h3>Aucun rapport généré</h3>
                            <p>Générez votre premier rapport en utilisant les boutons ci-dessus.</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get severity bar HTML
     */
    getSeverityBar(summary) {
        const total = summary.total || 1;
        const sev = summary.by_severity || {};

        const segments = [
            { count: sev.critical || 0, color: '#dc2626' },
            { count: sev.high || 0, color: '#f97316' },
            { count: sev.medium || 0, color: '#eab308' },
            { count: sev.low || 0, color: '#22c55e' },
            { count: sev.info || 0, color: '#3b82f6' }
        ];

        return segments
            .filter(s => s.count > 0)
            .map(s => `<div style="width: ${(s.count / total) * 100}%; background: ${s.color}"></div>`)
            .join('');
    },

    /**
     * Generate PDF report
     */
    async generatePDF() {
        try {
            const [campaigns, hosts, vulnSummary] = await Promise.all([
                api.getCampaigns({ limit: 100 }),
                api.getHosts({ limit: 500 }),
                api.getVulnerabilitySummary().catch(() => ({}))
            ]);

            const report = this.buildReportData(campaigns, hosts, vulnSummary);
            const blob = new Blob([this.generatePDFContent(report)], { type: 'text/html' });
            this.downloadBlob(blob, `networkrecon-report-${this.getDateStamp()}.html`);
            
            alert('Rapport HTML généré avec succès. Ouvrez le fichier dans un navigateur pour l\'imprimer en PDF.');
        } catch (error) {
            alert('Erreur lors de la génération: ' + error.message);
        }
    },

    /**
     * Generate CSV export
     */
    async generateCSV() {
        try {
            const [hosts, vulns] = await Promise.all([
                api.getHosts({ limit: 500 }),
                api.getVulnerabilities({ limit: 500 })
            ]);

            let csv = 'Type,IP,Hostname,Status,Port,Service,Version,Severity,CVE,CVSS\n';
            
            hosts.forEach(h => {
                (h.ports || []).forEach(p => {
                    csv += `Host,${h.ip_address},${h.hostname || ''},${h.status},${p.number},${p.service || ''},${p.version || ''},,,\n`;
                });
            });

            vulns.forEach(v => {
                csv += `Vuln,${v.host_ip},,${v.service || ''},${v.port || ''},,${v.cve?.severity || ''},${v.cve?.cve_id || ''},${v.cve?.cvss_score || ''}\n`;
            });

            const blob = new Blob([csv], { type: 'text/csv' });
            this.downloadBlob(blob, `networkrecon-export-${this.getDateStamp()}.csv`);
        } catch (error) {
            alert('Erreur lors de l\'export: ' + error.message);
        }
    },

    /**
     * Generate JSON export
     */
    async generateJSON() {
        try {
            const [campaigns, hosts, vulns] = await Promise.all([
                api.getCampaigns({ limit: 100 }),
                api.getHosts({ limit: 500 }),
                api.getVulnerabilities({ limit: 500 })
            ]);

            const data = {
                export_date: new Date().toISOString(),
                campaigns: campaigns,
                hosts: hosts,
                vulnerabilities: vulns
            };

            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            this.downloadBlob(blob, `networkrecon-export-${this.getDateStamp()}.json`);
        } catch (error) {
            alert('Erreur lors de l\'export: ' + error.message);
        }
    },

    /**
     * Build report data
     */
    buildReportData(campaigns, hosts, vulnSummary) {
        return {
            title: 'NetworkRecon - Rapport de Reconnaissance Réseau',
            generated_at: new Date().toLocaleString('fr-FR'),
            summary: {
                campaigns: campaigns.length,
                hosts: hosts.length,
                vulnerabilities: vulnSummary.total || 0,
                critical: vulnSummary.by_severity?.critical || 0,
                high: vulnSummary.by_severity?.high || 0
            },
            campaigns: campaigns,
            hosts: hosts,
            vulnerabilities: vulnSummary
        };
    },

    /**
     * Generate PDF content (HTML format for print)
     */
    generatePDFContent(report) {
        return `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>${report.title}</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 40px; color: #333; }
        h1 { color: #1e40af; border-bottom: 2px solid #1e40af; padding-bottom: 10px; }
        h2 { color: #374151; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
        .stat { background: #f3f4f6; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; color: #1e40af; }
        .stat-label { color: #6b7280; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #e5e7eb; padding: 10px; text-align: left; }
        th { background: #f9fafb; font-weight: 600; }
        .severity { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .critical { background: #fef2f2; color: #dc2626; }
        .high { background: #fff7ed; color: #f97316; }
        .medium { background: #fefce8; color: #ca8a04; }
        .low { background: #f0fdf4; color: #16a34a; }
        .info { background: #eff6ff; color: #2563eb; }
        @media print { body { padding: 20px; } }
    </style>
</head>
<body>
    <h1>${report.title}</h1>
    <p>Généré le: ${report.generated_at}</p>
    
    <h2>Résumé</h2>
    <div class="summary">
        <div class="stat">
            <div class="stat-value">${report.summary.campaigns}</div>
            <div class="stat-label">Campagnes</div>
        </div>
        <div class="stat">
            <div class="stat-value">${report.summary.hosts}</div>
            <div class="stat-label">Hôtes</div>
        </div>
        <div class="stat">
            <div class="stat-value">${report.summary.vulnerabilities}</div>
            <div class="stat-label">Vulnérabilités</div>
        </div>
        <div class="stat">
            <div class="stat-value" style="color: #dc2626">${report.summary.critical}</div>
            <div class="stat-label">Critiques</div>
        </div>
    </div>

    <h2>Campagnes</h2>
    <table>
        <thead>
            <tr><th>Nom</th><th>Cible</th><th>Statut</th><th>Date</th></tr>
        </thead>
        <tbody>
            ${report.campaigns.map(c => `
                <tr>
                    <td>${c.name}</td>
                    <td>${c.targets?.[0]?.ip_range || 'N/A'}</td>
                    <td>${c.status}</td>
                    <td>${new Date(c.created_at).toLocaleDateString('fr-FR')}</td>
                </tr>
            `).join('')}
        </tbody>
    </table>

    <h2>Hôtes découverts</h2>
    <table>
        <thead>
            <tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Statut</th></tr>
        </thead>
        <tbody>
            ${report.hosts.map(h => `
                <tr>
                    <td>${h.ip_address}</td>
                    <td>${h.hostname || '-'}</td>
                    <td>${h.os_detection || '-'}</td>
                    <td>${h.ports?.length || 0}</td>
                    <td>${h.status}</td>
                </tr>
            `).join('')}
        </tbody>
    </table>
</body>
</html>
        `;
    },

    /**
     * Download a blob as file
     */
    downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    /**
     * Get date stamp for filenames
     */
    getDateStamp() {
        return new Date().toISOString().slice(0, 10);
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
                <button onclick="Reports.render()" class="btn btn-primary">Réessayer</button>
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
