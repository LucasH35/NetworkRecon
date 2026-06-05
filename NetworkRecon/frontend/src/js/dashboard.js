/**
 * NetworkRecon - Dashboard Module
 * Displays global statistics, charts, and recent activity
 */

const Dashboard = {
    charts: {},

    /**
     * Render the dashboard view
     */
    async render() {
        const app = document.getElementById('app');
        app.innerHTML = this.getLoadingSkeleton();

        try {
            const [campaigns, hosts, vulnSummary] = await Promise.all([
                api.getCampaigns({ limit: 10 }),
                api.getHosts({ limit: 200 }),
                api.getVulnerabilitySummary().catch(() => ({
                    total: 0,
                    by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    affected_hosts: 0,
                    top_cves: []
                }))
            ]);

            const stats = this.calculateStats(campaigns, hosts, vulnSummary);

            app.innerHTML = this.getHTML(stats, campaigns, vulnSummary);
            this.initCharts(vulnSummary);
        } catch (error) {
            app.innerHTML = this.getErrorHTML(error);
        }
    },

    /**
     * Calculate dashboard statistics
     */
    calculateStats(campaigns, hosts, vulnSummary) {
        const runningCampaigns = campaigns.filter(c => c.status === 'running').length;
        const completedCampaigns = campaigns.filter(c => c.status === 'completed').length;
        const totalHosts = hosts.length;
        const upHosts = hosts.filter(h => h.status === 'up').length;
        const totalServices = hosts.reduce((sum, h) => sum + (h.ports?.length || 0), 0);

        return {
            totalCampaigns: campaigns.length,
            runningCampaigns,
            completedCampaigns,
            totalHosts,
            upHosts,
            totalServices,
            totalVulns: vulnSummary.total || 0,
            criticalVulns: vulnSummary.by_severity?.critical || 0,
            highVulns: vulnSummary.by_severity?.high || 0,
        };
    },

    /**
     * Get loading skeleton HTML
     */
    getLoadingSkeleton() {
        return `
            <div class="animate-fade-in space-y-6">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    ${Array(4).fill('').map(() => `
                        <div class="stat-card">
                            <div class="loading-skeleton w-12 h-12 rounded-lg mb-4"></div>
                            <div class="loading-skeleton w-20 h-8 mb-2"></div>
                            <div class="loading-skeleton w-32 h-4"></div>
                        </div>
                    `).join('')}
                </div>
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="card">
                        <div class="card-header"><div class="loading-skeleton w-32 h-5"></div></div>
                        <div class="card-body"><div class="loading-skeleton w-full h-64"></div></div>
                    </div>
                    <div class="card">
                        <div class="card-header"><div class="loading-skeleton w-32 h-5"></div></div>
                        <div class="card-body"><div class="loading-skeleton w-full h-64"></div></div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Get main dashboard HTML
     */
    getHTML(stats, campaigns, vulnSummary) {
        const recentCampaigns = campaigns.slice(0, 5);

        return `
            <div class="animate-fade-in space-y-6">
                <!-- Stats Cards -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="stat-card">
                        <div class="stat-icon bg-blue-500/10">
                            <svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
                            </svg>
                        </div>
                        <div class="stat-value text-white">${stats.totalHosts}</div>
                        <div class="stat-label">Hôtes découverts</div>
                        <div class="stat-change text-emerald-500">${stats.upHosts} actifs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon bg-purple-500/10">
                            <svg class="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                            </svg>
                        </div>
                        <div class="stat-value text-white">${stats.totalServices}</div>
                        <div class="stat-label">Services détectés</div>
                        <div class="stat-change text-blue-500">${stats.runningCampaigns} en cours</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon bg-red-500/10">
                            <svg class="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                            </svg>
                        </div>
                        <div class="stat-value text-white">${stats.totalVulns}</div>
                        <div class="stat-label">Vulnérabilités</div>
                        <div class="stat-change text-red-500">${stats.criticalVulns} critiques</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon bg-emerald-500/10">
                            <svg class="w-6 h-6 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                            </svg>
                        </div>
                        <div class="stat-value text-white">${stats.totalCampaigns}</div>
                        <div class="stat-label">Campagnes</div>
                        <div class="stat-change text-emerald-500">${stats.completedCampaigns} terminées</div>
                    </div>
                </div>

                <!-- Charts Row -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Severity Chart -->
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Répartition par sévérité</h3>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="severity-chart"></canvas>
                            </div>
                        </div>
                    </div>

                    <!-- Services Chart -->
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Services les plus fréquents</h3>
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="services-chart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Activity -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Recent Campaigns -->
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Campagnes récentes</h3>
                            <a href="#campaigns" class="text-sm text-primary-400 hover:text-primary-300">Voir tout</a>
                        </div>
                        <div class="card-body p-0">
                            ${recentCampaigns.length ? `
                                <div class="divide-y divide-surface-700">
                                    ${recentCampaigns.map(c => `
                                        <a href="#campaigns/${c._id || c.id}" class="flex items-center justify-between p-4 hover:bg-surface-700/50 transition-colors">
                                            <div class="flex items-center gap-3">
                                                <span class="status-dot ${c.status}"></span>
                                                <div>
                                                    <div class="font-medium text-white text-sm">${this.escapeHtml(c.name)}</div>
                                                    <div class="text-xs text-surface-400">${c.targets?.[0]?.ip_range || 'N/A'}</div>
                                                </div>
                                            </div>
                                            <span class="status-badge status-${c.status}">${this.getStatusLabel(c.status)}</span>
                                        </a>
                                    `).join('')}
                                </div>
                            ` : `
                                <div class="empty-state">
                                    <p>Aucune campagne pour le moment</p>
                                </div>
                            `}
                        </div>
                    </div>

                    <!-- Top Vulnerabilities -->
                    <div class="card">
                        <div class="card-header">
                            <h3 class="font-semibold text-white">Top vulnérabilités</h3>
                            <a href="#vulnerabilities" class="text-sm text-primary-400 hover:text-primary-300">Voir tout</a>
                        </div>
                        <div class="card-body p-0">
                            ${vulnSummary.top_cves?.length ? `
                                <div class="divide-y divide-surface-700">
                                    ${vulnSummary.top_cves.slice(0, 5).map(v => `
                                        <div class="flex items-center justify-between p-4">
                                            <div class="flex items-center gap-3">
                                                <span class="severity-badge severity-${v.severity}">${v.severity}</span>
                                                <div>
                                                    <div class="font-medium text-white text-sm font-mono">${this.escapeHtml(v.cve_id)}</div>
                                                    <div class="text-xs text-surface-400">${v.count} occurrence${v.count > 1 ? 's' : ''}</div>
                                                </div>
                                            </div>
                                            <a href="#vulnerabilities/${v.cve_id}" class="text-primary-400 hover:text-primary-300">
                                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                                </svg>
                                            </a>
                                        </div>
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
            </div>
        `;
    },

    /**
     * Initialize charts
     */
    initCharts(vulnSummary) {
        this.initSeverityChart(vulnSummary);
        this.initServicesChart();
    },

    /**
     * Initialize severity donut chart
     */
    initSeverityChart(vulnSummary) {
        const ctx = document.getElementById('severity-chart');
        if (!ctx) return;

        if (this.charts.severity) {
            this.charts.severity.destroy();
        }

        const data = vulnSummary.by_severity || {};

        this.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critique', 'Haute', 'Moyenne', 'Basse', 'Info'],
                datasets: [{
                    data: [
                        data.critical || 0,
                        data.high || 0,
                        data.medium || 0,
                        data.low || 0,
                        data.info || 0
                    ],
                    backgroundColor: [
                        '#dc2626',
                        '#f97316',
                        '#eab308',
                        '#22c55e',
                        '#3b82f6'
                    ],
                    borderColor: '#1e293b',
                    borderWidth: 3,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            padding: 16,
                            usePointStyle: true,
                            pointStyleWidth: 10,
                            font: { size: 12 }
                        }
                    }
                }
            }
        });
    },

    /**
     * Initialize services bar chart
     */
    async initServicesChart() {
        const ctx = document.getElementById('services-chart');
        if (!ctx) return;

        if (this.charts.services) {
            this.charts.services.destroy();
        }

        try {
            const hosts = await api.getHosts({ limit: 500 });
            const serviceCounts = {};

            hosts.forEach(host => {
                (host.ports || []).forEach(port => {
                    const service = port.service || 'unknown';
                    serviceCounts[service] = (serviceCounts[service] || 0) + 1;
                });
            });

            const sorted = Object.entries(serviceCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);

            this.charts.services = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: sorted.map(s => s[0].toUpperCase()),
                    datasets: [{
                        label: 'Nombre d\'occurrences',
                        data: sorted.map(s => s[1]),
                        backgroundColor: 'rgba(59, 130, 246, 0.5)',
                        borderColor: '#3b82f6',
                        borderWidth: 1,
                        borderRadius: 6,
                        barThickness: 30
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(51, 65, 85, 0.5)' },
                            ticks: { color: '#94a3b8' }
                        },
                        y: {
                            grid: { display: false },
                            ticks: {
                                color: '#94a3b8',
                                font: { size: 11 }
                            }
                        }
                    }
                }
            });
        } catch (error) {
            console.error('Error loading services chart:', error);
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
                <button onclick="Dashboard.render()" class="btn btn-primary">Réessayer</button>
            </div>
        `;
    },

    /**
     * Get status label in French
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
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};
