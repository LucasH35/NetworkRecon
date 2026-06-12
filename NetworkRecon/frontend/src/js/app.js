/**
 * NetworkRecon - Main Application
 * Handles SPA routing, global state, and UI interactions
 */

// ===================== Global State =====================
const AppState = {
    currentSection: 'dashboard',
    sidebarOpen: false,
    campaigns: [],
    hosts: [],
    vulnerabilities: []
};

// ===================== Router =====================
const Router = {
    routes: {
        'dashboard': { title: 'Dashboard', render: () => Dashboard.render() },
        'campaigns': { title: 'Campagnes de scan', render: () => Campaigns.render() },
        'hosts': { title: 'Hôtes découverts', render: () => Hosts.render() },
        'vulnerabilities': { title: 'Vulnérabilités', render: () => Vulnerabilities.render(), hidden: true },
        'mitre': { title: 'MITRE ATT&CK', render: () => Mitre.render(), hidden: true },
        'auth-tests': { title: 'Tests d\'authentification', render: () => AuthTests.render(), hidden: true },
        'sqlmap': { title: 'SQLMap - Injection SQL', render: () => Sqlmap.render(), hidden: true },
        'reports': { title: 'Rapports', render: () => Reports.render(), hidden: true },
    },

    /**
     * Initialize router
     */
    init() {
        window.addEventListener('hashchange', () => this.handleRoute());
        window.addEventListener('load', () => this.handleRoute());
    },

    /**
     * Navigate to a hash route explicitly (reliable back/navigation)
     */
    navigate(hash) {
        // Stop any running polling before navigating
        if (typeof Campaigns !== 'undefined') Campaigns.stopListPolling();
        if (typeof Campaigns !== 'undefined') Campaigns.stopStatusPolling();
        if (typeof AuthTests !== 'undefined') AuthTests.stopProgressPolling();
        if (typeof Sqlmap !== 'undefined') Sqlmap.stopProgressPolling();

        window.location.hash = '#' + hash;
        // Force re-render even if hash didn't change
        this.handleRoute();
    },

    /**
     * Handle route changes
     */
    handleRoute() {
        const hash = window.location.hash.slice(1) || 'dashboard';
        const parts = hash.split('/');
        const section = parts[0];
        const id = parts[1];

        // Update state
        AppState.currentSection = section;

        // Update sidebar active state
        this.updateSidebarActive(section);

        // Update page title
        this.updatePageTitle(section);

        // Render the appropriate view
        if (section === 'campaigns' && id) {
            Campaigns.renderDetail(id);
        } else if (section === 'hosts' && id) {
            Hosts.renderDetail(id);
        } else if (section === 'vulnerabilities' && id) {
            Vulnerabilities.renderDetail(id);
        } else if (section === 'sqlmap' && id) {
            Sqlmap.renderDetail(id);
        } else if (this.routes[section]) {
            this.routes[section].render();
        } else {
            // Default to dashboard
            window.location.hash = '#dashboard';
        }

        // Close sidebar on mobile
        if (window.innerWidth < 1024) {
            closeSidebar();
        }
    },

    /**
     * Update sidebar active state
     */
    updateSidebarActive(section) {
        const mainSections = ['dashboard', 'campaigns', 'hosts'];
        const activeSection = mainSections.includes(section) ? section : null;

        document.querySelectorAll('.nav-link').forEach(link => {
            const linkSection = link.getAttribute('data-section');
            if (linkSection === activeSection) {
                link.classList.add('bg-surface-800', 'text-white');
                link.classList.remove('text-surface-300');
            } else {
                link.classList.remove('bg-surface-800', 'text-white');
                link.classList.add('text-surface-300');
            }
        });
    },

    /**
     * Update page title
     */
    updatePageTitle(section) {
        const titleEl = document.getElementById('page-title');
        const route = this.routes[section];
        if (titleEl && route) {
            titleEl.textContent = route.title;
        }
    }
};

// ===================== UI Functions =====================

/**
 * Update scan command preview based on scan type selection
 */
function updateScanCommand(scanType) {
    const preview = document.getElementById('scan-command-preview');
    if (!preview) return;

    const commands = {
        'quick': 'nmap -sT --top-ports 1000 -T4 -O -sV &lt;cible&gt;',
        'stealth': 'nmap -sS -T2 --top-ports 100 -O -sV &lt;cible&gt;',
        'full': 'nmap -sV -sC -O &lt;cible&gt;'
    };

    preview.innerHTML = commands[scanType] || commands['quick'];
}

/**
 * Toggle sidebar on mobile
 */
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    if (sidebar.classList.contains('-translate-x-full')) {
        sidebar.classList.remove('-translate-x-full');
        sidebar.classList.add('translate-x-0');
        overlay.classList.remove('hidden');
        AppState.sidebarOpen = true;
    } else {
        closeSidebar();
    }
}

/**
 * Close sidebar
 */
function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    sidebar.classList.remove('translate-x-0');
    sidebar.classList.add('-translate-x-full');
    overlay.classList.add('hidden');
    AppState.sidebarOpen = false;
}

/**
 * Show new scan modal
 */
function showNewScanModal() {
    const modal = document.getElementById('new-scan-modal');
    if (modal) {
        modal.classList.remove('hidden');
    }
}

/**
 * Hide new scan modal
 */
function hideNewScanModal() {
    const modal = document.getElementById('new-scan-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// ===================== Form Handling =====================

/**
 * Initialize form handlers
 */
function initForms() {
    const newScanForm = document.getElementById('new-scan-form');
    if (newScanForm) {
        newScanForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(e.target);
            const name = formData.get('name');
            const description = formData.get('description');
            const target = formData.get('target');
            const scanType = formData.get('scan_type');
            const portsRange = formData.get('ports_range');
            const authorized = formData.get('authorized') === 'on';

            if (!authorized) {
                alert('Vous devez confirmer que le scan est autorisé.');
                return;
            }

            try {
                await api.createCampaign({
                    name: name,
                    description: description || undefined,
                    target: target || '192.168.2.0/24',
                    scan_type: scanType || 'full',
                    ports_range: portsRange || undefined,
                });

                hideNewScanModal();
                e.target.reset();

                // Navigate to campaigns
                window.location.hash = '#campaigns';
            } catch (error) {
                console.error('Create campaign error:', error);
                alert('Erreur lors de la création: ' + (error.message || 'Erreur inconnue'));
            }
        });
    }
}

// ===================== Keyboard Shortcuts =====================

/**
 * Initialize keyboard shortcuts
 */
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Escape to close modals
        if (e.key === 'Escape') {
            hideNewScanModal();
            Mitre.closeTechniqueModal();
            AuthTests.hideConfigModal();
        }

        // Ctrl+K for search (future feature)
        if (e.ctrlKey && e.key === 'k') {
            e.preventDefault();
            // TODO: Implement global search
        }
    });
}

// ===================== API Connection Check =====================

/**
 * Check API connection
 */
async function checkAPIConnection() {
    const indicator = document.querySelector('#sidebar .flex.items-center.gap-2');
    const dot = indicator?.querySelector('.w-2');
    const text = indicator?.querySelector('span');

    try {
        const connected = await api.healthCheck();
        if (dot) {
            dot.classList.toggle('bg-emerald-500', connected);
            dot.classList.toggle('bg-red-500', !connected);
        }
        if (text) {
            text.textContent = connected ? 'API Connectée' : 'API Déconnectée';
        }
    } catch {
        if (dot) {
            dot.classList.remove('bg-emerald-500');
            dot.classList.add('bg-red-500');
        }
        if (text) {
            text.textContent = 'API Déconnectée';
        }
    }
}

/**
 * Reset all data with confirmation
 */
async function resetAllData() {
    if (!confirm('⚠️ ATTENTION : Cette action va supprimer TOUTES les données (campagnes, hôtes, vulnérabilités, rapports, etc.).\n\nCette action est IRRÉVERSIBLE.\n\nÊtes-vous sûr de vouloir continuer ?')) {
        return;
    }
    if (!confirm('Dernière confirmation : Voulez-vous vraiment tout supprimer ?')) {
        return;
    }

    try {
        await api.resetAllData();
        alert('✅ Toutes les données ont été réinitialisées.');
        Router.navigate('dashboard');
    } catch (error) {
        alert('❌ Erreur lors de la réinitialisation : ' + (error.message || 'Erreur inconnue'));
    }
}

// ===================== Initialize =====================

document.addEventListener('DOMContentLoaded', () => {
    // Initialize router
    Router.init();

    // Initialize forms
    initForms();

    // Initialize keyboard shortcuts
    initKeyboardShortcuts();

    // Check API connection
    checkAPIConnection();

    // Check connection periodically
    setInterval(checkAPIConnection, 30000);

    console.log('NetworkRecon Frontend initialized');
});
