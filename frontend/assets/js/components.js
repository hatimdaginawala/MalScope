import { swalTheme } from './theme.js';

export function renderSidebar() {
    const sidebar = `
    <aside class="app-sidebar w-64 h-screen fixed top-0 left-0 flex flex-col z-20">
        <div class="sidebar-brand p-6 flex items-center gap-3">
            <i data-lucide="shield-alert" class="w-7 h-7" style="color: var(--accent-primary);"></i>
            <h1 class="text-xl font-bold">MalScope</h1>
        </div>
        <nav class="flex-1 overflow-y-auto py-4 px-3 flex flex-col gap-1">
            <a href="dashboard.html" class="nav-link" data-page="dashboard">
                <i data-lucide="layout-dashboard" class="w-5 h-5"></i> Dashboard
            </a>
            <a href="samples.html" class="nav-link" data-page="samples">
                <i data-lucide="file-code" class="w-5 h-5"></i> Samples
            </a>
            <a href="static-analyses.html" class="nav-link" data-page="static-analyses">
                <i data-lucide="search-code" class="w-5 h-5"></i> Static Analyses
            </a>
            <a href="threat-intel.html" class="nav-link" data-page="threat-intel">
                <i data-lucide="globe-lock" class="w-5 h-5"></i> Threat Intel Search
            </a>
            <a href="iocs.html" class="nav-link" data-page="iocs">
                <i data-lucide="radar" class="w-5 h-5"></i> IOCs
            </a>
            <a href="behaviors.html" class="nav-link" data-page="behaviors">
                <i data-lucide="activity" class="w-5 h-5"></i> Behaviors
            </a>
            <a href="reports.html" class="nav-link" data-page="reports">
                <i data-lucide="file-bar-chart" class="w-5 h-5"></i> Reports
            </a>
            <a href="users.html" class="nav-link" data-page="users">
                <i data-lucide="users" class="w-5 h-5"></i> Users
            </a>
        </nav>
        <div class="sidebar-footer p-4">
            <button id="logoutBtn" class="logout-btn">
                <i data-lucide="log-out" class="w-4 h-4"></i> Logout
            </button>
        </div>
    </aside>
    `;

    document.getElementById('sidebar-container').innerHTML = sidebar;

    // Highlight active nav
    const currentPage = window.location.pathname.split('/').pop().replace('.html', '');
    const activeLink = document.querySelector(`.nav-link[data-page="${currentPage || 'dashboard'}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }

    // Initialize Lucide icons for the sidebar
    if (window.lucide) {
        window.lucide.createIcons();
    }
}

export function showToast(message, type = 'success') {
    const t = swalTheme();
    const Toast = Swal.mixin({
        toast: true,
        position: 'top-end',
        showConfirmButton: false,
        timer: 3000,
        timerProgressBar: true,
        background: t.background,
        color: t.color
    });
    Toast.fire({
        icon: type,
        title: message
    });
}