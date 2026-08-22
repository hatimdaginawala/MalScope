import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { initThemeToggle } from './theme.js';

let currentPage = 1;
let currentFilters = {};

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';

    renderSidebar();
    initThemeToggle();

    document.getElementById('refreshBtn').addEventListener('click', () => loadIOCs(currentPage));

    // Search with debounce
    let timeout = null;
    document.getElementById('searchInput').addEventListener('input', (e) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            currentFilters.search = e.target.value;
            currentPage = 1;
            loadIOCs();
        }, 500);
    });

    document.getElementById('prevBtn').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadIOCs(currentPage);
        }
    });

    document.getElementById('nextBtn').addEventListener('click', () => {
        currentPage++;
        loadIOCs(currentPage);
    });

    loadIOCs();
});

async function loadIOCs(page = 1) {
    const tbody = document.getElementById('iocsTable');
    tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center empty-row"><i data-lucide="loader-2" class="w-5 h-5 animate-spin mx-auto mb-2"></i>Loading...</td></tr>`;
    if (window.lucide) window.lucide.createIcons();

    try {
        let query = `page=${page}&limit=15`;
        if (currentFilters.search) query += `&search=${encodeURIComponent(currentFilters.search)}`;

        const response = await API.threatIntel.getIOCs(query);
        const iocsList = response.data || [];
        renderTable(iocsList);

        // Handle pagination UI
        const pag = response.pagination || {};
        currentPage = pag.page || page;
        const total = pag.total || iocsList.length || 0;
        document.getElementById('pageInfo').innerText = `Showing ${iocsList.length} of ${total} results`;

        document.getElementById('prevBtn').disabled = currentPage <= 1;
        document.getElementById('nextBtn').disabled = (currentPage * (pag.limit || 15)) >= total;

    } catch (error) {
        showToast('Failed to load IOCs', 'error');
        tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center error-row">Error loading IOCs</td></tr>`;
    }
}

function severityChip(severity) {
    const key = (severity || '').toLowerCase();
    if (key === 'high') return { cls: 'chip--critical', label: severity };
    if (key === 'medium') return { cls: 'chip--warning', label: severity };
    if (key === 'low') return { cls: 'chip--info', label: severity };
    return { cls: 'chip--info', label: severity || 'Unknown' };
}

function renderTable(iocs) {
    const tbody = document.getElementById('iocsTable');
    if (!iocs.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center empty-row">No IOCs found.</td></tr>`;
        return;
    }

    const typeIcons = {
        'ip': 'globe',
        'domain': 'link',
        'url': 'link-2',
        'hash': 'hash'
    };

    tbody.innerHTML = iocs.map(ioc => {
        const chip = severityChip(ioc.severity);
        const iconName = typeIcons[ioc.type] || 'file';

        return `
        <tr>
            <td class="px-6 py-4">
                <div class="flex items-center gap-2">
                    <i data-lucide="${iconName}" class="w-4 h-4" style="color: var(--text-faint);"></i>
                    <span class="capitalize">${ioc.type || 'Unknown'}</span>
                </div>
            </td>
            <td class="px-6 py-4 hash-cell truncate max-w-[250px]" title="${ioc.value}">${ioc.value}</td>
            <td class="px-6 py-4">
                <span class="chip ${chip.cls}">${chip.label}</span>
            </td>
            <td class="px-6 py-4 timestamp-cell">${ioc.source || 'Unknown'}</td>
            <td class="px-6 py-4 timestamp-cell">${ioc.firstSeen ? new Date(ioc.firstSeen).toLocaleString() : 'N/A'}</td>
            <td class="px-6 py-4 text-right">
                <button class="icon-btn icon-btn--info" title="Copy value" onclick="copyIOCValue('${ioc.value}')">
                    <i data-lucide="copy" class="w-4 h-4"></i>
                </button>
            </td>
        </tr>
    `}).join('');

    if (window.lucide) window.lucide.createIcons();
}

window.copyIOCValue = (value) => {
    navigator.clipboard.writeText(value);
    showToast('Copied to clipboard');
};