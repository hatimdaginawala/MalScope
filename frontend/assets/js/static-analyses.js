import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { initThemeToggle } from './theme.js';

let currentPage = 1;
let currentFilters = {};

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';

    renderSidebar();
    initThemeToggle();

    document.getElementById('refreshBtn').addEventListener('click', () => loadAnalyses(currentPage));

    // Search with debounce
    let timeout = null;
    document.getElementById('searchInput').addEventListener('input', (e) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            currentFilters.search = e.target.value;
            currentPage = 1;
            loadAnalyses();
        }, 500);
    });

    document.getElementById('prevBtn').addEventListener('click', () => {
        if (currentPage > 1) {
            loadAnalyses(currentPage - 1);
        }
    });

    document.getElementById('nextBtn').addEventListener('click', () => {
        loadAnalyses(currentPage + 1);
    });

    loadAnalyses();
});

async function loadAnalyses(page = 1) {
    const tbody = document.getElementById('analysesTable');
    tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center empty-row"><i data-lucide="loader-2" class="w-5 h-5 animate-spin mx-auto mb-2"></i>Loading...</td></tr>`;
    if (window.lucide) window.lucide.createIcons();

    try {
        let query = `page=${page}&limit=15&status=completed`;
        if (currentFilters.search) query += `&search=${encodeURIComponent(currentFilters.search)}`;

        const response = await API.samples.getAll(query);
        const samplesList = response.data || [];
        renderTable(samplesList);

        // Handle pagination UI
        const pag = response.pagination || {};
        currentPage = pag.page || page;
        const total = pag.total || samplesList.length || 0;
        document.getElementById('pageInfo').innerText = `Showing ${samplesList.length} of ${total} results`;

        document.getElementById('prevBtn').disabled = currentPage <= 1;
        document.getElementById('nextBtn').disabled = (currentPage * 15) >= total;

    } catch (error) {
        showToast('Failed to load static analyses', 'error');
        tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center error-row">Error loading analyses</td></tr>`;
    }
}

function riskChip(riskLevel) {
    if (typeof riskLevel === 'number') {
        if (riskLevel >= 70) return { cls: 'chip--critical', label: String(riskLevel) };
        if (riskLevel >= 40) return { cls: 'chip--warning', label: String(riskLevel) };
        return { cls: 'chip--clear', label: String(riskLevel) };
    }
    const key = (riskLevel || '').toString().toLowerCase();
    if (key === 'high' || key === 'critical') return { cls: 'chip--critical', label: riskLevel };
    if (key === 'medium') return { cls: 'chip--warning', label: riskLevel };
    if (key === 'low') return { cls: 'chip--clear', label: riskLevel };
    return { cls: 'chip--info', label: riskLevel || 'Unknown' };
}

function renderTable(samples) {
    const tbody = document.getElementById('analysesTable');
    if (!samples.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center empty-row">No completed analyses found.</td></tr>`;
        return;
    }

    tbody.innerHTML = samples.map(s => {
        const risk = riskChip(s.riskLevel || s.riskScore);

        return `
        <tr>
            <td class="px-6 py-4 truncate max-w-[200px]" title="${s.filename || 'Unknown'}">${s.filename || 'Unknown'}</td>
            <td class="px-6 py-4 hash-cell truncate max-w-[250px]" title="${s.sha256}">${s.sha256}</td>
            <td class="px-6 py-4">
                <span class="chip chip--clear">Completed</span>
            </td>
            <td class="px-6 py-4">
                <span class="chip ${risk.cls}">${risk.label}</span>
            </td>
            <td class="px-6 py-4 timestamp-cell">${new Date(s.updatedAt || s.createdAt || Date.now()).toLocaleString()}</td>
            <td class="px-6 py-4 text-right">
                <a href="analysis.html?hash=${s.sha256}" class="icon-btn" title="View Analysis">
                    <i data-lucide="microscope" class="w-4 h-4"></i>
                </a>
            </td>
        </tr>
    `}).join('');

    if (window.lucide) window.lucide.createIcons();
}