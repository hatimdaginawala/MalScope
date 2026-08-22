import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { initThemeToggle } from './theme.js';

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';
    renderSidebar();
    initThemeToggle();

    document.getElementById('threatSearchForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const type = document.getElementById('indicatorType').value;
        const value = document.getElementById('indicatorValue').value.trim();
        if (!value) return;

        const btn = e.target.querySelector('button');
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i>';
        if (window.lucide) window.lucide.createIcons();

        try {
            let res;
            if (type === 'hash') res = await API.threatIntel.searchHash(value);
            else if (type === 'ip') res = await API.threatIntel.searchIP(value);
            else if (type === 'domain') res = await API.threatIntel.searchDomain(value);

            renderResults(res.data || res);
        } catch (error) {
            showToast(error.message || 'Threat intel lookup failed', 'error');
            document.getElementById('resultsContainer').classList.add('hidden');
        } finally {
            btn.innerHTML = origHTML;
        }
    });
});

function renderResults(data) {
    const container = document.getElementById('resultsContainer');
    const scoreBadge = document.getElementById('threatScore');
    const content = document.getElementById('resultsContent');

    container.classList.remove('hidden');

    // Simple heuristic for score/badge
    const maliciousCount = data.malicious || 0;
    const totalEngines = data.total || 0;

    if (maliciousCount > 0) {
        scoreBadge.className = 'chip chip--critical';
        scoreBadge.innerText = `Malicious (${maliciousCount}/${totalEngines})`;
    } else if (totalEngines > 0) {
        scoreBadge.className = 'chip chip--clear';
        scoreBadge.innerText = `Clean (0/${totalEngines})`;
    } else {
        scoreBadge.className = 'chip chip--info';
        scoreBadge.innerText = `No data / unknown`;
    }

    content.innerHTML = `
        <div class="grid grid-cols-2 gap-4 mb-4">
            <div>
                <span class="field-label">Indicator</span>
                <span class="field-value">${data.indicator || document.getElementById('indicatorValue').value}</span>
            </div>
            <div>
                <span class="field-label">Reputation</span>
                <span class="field-value">${data.reputation || 'N/A'}</span>
            </div>
        </div>
        <div class="data-readout">
            <pre>${JSON.stringify(data.details || data, null, 2)}</pre>
        </div>
    `;
}