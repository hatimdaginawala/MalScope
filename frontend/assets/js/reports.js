import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { initThemeToggle } from './theme.js';

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';
    renderSidebar();
    initThemeToggle();
    loadCompletedAnalyses();
});

async function loadCompletedAnalyses() {
    const tbody = document.getElementById('reportsTable');
    tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center empty-row"><i data-lucide="loader-2" class="w-5 h-5 animate-spin mx-auto mb-2"></i>Loading...</td></tr>`;
    if (window.lucide) window.lucide.createIcons();

    try {
        // We fetch samples that have status 'completed'
        const data = await API.samples.getAll('status=completed&limit=50');
        const samples = data.samples || data.data || [];

        if (!samples.length) {
            tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center empty-row">No completed analyses available for reporting.</td></tr>`;
            return;
        }

        tbody.innerHTML = samples.map(s => {
            // Check if backend exposes a threat level, otherwise mock or rely on status
            const threat = s.threatLevel || 'Unknown';
            const key = threat.toLowerCase();
            const chipCls = (key === 'malicious' || key === 'high') ? 'chip--critical' :
                             key === 'suspicious' ? 'chip--warning' :
                             key === 'unknown' ? 'chip--neutral' : 'chip--clear';

            return `
            <tr>
                <td class="px-6 py-4 hash-cell truncate max-w-[250px]">${s.sha256 || 'N/A'}</td>
                <td class="px-6 py-4 timestamp-cell">${new Date(s.updatedAt || Date.now()).toLocaleString()}</td>
                <td class="px-6 py-4">
                    <span class="chip ${chipCls}">${threat}</span>
                </td>
                <td class="px-6 py-4 text-right">
                    <button onclick="downloadReport('${s._id}', 'json')" class="export-btn">JSON</button>
                    <button onclick="downloadReport('${s._id}', 'csv')" class="export-btn">CSV</button>
                </td>
            </tr>
        `}).join('');

    } catch (error) {
        showToast('Failed to load reports', 'error');
        tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center error-row">Error loading reports</td></tr>`;
    }
}

window.downloadReport = async (sampleId, format) => {
    try {
        // Need to get analysis ID for the sample first, or the backend accepts sample ID
        // For standard flow: get analysis by sampleId
        const analysisRes = await API.analysis.getBySampleId(sampleId);
        const analysis = Array.isArray(analysisRes) ? analysisRes[0] : (analysisRes.data || analysisRes);

        if (!analysis || !analysis._id) throw new Error("Analysis not found for this sample");

        if (format === 'json') {
            window.location.href = API.reports.downloadJson(analysis._id);
        } else {
            window.location.href = API.reports.downloadCsv(analysis._id);
        }
    } catch (error) {
        showToast(error.message, 'error');
    }
};