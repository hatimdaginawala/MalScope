import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';
    renderSidebar();
    loadCompletedAnalyses();
});

async function loadCompletedAnalyses() {
    const tbody = document.getElementById('reportsTable');
    tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center text-slate-500"><i data-lucide="loader-2" class="w-6 h-6 animate-spin mx-auto mb-2"></i>Loading...</td></tr>`;
    if (window.lucide) window.lucide.createIcons();

    try {
        // We fetch samples that have status 'completed'
        const data = await API.samples.getAll('status=completed&limit=50');
        const samples = data.samples || data.data || [];
        
        if (!samples.length) {
            tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center text-slate-500">No completed analyses available for reporting.</td></tr>`;
            return;
        }

        tbody.innerHTML = samples.map(s => {
            // Check if backend exposes a threat level, otherwise mock or rely on status
            const threat = s.threatLevel || 'Unknown';
            const threatColor = threat.toLowerCase() === 'malicious' || threat.toLowerCase() === 'high' ? 'text-red-500 bg-red-500/10 border-red-500/20' : 
                                threat.toLowerCase() === 'suspicious' ? 'text-amber-500 bg-amber-500/10 border-amber-500/20' : 
                                'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';

            return `
            <tr class="hover:bg-slate-800/50 transition-colors">
                <td class="px-6 py-4 mono text-slate-300 truncate max-w-[250px] text-xs">${s.sha256 || 'N/A'}</td>
                <td class="px-6 py-4 text-slate-400 text-xs">${new Date(s.updatedAt || Date.now()).toLocaleString()}</td>
                <td class="px-6 py-4">
                    <span class="px-2.5 py-1 rounded-full text-[10px] uppercase font-bold tracking-wider border ${threatColor}">
                        ${threat}
                    </span>
                </td>
                <td class="px-6 py-4 text-right">
                    <button onclick="downloadReport('${s._id}', 'json')" class="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs transition-colors mr-2">JSON</button>
                    <button onclick="downloadReport('${s._id}', 'csv')" class="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs transition-colors">CSV</button>
                </td>
            </tr>
        `}).join('');

    } catch (error) {
        showToast('Failed to load reports', 'error');
        tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center text-red-500">Error loading reports</td></tr>`;
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
