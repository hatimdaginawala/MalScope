import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';

let analysisId = null;
let sampleHash = null;

let currentAnalysis = null;

document.addEventListener('DOMContentLoaded', async () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';
    renderSidebar();

    const urlParams = new URLSearchParams(window.location.search);
    sampleHash = urlParams.get('hash');
    const aid = urlParams.get('id');

    if (!sampleHash && !aid) {
        showToast('No sample or analysis ID provided.', 'error');
        return;
    }

    setupTabs();

    try {
        if (sampleHash) {
            document.getElementById('hashLabel').innerText = sampleHash;
            const sampleData = await API.samples.getByHash(sampleHash);
            const sample = sampleData.sample || sampleData.data || sampleData;
            
            const analysisRes = await API.analysis.getBySampleId(sample._id);
            let extracted = analysisRes.data || analysisRes;
            if (Array.isArray(extracted)) {
                currentAnalysis = extracted.find(a => a.status === 'completed') || extracted[0];
            } else {
                currentAnalysis = extracted;
            }
            if (currentAnalysis) analysisId = currentAnalysis._id;
        } else if (aid) {
            analysisId = aid;
            const analysisData = await API.analysis.getById(analysisId);
            let extracted = analysisData.data || analysisData;
            currentAnalysis = Array.isArray(extracted) ? extracted[0] : extracted;
            if (currentAnalysis && currentAnalysis.sample) {
                document.getElementById('hashLabel').innerText = currentAnalysis.sample.sha256 || 'Unknown Hash';
            }
        }

        if (analysisId && currentAnalysis) {
            loadStaticAnalysisData();
        } else {
            document.getElementById('statusBadge').innerText = 'NO ANALYSIS FOUND';
            document.getElementById('statusBadge').className = 'px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-slate-500/10 text-slate-400 border border-slate-500/20';
            clearLoadingStates('No analysis data available.');
        }

    } catch (error) {
        showToast(error.message, 'error');
        clearLoadingStates('Failed to load analysis.');
    }
});

function setupTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => {
                t.classList.remove('text-emerald-500', 'border-emerald-500');
                t.classList.add('text-slate-400', 'border-transparent');
            });
            contents.forEach(c => c.classList.add('hidden'));

            tab.classList.remove('text-slate-400', 'border-transparent');
            tab.classList.add('text-emerald-500', 'border-emerald-500');
            document.getElementById(`tab-${tab.dataset.target}`).classList.remove('hidden');
        });
    });
}

function clearLoadingStates(message) {
    document.getElementById('fileInfoTable').innerHTML = `<tr><td class="py-2 text-slate-500">${message}</td></tr>`;
    document.getElementById('hashesTable').innerHTML = `<tr><td class="py-2 text-slate-500">${message}</td></tr>`;
    document.getElementById('apiIntelContent').innerHTML = `<span class="text-slate-500">${message}</span>`;
    document.getElementById('importsContent').innerHTML = `<span class="text-slate-500">${message}</span>`;
    document.getElementById('sectionsContent').innerHTML = `<tr><td colspan="5" class="px-4 py-4 text-slate-500">${message}</td></tr>`;
    document.getElementById('signaturesContent').innerHTML = `<span class="text-slate-500">${message}</span>`;
    document.getElementById('stringsContent').innerHTML = `<span class="text-slate-500">${message}</span>`;
}

async function loadStaticAnalysisData() {
    const status = currentAnalysis.status || 'unknown';
    const badge = document.getElementById('statusBadge');
    
    if (status === 'failed') {
        badge.innerText = 'FAILED';
        badge.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-red-500/10 text-red-500 border border-red-500/20';
        const errMsg = currentAnalysis.errorInfo?.message || 'Analysis failed to execute or the file is not a supported PE file.';
        clearLoadingStates(`Analysis Failed: ${errMsg}`);
        return;
    }

    badge.innerText = status.toUpperCase();
    badge.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-500 border border-emerald-500/20';

    try {
        const [summary, intel, peInfo, yara] = await Promise.allSettled([
            API.analysis.static.getSummary(analysisId),
            API.analysis.static.getApiIntel(analysisId),
            API.analysis.static.getPeInfo(analysisId),
            API.analysis.static.getYara(analysisId)
        ]);

        if (summary.status === 'fulfilled') renderSummary(summary.value.data || {});
        
        // API intel structure varies depending on whether highRiskApis or capabilities are populated
        if (intel.status === 'fulfilled') {
            const d = intel.value.data || {};
            renderIntel(d.highRiskApis || d.capabilities || d.categories || []);
        }

        if (peInfo.status === 'fulfilled') {
            const peData = peInfo.value.data || {};
            renderImports(peData.imports || []);
            renderSections(peData.sections || []);
            
            // Strings could be an array or an object depending on parsing backend
            let strArray = [];
            if (Array.isArray(peData.strings)) strArray = peData.strings;
            else if (peData.strings && Array.isArray(peData.strings.all)) strArray = peData.strings.all;
            else if (peData.strings) strArray = Object.values(peData.strings).flat();
            renderStrings(strArray);
        }

        if (yara.status === 'fulfilled') renderSignatures(yara.value.data?.matches || []);

    } catch(err) {
        console.error("Partial load failure", err);
    }
}

function renderSummary(data) {
    const info = data.fileInfo || data || {};
    
    const infoTbody = document.getElementById('fileInfoTable');
    infoTbody.innerHTML = `
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium w-1/3">File Type</td><td class="py-2.5">${info.fileType || 'Unknown'}</td></tr>
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium">Size</td><td class="py-2.5">${info.fileSize || info.size ? ((info.fileSize || info.size) / 1024).toFixed(2) + ' KB' : 'N/A'}</td></tr>
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium">Architecture</td><td class="py-2.5">${info.arch || info.architecture || 'N/A'}</td></tr>
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium">Compiler</td><td class="py-2.5">${info.compiler || 'N/A'}</td></tr>
    `;

    const hashesTbody = document.getElementById('hashesTable');
    hashesTbody.innerHTML = `
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium w-1/4">MD5</td><td class="py-2.5 mono text-xs">${info.md5 || 'N/A'}</td></tr>
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium">SHA1</td><td class="py-2.5 mono text-xs">${info.sha1 || 'N/A'}</td></tr>
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium">SHA256</td><td class="py-2.5 mono text-xs">${info.sha256 || 'N/A'}</td></tr>
        <tr><td class="py-2.5 pr-4 text-slate-400 font-medium">Imphash</td><td class="py-2.5 mono text-xs">${info.imphash || 'N/A'}</td></tr>
    `;
}

function renderIntel(data) {
    const el = document.getElementById('apiIntelContent');
    if (!data || !data.length) { el.innerHTML = '<span class="text-slate-500">No suspicious APIs detected.</span>'; return; }
    el.innerHTML = `<ul class="space-y-2 text-sm">${data.map(api => {
        const apiName = api.api || api.name || (typeof api === 'string' ? api : JSON.stringify(api));
        const category = api.category || api.description || '';
        return `<li><span class="text-amber-500 font-bold mr-2 mono">${apiName}</span>${category ? `<span class="text-slate-400 text-xs">- ${category}</span>` : ''}</li>`;
    }).join('')}</ul>`;
}

function renderImports(data) {
    const el = document.getElementById('importsContent');
    if (!data || !data.length) { el.innerHTML = '<span class="text-slate-500">No imports found.</span>'; return; }
    
    let html = '<div class="space-y-4">';
    data.forEach(dll => {
        html += `<div>
            <h4 class="text-emerald-500 font-semibold mb-1">${dll.dll || dll.name || 'Unknown DLL'}</h4>
            <div class="flex flex-wrap gap-2">
                ${(dll.imports || dll.functions || []).map(imp => `<span class="px-2 py-1 bg-slate-700 rounded text-xs mono text-slate-300">${imp.name || imp}</span>`).join('')}
            </div>
        </div>`;
    });
    html += '</div>';
    el.innerHTML = html;
}

function renderSections(data) {
    const tbody = document.getElementById('sectionsContent');
    if (!data || !data.length) { tbody.innerHTML = '<tr><td colspan="5" class="px-4 py-4 text-slate-500">No sections found.</td></tr>'; return; }
    
    tbody.innerHTML = data.map(sec => `
        <tr class="hover:bg-slate-800/50">
            <td class="px-4 py-3 font-medium text-slate-300">${sec.name || ''}</td>
            <td class="px-4 py-3 mono text-xs">${sec.virtualAddress || ''}</td>
            <td class="px-4 py-3 mono text-xs">${sec.virtualSize || ''}</td>
            <td class="px-4 py-3 mono text-xs">${sec.rawSize || ''}</td>
            <td class="px-4 py-3 ${sec.entropy > 7 ? 'text-red-500 font-bold' : ''}">${sec.entropy ? sec.entropy.toFixed(2) : ''}</td>
        </tr>
    `).join('');
}

function renderSignatures(data) {
    const el = document.getElementById('signaturesContent');
    if (!data || !data.length) { el.innerHTML = '<span class="text-slate-500">No signatures matched.</span>'; return; }
    el.innerHTML = `<ul class="space-y-2 text-sm">${data.map(sig => `<li><span class="text-red-500 font-bold mr-2">${sig.name || sig}</span> - <span class="text-slate-400">${sig.description || ''}</span></li>`).join('')}</ul>`;
}

let allStrings = [];
function renderStrings(data) {
    allStrings = data || [];
    updateStringsView(allStrings);

    document.getElementById('stringSearch').addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        if(!query) updateStringsView(allStrings);
        else updateStringsView(allStrings.filter(s => s.toLowerCase().includes(query)));
    });
}

function updateStringsView(stringsArray) {
    const el = document.getElementById('stringsContent');
    if (!stringsArray || !stringsArray.length) { 
        el.innerHTML = '<span class="text-slate-500">No strings found or matched.</span>'; 
        return; 
    }
    // Limit to 1000 to prevent DOM lag
    el.innerHTML = stringsArray.slice(0, 1000).join('\n') + (stringsArray.length > 1000 ? '\n\n... (truncated)' : '');
}
