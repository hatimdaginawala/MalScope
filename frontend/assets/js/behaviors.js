import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { initThemeToggle } from './theme.js';

let currentPage = 1;
let currentFilters = {};
let allBehaviors = [];
const itemsPerPage = 15;

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';

    renderSidebar();
    initThemeToggle();

    document.getElementById('refreshBtn').addEventListener('click', () => {
        currentPage = 1;
        fetchAndAggregateBehaviors();
    });

    let timeout = null;
    document.getElementById('searchInput').addEventListener('input', (e) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            currentFilters.search = e.target.value.toLowerCase();
            currentPage = 1;
            renderBehaviors();
        }, 500);
    });

    document.getElementById('prevBtn').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderBehaviors();
        }
    });

    document.getElementById('nextBtn').addEventListener('click', () => {
        currentPage++;
        renderBehaviors();
    });

    fetchAndAggregateBehaviors();
});

async function fetchAndAggregateBehaviors() {
    const tbody = document.getElementById('behaviorsTable');
    tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center empty-row"><i data-lucide="loader-2" class="w-5 h-5 animate-spin mx-auto mb-2"></i>Loading behaviors from recent samples...</td></tr>`;
    if (window.lucide) window.lucide.createIcons();

    try {
        // Fetch recent completed samples
        const response = await API.samples.getAll('limit=10&status=completed');
        const samples = response.data || [];

        const behaviors = [];

        for (const sample of samples) {
            try {
                // Get analysis ID for sample
                const analysisRes = await API.analysis.getBySampleId(sample._id);

                let analysisId;
                if (analysisRes.data && Array.isArray(analysisRes.data) && analysisRes.data.length > 0) {
                    analysisId = analysisRes.data[0]._id;
                } else if (analysisRes.data && analysisRes.data._id) {
                    analysisId = analysisRes.data._id;
                } else if (analysisRes._id) {
                    analysisId = analysisRes._id;
                } else if (Array.isArray(analysisRes) && analysisRes.length > 0) {
                    analysisId = analysisRes[0]._id;
                }

                if (analysisId) {
                    // Fetch findings
                    const findingsRes = await API.analysis.static.getFindings(analysisId);
                    if (findingsRes && findingsRes.data && Array.isArray(findingsRes.data.findings)) {
                        findingsRes.data.findings.forEach(finding => {
                            behaviors.push({
                                category: finding.type, // map type to category column
                                severity: finding.severity,
                                description: finding.description || finding.evidence || '',
                                confidence: finding.confidence,
                                sampleHash: sample.sha256 // optional context
                            });
                        });
                    }
                }
            } catch (err) {
                console.warn(`Could not fetch analysis for sample ${sample._id}`, err);
            }
        }

        allBehaviors = behaviors;
        renderBehaviors();

    } catch (error) {
        showToast('Failed to load behaviors', 'error');
        tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center error-row">Error loading behaviors</td></tr>`;
    }
}

function severityChip(severity) {
    const key = (severity || '').toLowerCase();
    if (key === 'high') return { cls: 'chip--critical', label: severity };
    if (key === 'medium') return { cls: 'chip--warning', label: severity };
    if (key === 'low') return { cls: 'chip--info', label: severity };
    return { cls: 'chip--info', label: severity || 'Unknown' };
}

function renderBehaviors() {
    const tbody = document.getElementById('behaviorsTable');

    // Filter
    let filtered = allBehaviors;
    if (currentFilters.search) {
        const query = currentFilters.search;
        filtered = filtered.filter(b =>
            (b.category && b.category.toLowerCase().includes(query)) ||
            (b.description && b.description.toLowerCase().includes(query)) ||
            (b.severity && b.severity.toLowerCase().includes(query))
        );
    }

    const total = filtered.length;
    const startIdx = (currentPage - 1) * itemsPerPage;
    const paginated = filtered.slice(startIdx, startIdx + itemsPerPage);

    if (!paginated.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center empty-row">No behaviors found.</td></tr>`;
    } else {
        tbody.innerHTML = paginated.map(b => {
            const chip = severityChip(b.severity);

            return `
            <tr>
                <td class="px-6 py-4 truncate max-w-[200px]" title="${b.category || 'Unknown'}">${b.category || 'Unknown'}</td>
                <td class="px-6 py-4">
                    <span class="chip ${chip.cls}">${chip.label}</span>
                </td>
                <td class="px-6 py-4 truncate max-w-[400px]" title="${b.description || ''}" style="color: var(--text-muted);">${b.description || ''}</td>
                <td class="px-6 py-4 timestamp-cell">${b.confidence || 'N/A'}</td>
            </tr>
            `;
        }).join('');
    }

    if (window.lucide) window.lucide.createIcons();

    // Update pagination info
    document.getElementById('pageInfo').innerText = `Showing ${paginated.length > 0 ? startIdx + 1 : 0} to ${Math.min(startIdx + itemsPerPage, total)} of ${total} results`;
    document.getElementById('prevBtn').disabled = currentPage <= 1;
    document.getElementById('nextBtn').disabled = startIdx + itemsPerPage >= total;
}