import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { initThemeToggle, swalTheme } from './theme.js';

let currentPage = 1;
let currentFilters = {};

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';

    renderSidebar();
    initThemeToggle();

    document.getElementById('refreshBtn').addEventListener('click', () => loadSamples(currentPage));
    document.getElementById('uploadBtn').addEventListener('click', openUploadModal);

    // Search with debounce
    let timeout = null;
    document.getElementById('searchInput').addEventListener('input', (e) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            currentFilters.search = e.target.value;
            currentPage = 1;
            loadSamples();
        }, 500);
    });

    document.getElementById('statusFilter').addEventListener('change', (e) => {
        currentFilters.status = e.target.value;
        currentPage = 1;
        loadSamples();
    });

    document.getElementById('prevBtn').addEventListener('click', () => {
        if (currentPage > 1) loadSamples(currentPage - 1);
    });
    document.getElementById('nextBtn').addEventListener('click', () => {
        loadSamples(currentPage + 1);
    });

    loadSamples();
});

async function loadSamples(page = 1) {
    const tbody = document.getElementById('samplesTable');
    tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center empty-row"><i data-lucide="loader-2" class="w-5 h-5 animate-spin mx-auto mb-2"></i>Loading...</td></tr>`;
    if (window.lucide) window.lucide.createIcons();

    try {
        let query = `page=${page}&limit=15`;
        if (currentFilters.search) query += `&search=${encodeURIComponent(currentFilters.search)}`;
        if (currentFilters.status) query += `&status=${currentFilters.status}`;

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
        showToast('Failed to load samples', 'error');
        tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center error-row">Error loading samples</td></tr>`;
    }
}

function statusChip(status) {
    const key = (status || 'pending').toLowerCase();
    if (key === 'completed') return { cls: 'chip--clear', label: 'Completed' };
    if (key === 'analyzing') return { cls: 'chip--warning', label: 'Analyzing' };
    return { cls: 'chip--info', label: status || 'Pending' };
}

function renderTable(samples) {
    const tbody = document.getElementById('samplesTable');
    if (!samples.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center empty-row">No samples found.</td></tr>`;
        return;
    }

    tbody.innerHTML = samples.map(s => {
        const chip = statusChip(s.status);
        return `
        <tr>
            <td class="px-6 py-4 truncate max-w-[200px]" title="${s.filename || 'Unknown'}">${s.filename || 'Unknown'}</td>
            <td class="px-6 py-4 hash-cell truncate max-w-[250px]" title="${s.sha256}">${s.sha256}</td>
            <td class="px-6 py-4">
                <span class="chip ${chip.cls}">${chip.label}</span>
            </td>
            <td class="px-6 py-4 timestamp-cell">${new Date(s.createdAt || Date.now()).toLocaleString()}</td>
            <td class="px-6 py-4 text-right">
                ${s.status === 'pending' ? `<button onclick="analyzeSample('${s._id}')" class="icon-btn icon-btn--clear" title="Analyze">
                    <i data-lucide="play" class="w-4 h-4"></i>
                </button>` : ''}
                <a href="analysis.html?hash=${s.sha256}" class="icon-btn" title="View Analysis">
                    <i data-lucide="microscope" class="w-4 h-4"></i>
                </a>
                <button onclick="downloadSample('${s._id}')" class="icon-btn icon-btn--info" title="Download">
                    <i data-lucide="download" class="w-4 h-4"></i>
                </button>
                <button onclick="deleteSample('${s._id}')" class="icon-btn icon-btn--danger" title="Delete">
                    <i data-lucide="trash-2" class="w-4 h-4"></i>
                </button>
            </td>
        </tr>
    `}).join('');

    if (window.lucide) window.lucide.createIcons();
}

window.analyzeSample = async (id) => {
    const t = swalTheme();
    try {
        Swal.fire({
            title: 'Starting analysis...',
            text: 'Queueing sample for static analysis.',
            allowOutsideClick: false,
            background: t.background,
            color: t.color,
            didOpen: () => { Swal.showLoading(); }
        });

        await API.analysis.trigger({ sampleId: id });
        showToast('Analysis triggered successfully');
        loadSamples(currentPage);
    } catch (error) {
        Swal.fire({
            icon: 'error',
            title: 'Analysis failed',
            text: error.message,
            background: t.background,
            color: t.color,
            confirmButtonColor: t.dangerColor
        });
    }
};

window.downloadSample = (id) => {
    window.location.href = API.samples.download(id);
};

window.deleteSample = async (id) => {
    const t = swalTheme();
    const result = await Swal.fire({
        title: 'Delete sample?',
        text: 'This will permanently delete the sample and its analysis data.',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: t.dangerColor,
        cancelButtonColor: t.cancelColor,
        confirmButtonText: 'Yes, delete it',
        background: t.background,
        color: t.color
    });

    if (result.isConfirmed) {
        try {
            await API.samples.delete(id);
            showToast('Sample deleted successfully');
            loadSamples(currentPage);
        } catch (error) {
            showToast(error.message, 'error');
        }
    }
};

async function openUploadModal() {
    const t = swalTheme();
    const { value: file } = await Swal.fire({
        title: 'Upload malware sample',
        input: 'file',
        inputAttributes: {
            'accept': '*/*',
            'aria-label': 'Upload your sample'
        },
        background: t.background,
        color: t.color,
        showCancelButton: true,
        confirmButtonText: 'Upload & analyze',
        confirmButtonColor: t.confirmColor,
        cancelButtonColor: t.cancelColor
    });

    if (file) {
        const formData = new FormData();
        formData.append('file', file);

        Swal.fire({
            title: 'Uploading...',
            text: 'Please wait while the file is processed.',
            allowOutsideClick: false,
            background: t.background,
            color: t.color,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        try {
            await API.samples.upload(formData);
            showToast('File uploaded successfully');
            loadSamples(1);
        } catch (error) {
            Swal.fire({
                icon: 'error',
                title: 'Upload failed',
                text: error.message,
                background: t.background,
                color: t.color,
                confirmButtonColor: t.dangerColor
            });
        }
    }
}