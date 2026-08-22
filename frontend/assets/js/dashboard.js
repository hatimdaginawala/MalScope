import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { currentTheme, initThemeToggle } from './theme.js';

// Palette — kept in sync with the CSS custom properties in style.css.
// (Canvas contexts can't read CSS vars directly, so the hexes are mirrored here.)
const THEMES = {
    dark: {
        signal: '#e8a33d', info: '#3fa9a0', danger: '#d6544a', clear: '#5fa777',
        line: '#232a32', textMuted: '#8a939e', panel: '#12161b'
    },
    light: {
        signal: '#b97015', info: '#29847c', danger: '#b83e35', clear: '#3f7f56',
        line: '#ddd8ce', textMuted: '#5b6169', panel: '#ffffff'
    }
};

let PALETTE = THEMES[currentTheme()];
let timelineChartInstance = null;
let threatChartInstance = null;

function applyChartTheme() {
    PALETTE = THEMES[currentTheme()];
    Chart.defaults.color = PALETTE.textMuted;
    Chart.defaults.borderColor = PALETTE.line;

    if (timelineChartInstance) {
        const ds = timelineChartInstance.data.datasets[0];
        ds.borderColor = PALETTE.signal;
        ds.pointHoverBackgroundColor = PALETTE.signal;
        timelineChartInstance.options.scales.y.grid.color = PALETTE.line;
        timelineChartInstance.options.scales.y.ticks.color = PALETTE.textMuted;
        timelineChartInstance.options.scales.x.ticks.color = PALETTE.textMuted;
        timelineChartInstance.update();
    }
    if (threatChartInstance) {
        threatChartInstance.data.datasets[0].backgroundColor = [PALETTE.clear, PALETTE.signal, PALETTE.danger];
        threatChartInstance.data.datasets[0].borderColor = PALETTE.panel;
        threatChartInstance.options.plugins.legend.labels.color = PALETTE.textMuted;
        threatChartInstance.update();
    }
}

Chart.defaults.font.family = "'IBM Plex Sans', sans-serif";

const reticleMarkup = `
    <span class="reticle-corner tl"></span><span class="reticle-corner tr"></span>
    <span class="reticle-corner bl"></span><span class="reticle-corner br"></span>
`;

document.addEventListener('DOMContentLoaded', async () => {
    // Check auth
    if (!localStorage.getItem('malscope_token')) {
        window.location.href = 'index.html';
        return;
    }

    renderSidebar();
    initThemeToggle(applyChartTheme);

    // User greeting
    const user = JSON.parse(localStorage.getItem('malscope_user') || '{}');
    if (user.username) {
        document.getElementById('userGreeting').innerHTML = `<i data-lucide="user" class="inline w-3.5 h-3.5 mr-1"></i> ${user.username}`;
    }

    // Logout handler
    document.getElementById('logoutBtn').addEventListener('click', API.auth.logout);

    if (window.lucide) window.lucide.createIcons();

    await loadDashboardData();
});

async function loadDashboardData() {
    try {
        const [statsRes, timelineRes, alertsRes] = await Promise.all([
            API.dashboard.getStats(),
            API.dashboard.getTimeline(),
            API.dashboard.getAlerts()
        ]);

        const statsData = statsRes.data || {};
        const timelineData = timelineRes.data || {};
        const alertsData = alertsRes.data || {};

        renderStats(statsData);
        renderTimelineChart(timelineData);
        renderThreatChart(statsData.threats?.byVerdict || {});
        renderAlerts(alertsData.alerts || []);
    } catch (error) {
        showToast('Failed to load dashboard data', 'error');
        console.error('Dashboard Error:', error);
    }
}

function renderStats(stats) {
    const container = document.getElementById('statsContainer');

    const items = [
        { tag: 'SRC/01', label: 'Total Samples', value: stats.samples?.total || 0, icon: 'database', color: PALETTE.info },
        { tag: 'RUN/02', label: 'Analyses Run', value: stats.analyses?.total || 0, icon: 'activity', color: PALETTE.signal },
        { tag: 'HIT/03', label: 'Malicious Found', value: stats.threats?.byVerdict?.malicious || 0, icon: 'skull', color: PALETTE.danger },
        { tag: 'IOC/04', label: 'IOCs Tracked', value: stats.iocs?.total || 0, icon: 'shield-alert', color: PALETTE.signal }
    ];

    container.innerHTML = items.map(item => `
        <div class="scope-card flex items-center justify-between">
            ${reticleMarkup}
            <span class="scope-tag">${item.tag}</span>
            <div>
                <p class="stat-label">${item.label}</p>
                <h4 class="stat-value">${item.value}</h4>
            </div>
            <div class="stat-icon-well">
                <i data-lucide="${item.icon}" class="w-5 h-5" style="color: ${item.color}"></i>
            </div>
        </div>
    `).join('');

    if (window.lucide) window.lucide.createIcons();
}

function renderTimelineChart(timelineData) {
    const ctx = document.getElementById('timelineChart').getContext('2d');

    const tl = timelineData.timeline || [];
    const labels = tl.length ? tl.map(t => t.date) : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const values = tl.length ? tl.map(t => t.total) : [0,0,0,0,0,0,0];

    timelineChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Analyses per day',
                data: values,
                borderColor: PALETTE.signal,
                backgroundColor: 'rgba(232, 163, 61, 0.08)',
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: PALETTE.signal,
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true, grid: { color: PALETTE.line }, ticks: { color: PALETTE.textMuted, font: { family: "'IBM Plex Mono', monospace", size: 11 } } },
                x: { grid: { display: false }, ticks: { color: PALETTE.textMuted, font: { family: "'IBM Plex Mono', monospace", size: 11 } } }
            }
        }
    });
}

function renderThreatChart(distribution) {
    const ctx = document.getElementById('threatChart').getContext('2d');

    const labels = Object.keys(distribution).length ? Object.keys(distribution) : ['Clean', 'Suspicious', 'Malicious'];
    const data = Object.values(distribution).length ? Object.values(distribution) : [0, 0, 0];

    threatChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [PALETTE.clear, PALETTE.signal, PALETTE.danger],
                borderColor: PALETTE.panel,
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '75%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: PALETTE.textMuted, font: { family: "'IBM Plex Mono', monospace", size: 11 }, boxWidth: 10 }
                }
            }
        }
    });
}

function severityChip(severity) {
    const key = (severity || '').toLowerCase();
    if (key === 'critical' || key === 'malicious') return { cls: 'chip--critical', label: severity || 'Critical' };
    if (key === 'suspicious' || key === 'warning') return { cls: 'chip--warning', label: severity || 'Warning' };
    if (key === 'clean') return { cls: 'chip--clear', label: severity || 'Clean' };
    return { cls: 'chip--info', label: severity || 'Alert' };
}

function renderAlerts(alerts) {
    const tbody = document.getElementById('alertsTable');
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="px-4 py-6 text-center empty-row">No recent alerts.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.slice(0, 5).map(alert => {
        const hash = alert.data?.sha256 || alert.data?.value || 'N/A';
        const link = alert.data?.sampleId ? `analysis.html?hash=${hash}` : '#';
        const chip = severityChip(alert.severity);

        return `
        <tr>
            <td class="px-4 py-3 whitespace-nowrap timestamp-cell">${new Date(alert.timestamp).toLocaleString()}</td>
            <td class="px-4 py-3 whitespace-nowrap hash-cell truncate max-w-[200px]" title="${hash}">${hash}</td>
            <td class="px-4 py-3 whitespace-nowrap">
                <span class="chip ${chip.cls}">${chip.label}</span>
            </td>
            <td class="px-4 py-3 text-right">
                <a href="${link}" class="log-link">View <i data-lucide="arrow-right" class="w-3 h-3 inline"></i></a>
            </td>
        </tr>
    `}).join('');

    if (window.lucide) window.lucide.createIcons();
}