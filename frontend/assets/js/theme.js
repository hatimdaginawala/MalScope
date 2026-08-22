// Shared across all pages: dark is the enforced default (see the blocking
// script in each page's <head>); this just wires up the topbar toggle button
// and gives pages a way to color SweetAlert modals to match the active theme.

export function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

export function initThemeToggle(onChange) {
    const btn = document.getElementById('themeToggle');
    if (!btn) return;
    btn.addEventListener('click', () => {
        const next = currentTheme() === 'light' ? 'dark' : 'light';
        if (next === 'light') {
            document.documentElement.setAttribute('data-theme', 'light');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        localStorage.setItem('malscope_theme', next);
        btn.setAttribute('aria-label', next === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
        if (typeof onChange === 'function') onChange(next);
    });
}

// SweetAlert2 can't read CSS variables, so hand back matching hexes.
export function swalTheme() {
    const light = currentTheme() === 'light';
    return {
        background: light ? '#ffffff' : '#12161b',
        color: light ? '#1c2024' : '#edeae3',
        borderColor: light ? '#ddd8ce' : '#232a32',
        confirmColor: light ? '#b97015' : '#e8a33d',
        dangerColor: light ? '#b83e35' : '#d6544a',
        cancelColor: light ? '#f7f5ef' : '#1a1f26'
    };
}