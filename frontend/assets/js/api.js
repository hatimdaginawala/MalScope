const API_BASE = 'http://localhost:5000/api/v1'; // Adjust port if needed

// Core Fetch Wrapper
async function fetchAPI(endpoint, options = {}) {
    const token = localStorage.getItem('malscope_token');
    
    const headers = {
        ...options.headers
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    // Don't set Content-Type if it's FormData (browser will set it with boundary)
    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }

    const config = {
        ...options,
        headers
    };

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, config);
        
        // Handle 401 Unauthorized globally
        if (response.status === 401 && !endpoint.includes('/auth/login')) {
            localStorage.removeItem('malscope_token');
            localStorage.removeItem('malscope_user');
            window.location.href = 'index.html';
            return null;
        }

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || data.error || 'API request failed');
        }
        
        // Return full payload so endpoints with pagination metadata aren't lost
        return data;
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        throw error;
    }
}

// API Services
export const API = {
    auth: {
        login: (credentials) => fetchAPI('/auth/login', { method: 'POST', body: JSON.stringify(credentials) }),
        register: (userData) => fetchAPI('/auth/register', { method: 'POST', body: JSON.stringify(userData) }),
        me: () => fetchAPI('/auth/me', { method: 'GET' }),
        logout: () => {
            localStorage.removeItem('malscope_token');
            localStorage.removeItem('malscope_user');
            window.location.href = 'index.html';
        }
    },
    users: {
        getAll: (params = '') => fetchAPI(`/users${params ? '?' + params : ''}`),
        getById: (id) => fetchAPI(`/users/${id}`),
        create: (userData) => fetchAPI('/auth/register', { method: 'POST', body: JSON.stringify(userData) }),
        update: (id, userData) => fetchAPI(`/users/${id}`, { method: 'PUT', body: JSON.stringify(userData) }),
        delete: (id) => fetchAPI(`/users/${id}`, { method: 'DELETE' })
    },
    dashboard: {
        getStats: () => fetchAPI('/dashboard/stats'),
        getTimeline: () => fetchAPI('/dashboard/timeline'),
        getAlerts: () => fetchAPI('/dashboard/alerts'),
        getWidgets: () => fetchAPI('/dashboard/widgets'),
        getDaily: () => fetchAPI('/dashboard/daily')
    },
    samples: {
        getAll: (params = '') => fetchAPI(`/samples${params ? '?' + params : ''}`),
        getById: (id) => fetchAPI(`/samples/${id}`),
        getByHash: (hash) => fetchAPI(`/samples/hash/${hash}`),
        upload: (formData) => fetchAPI('/samples', { method: 'POST', body: formData }),
        delete: (id) => fetchAPI(`/samples/${id}`, { method: 'DELETE' }),
        addTags: (id, tags) => fetchAPI(`/samples/${id}/tags`, { method: 'POST', body: JSON.stringify({ tags }) }),
        removeTags: (id, tags) => fetchAPI(`/samples/${id}/tags`, { method: 'DELETE', body: JSON.stringify({ tags }) }),
        download: (id) => `${API_BASE}/samples/${id}/download?token=${localStorage.getItem('malscope_token')}`
    },
    analysis: {
        getAll: (params = '') => fetchAPI(`/analyses/stats`), // Or a dedicated list route if it exists
        trigger: (data) => fetchAPI('/analyses', { method: 'POST', body: JSON.stringify(data) }),
        getStatus: (id) => fetchAPI(`/analyses/${id}/status`),
        getById: (id) => fetchAPI(`/analyses/${id}`),
        getBySampleId: (sampleId) => fetchAPI(`/analyses/sample/${sampleId}`),
        static: {
            getFull: (analysisId) => fetchAPI(`/analyses/${analysisId}/static`),
            getSummary: (analysisId) => fetchAPI(`/analyses/${analysisId}/static/summary`),
            getApiIntel: (analysisId) => fetchAPI(`/analyses/${analysisId}/static/api-intelligence`),
            getPeInfo: (analysisId) => fetchAPI(`/analyses/${analysisId}/static/pe-info`),
            getYara: (analysisId) => fetchAPI(`/analyses/${analysisId}/static/yara`),
            getFindings: (analysisId) => fetchAPI(`/analyses/${analysisId}/static/findings`)
        }
    },
    threatIntel: {
        searchIP: (ip) => fetchAPI(`/threat-intel/iocs/search?query=${ip}`),
        searchDomain: (domain) => fetchAPI(`/threat-intel/iocs/search?query=${domain}`),
        searchHash: (hash) => fetchAPI(`/threat-intel/iocs/search?query=${hash}`),
        getIOCs: (params = '') => fetchAPI(`/threat-intel/iocs${params ? '?' + params : ''}`)
    },
    reports: {
        generate: (analysisId, format = 'json') => fetchAPI(`/reports/${analysisId}`, { method: 'POST', body: JSON.stringify({ format }) }),
        getFormats: () => fetchAPI('/reports/formats'),
        getSummary: (analysisId) => fetchAPI(`/reports/${analysisId}/summary`),
        downloadJson: (analysisId) => `${API_BASE}/reports/${analysisId}/download/json?token=${localStorage.getItem('malscope_token')}`,
        downloadCsv: (analysisId) => `${API_BASE}/reports/${analysisId}/download/csv?token=${localStorage.getItem('malscope_token')}`
    }
};
