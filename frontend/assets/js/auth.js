import { API } from './api.js';

// Initialize Icons
if (window.lucide) {
    window.lucide.createIcons();
}

// Check if already logged in
document.addEventListener('DOMContentLoaded', () => {
    if (localStorage.getItem('malscope_token')) {
        window.location.href = 'dashboard.html';
    }
});

const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const submitBtn = document.getElementById('submitBtn');
        
        const originalText = submitBtn.innerText;
        submitBtn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin mr-2 inline"></i> Authenticating...`;
        submitBtn.disabled = true;
        if (window.lucide) window.lucide.createIcons();

        try {
            const response = await API.auth.login({ username, password });
            
            // Store token and redirect
            localStorage.setItem('malscope_token', response.data.token);
            if (response.data.user) {
                localStorage.setItem('malscope_user', JSON.stringify(response.data.user));
            }
            
            const Toast = Swal.mixin({
                toast: true, position: 'top-end', showConfirmButton: false, timer: 1000
            });
            await Toast.fire({ icon: 'success', title: 'Authentication successful', background: '#1e293b', color: '#f8fafc' });
            
            window.location.href = 'dashboard.html';
        } catch (error) {
            Swal.fire({
                icon: 'error',
                title: 'Access Denied',
                text: error.message,
                background: '#1e293b',
                color: '#f8fafc',
                confirmButtonColor: '#ef4444'
            });
        } finally {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    });
}
