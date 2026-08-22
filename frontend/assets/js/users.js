import { API } from './api.js';
import { renderSidebar, showToast } from './components.js';
import { initThemeToggle, swalTheme } from './theme.js';

let currentPage = 1;
const limit = 10;
let searchQuery = '';

document.addEventListener('DOMContentLoaded', () => {
    if (!localStorage.getItem('malscope_token')) return window.location.href = 'index.html';

    renderSidebar();
    initThemeToggle();
    loadUsers();
    setupEventListeners();
});

function setupEventListeners() {
    document.getElementById('refreshBtn').addEventListener('click', () => loadUsers());

    document.getElementById('searchInput').addEventListener('input', (e) => {
        searchQuery = e.target.value;
        currentPage = 1;
        clearTimeout(window.searchTimeout);
        window.searchTimeout = setTimeout(loadUsers, 500);
    });

    document.getElementById('prevBtn').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadUsers();
        }
    });

    document.getElementById('nextBtn').addEventListener('click', () => {
        currentPage++;
        loadUsers();
    });

    document.getElementById('addUserBtn').addEventListener('click', showAddUserModal);

    document.getElementById('usersTable').addEventListener('click', (e) => {
        const editBtn = e.target.closest('.edit-user-btn');
        const delBtn = e.target.closest('.delete-user-btn');

        if (editBtn) {
            const id = editBtn.dataset.id;
            const role = editBtn.dataset.role;
            const active = editBtn.dataset.active;
            showEditUserModal(id, role, active);
        } else if (delBtn) {
            const id = delBtn.dataset.id;
            deleteUser(id);
        }
    });
}

async function loadUsers() {
    const tableBody = document.getElementById('usersTable');
    tableBody.innerHTML = '<tr><td colspan="6" class="px-6 py-8 text-center empty-row">Loading users...</td></tr>';

    try {
        let query = `page=${currentPage}&limit=${limit}`;
        if (searchQuery) query += `&search=${encodeURIComponent(searchQuery)}`;

        const response = await API.users.getAll(query);
        const { data, pagination } = response;

        renderUsersTable(data);
        updatePagination(pagination);
        if (window.lucide) window.lucide.createIcons();
    } catch (error) {
        tableBody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center error-row">Failed to load users: ${error.message}</td></tr>`;
        showToast('Failed to load users', 'error');
    }
}

function roleChip(role) {
    const key = (role || '').toLowerCase();
    if (key === 'admin') return { cls: 'chip--warning', label: role };
    if (key === 'analyst') return { cls: 'chip--info', label: role };
    return { cls: 'chip--neutral', label: role || 'Unknown' };
}

function renderUsersTable(users) {
    const tableBody = document.getElementById('usersTable');

    if (users.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" class="px-6 py-8 text-center empty-row">No users found.</td></tr>';
        return;
    }

    tableBody.innerHTML = users.map(user => {
        const role = roleChip(user.role);
        const active = !!user.isActive;

        return `
        <tr>
            <td class="px-6 py-4 font-medium">${escapeHtml(user.username)}</td>
            <td class="px-6 py-4" style="color: var(--text-muted);">${escapeHtml(user.email)}</td>
            <td class="px-6 py-4">
                <span class="chip ${role.cls}">${role.label}</span>
            </td>
            <td class="px-6 py-4">
                <span class="chip ${active ? 'chip--clear' : 'chip--critical'}">${active ? 'Active' : 'Inactive'}</span>
            </td>
            <td class="px-6 py-4 timestamp-cell">${user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}</td>
            <td class="px-6 py-4 text-right">
                <div class="flex justify-end gap-2">
                    <button class="edit-user-btn icon-btn icon-btn--info"
                        data-id="${user._id}" data-role="${user.role}" data-active="${user.isActive}" title="Edit role/status">
                        <i data-lucide="edit" class="w-4 h-4"></i>
                    </button>
                    <button class="delete-user-btn icon-btn icon-btn--danger"
                        data-id="${user._id}" title="Delete user">
                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                    </button>
                </div>
            </td>
        </tr>
    `}).join('');
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function updatePagination(pagination) {
    const { total, page, pages } = pagination;
    currentPage = page;

    document.getElementById('pageInfo').textContent = `Showing page ${page} of ${pages} (${total} total)`;

    document.getElementById('prevBtn').disabled = page <= 1;
    document.getElementById('nextBtn').disabled = page >= pages;
}

async function showAddUserModal() {
    const t = swalTheme();
    const { value: formValues } = await Swal.fire({
        title: 'Add new user',
        html: `
            <div class="flex flex-col gap-4 text-left">
                <div>
                    <label class="swal-field-label">Username</label>
                    <input id="swal-input-username" class="swal-field-input swal2-input" placeholder="Username">
                </div>
                <div>
                    <label class="swal-field-label">Email</label>
                    <input id="swal-input-email" type="email" class="swal-field-input swal2-input" placeholder="Email">
                </div>
                <div>
                    <label class="swal-field-label">Password</label>
                    <input id="swal-input-password" type="password" class="swal-field-input swal2-input" placeholder="Password">
                </div>
                <div>
                    <label class="swal-field-label">Role</label>
                    <select id="swal-input-role" class="swal-field-select swal2-select !flex">
                        <option value="viewer">Viewer</option>
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
            </div>
        `,
        focusConfirm: false,
        showCancelButton: true,
        confirmButtonText: 'Create user',
        confirmButtonColor: t.confirmColor,
        cancelButtonColor: t.cancelColor,
        background: t.background,
        color: t.color,
        preConfirm: () => {
            const username = document.getElementById('swal-input-username').value;
            const email = document.getElementById('swal-input-email').value;
            const password = document.getElementById('swal-input-password').value;
            const role = document.getElementById('swal-input-role').value;

            if (!username || !email || !password || !role) {
                Swal.showValidationMessage('Please fill out all fields');
                return false;
            }

            return { username, email, password, role };
        }
    });

    if (formValues) {
        try {
            await API.users.create(formValues);
            showToast('User created successfully', 'success');
            loadUsers();
        } catch (error) {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: error.message || 'Failed to create user',
                background: t.background,
                color: t.color,
                confirmButtonColor: t.confirmColor
            });
        }
    }
}

async function showEditUserModal(id, currentRole, currentActive) {
    const t = swalTheme();
    const isActive = currentActive === 'true' || currentActive === true;

    const { value: formValues } = await Swal.fire({
        title: 'Edit user',
        html: `
            <div class="flex flex-col gap-4 text-left">
                <div>
                    <label class="swal-field-label">Role</label>
                    <select id="swal-edit-role" class="swal-field-select swal2-select !flex">
                        <option value="viewer" ${currentRole === 'viewer' ? 'selected' : ''}>Viewer</option>
                        <option value="analyst" ${currentRole === 'analyst' ? 'selected' : ''}>Analyst</option>
                        <option value="admin" ${currentRole === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                </div>
                <div class="swal-field-checkbox-row">
                    <input type="checkbox" id="swal-edit-active" class="w-4 h-4" ${isActive ? 'checked' : ''}>
                    <label for="swal-edit-active">Account active</label>
                </div>
            </div>
        `,
        focusConfirm: false,
        showCancelButton: true,
        confirmButtonText: 'Save changes',
        confirmButtonColor: t.confirmColor,
        cancelButtonColor: t.cancelColor,
        background: t.background,
        color: t.color,
        preConfirm: () => {
            return {
                role: document.getElementById('swal-edit-role').value,
                isActive: document.getElementById('swal-edit-active').checked
            };
        }
    });

    if (formValues) {
        try {
            await API.users.update(id, formValues);
            showToast('User updated successfully', 'success');
            loadUsers();
        } catch (error) {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: error.message || 'Failed to update user',
                background: t.background,
                color: t.color,
                confirmButtonColor: t.confirmColor
            });
        }
    }
}

async function deleteUser(id) {
    const t = swalTheme();
    const result = await Swal.fire({
        title: 'Are you sure?',
        text: "You won't be able to revert this!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: t.dangerColor,
        cancelButtonColor: t.cancelColor,
        confirmButtonText: 'Yes, delete it!',
        background: t.background,
        color: t.color
    });

    if (result.isConfirmed) {
        try {
            await API.users.delete(id);
            showToast('User deleted successfully', 'success');
            loadUsers();
        } catch (error) {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: error.message || 'Failed to delete user',
                background: t.background,
                color: t.color,
                confirmButtonColor: t.dangerColor
            });
        }
    }
}