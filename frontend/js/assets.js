/**
 * Asset Management Handler
 */
// NOTE: Page script: handles UI behavior, user actions, and API calls for this screen.
/**
 * SECTION GUIDE:
 * 1) Page Initialization: checks auth and loads initial assets.
 * 2) Event Wiring: hooks buttons/forms to handlers.
 * 3) Data Loading: fetches assets from API and renders table/cards.
 * 4) CRUD Actions: create, edit, and delete asset workflows.
 */



let assets = [];
let currentEditingAssetId = null;

document.addEventListener('DOMContentLoaded', () => {
    initializeAssets();
});

async function initializeAssets() {
    if (!apiClient.isAuthenticated()) {
        window.location.href = 'index.html';
        return;
    }

    setupUserInfo();
    setupLogoutButton();
    setupEventListeners();
    await loadAssets();
}

function setupEventListeners() {
    // Add asset button
    const addBtn = document.getElementById('add-asset-btn');
    if (addBtn) {
        addBtn.addEventListener('click', openAssetModal);
    }

    // Modal controls
    const modalClose = document.getElementById('modal-close');
    if (modalClose) {
        modalClose.addEventListener('click', closeAssetModal);
    }

    const cancelBtn = document.getElementById('cancel-btn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeAssetModal);
    }

    const modalOverlay = document.getElementById('modal-overlay');
    if (modalOverlay) {
        modalOverlay.addEventListener('click', closeAssetModal);
    }

    // Form submission
    const assetForm = document.getElementById('asset-form');
    if (assetForm) {
        assetForm.addEventListener('submit', handleAssetFormSubmit);
    }

    // Filters
    const searchInput = document.getElementById('search-assets');
    if (searchInput) {
        searchInput.addEventListener('input', filterAssets);
    }

    const filterType = document.getElementById('filter-type');
    if (filterType) {
        filterType.addEventListener('change', filterAssets);
    }

    const filterStatus = document.getElementById('filter-status');
    if (filterStatus) {
        filterStatus.addEventListener('change', filterAssets);
    }

    // Delete modal
    const deleteConfirm = document.getElementById('delete-confirm');
    if (deleteConfirm) {
        deleteConfirm.addEventListener('click', confirmDelete);
    }

    const deleteCancel = document.getElementById('delete-cancel');
    if (deleteCancel) {
        deleteCancel.addEventListener('click', closeDeleteModal);
    }
}

async function loadAssets() {
    showLoading(true);
    renderTableSkeleton('assets-tbody', 7, 4);

    try {
        assets = await apiClient.getAssets();
        displayAssets(assets);
    } catch (error) {
        console.error('Error loading assets:', error);
        showNotification('Error loading assets', 'error');
    } finally {
        showLoading(false);
    }
}

function displayAssets(assetsToDisplay) {
    const tbody = document.getElementById('assets-tbody');
    tbody.innerHTML = '';

    if (!assetsToDisplay || assetsToDisplay.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No assets registered</td></tr>';
        return;
    }

    assetsToDisplay.forEach(asset => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${asset.assetName}</td>
            <td>${asset.assetType}</td>
            <td>${asset.location || '-'}</td>
            <td><span class="status-badge status-${asset.status.toLowerCase()}">${asset.status}</span></td>
            <td>${asset.criticality}</td>
            <td>${asset.owner || '-'}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="editAsset('${asset._id}')">Edit</button>
                <button class="btn btn-sm btn-danger" onclick="openDeleteModal('${asset._id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function filterAssets() {
    const searchQuery = document.getElementById('search-assets').value.toLowerCase();
    const typeFilter = document.getElementById('filter-type').value;
    const statusFilter = document.getElementById('filter-status').value;

    const filtered = assets.filter(asset => {
        const matchesSearch = asset.assetName.toLowerCase().includes(searchQuery) ||
                             asset.description?.toLowerCase().includes(searchQuery);
        const matchesType = !typeFilter || asset.assetType === typeFilter;
        const matchesStatus = !statusFilter || asset.status === statusFilter;

        return matchesSearch && matchesType && matchesStatus;
    });

    displayAssets(filtered);
}

function openAssetModal() {
    currentEditingAssetId = null;
    document.getElementById('modal-title').textContent = 'Add New Asset';
    document.getElementById('asset-form').reset();
    showModal('asset-modal');
}

function closeAssetModal() {
    hideModal('asset-modal');
    document.getElementById('asset-form').reset();
    currentEditingAssetId = null;
}

async function editAsset(assetId) {
    try {
        const asset = await apiClient.getAsset(assetId);
        
        currentEditingAssetId = assetId;
        document.getElementById('modal-title').textContent = 'Edit Asset';
        
        // Populate form
        document.getElementById('asset-name').value = asset.assetName;
        document.getElementById('asset-type').value = asset.assetType;
        document.getElementById('asset-location').value = asset.location || '';
        document.getElementById('asset-description').value = asset.description || '';
        document.getElementById('asset-criticality').value = asset.criticality;
        document.getElementById('asset-owner').value = asset.owner || '';
        document.getElementById('asset-status').value = asset.status;
        
        showModal('asset-modal');
    } catch (error) {
        console.error('Error loading asset:', error);
        showNotification('Error loading asset', 'error');
    }
}

async function handleAssetFormSubmit(e) {
    e.preventDefault();

    const formData = getFormData(e.target);

    showLoading(true);

    try {
        if (currentEditingAssetId) {
            await apiClient.updateAsset(currentEditingAssetId, formData);
            showNotification('Asset updated successfully', 'success');
        } else {
            await apiClient.createAsset(formData);
            showNotification('Asset created successfully', 'success');
        }

        closeAssetModal();
        await loadAssets();
    } catch (error) {
        console.error('Error saving asset:', error);
        showNotification('Error saving asset', 'error');
    } finally {
        showLoading(false);
    }
}

function openDeleteModal(assetId) {
    currentEditingAssetId = assetId;
    showModal('delete-modal');
}

function closeDeleteModal() {
    hideModal('delete-modal');
    currentEditingAssetId = null;
}

async function confirmDelete() {
    showLoading(true);

    try {
        await apiClient.deleteAsset(currentEditingAssetId);
        showNotification('Asset deleted successfully', 'success');
        closeDeleteModal();
        await loadAssets();
    } catch (error) {
        console.error('Error deleting asset:', error);
        showNotification('Error deleting asset', 'error');
    } finally {
        showLoading(false);
    }
}

function setupUserInfo() {
    const user = getLocalStorage('user');
    const userNameEl = document.getElementById('user-name');
    if (user && userNameEl) {
        userNameEl.textContent = user.fullName || user.email;
    }
}

function setupLogoutButton() {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.type = 'button';
    }
}

