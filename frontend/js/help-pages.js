// NOTE: Shared interactivity for FAQ and User Guide pages.

const HELP_CHECKLIST_STORAGE_KEY = 'helpGuide:checklist';
const HELP_AUTODETECT_STORAGE_KEY = 'helpGuide:autoDetected';
const GUIDE_TASK_ROUTES = {
    'dashboard-review': 'dashboard.html',
    'incident-report': 'report-incident.html',
    'incident-tracking': 'incident-logs.html',
    'risk-review': 'risk-analysis.html',
    'report-export': 'incident-logs.html',
};

function getHelpPageElements() {
    return {
        pageType: document.body.dataset.helpPage || '',
        searchInput: document.getElementById('help-search-input'),
        filterButtons: Array.from(document.querySelectorAll('[data-help-filter]')),
        items: Array.from(document.querySelectorAll('[data-help-item]')),
        emptyState: document.getElementById('help-empty'),
        resultsCount: document.getElementById('help-results-count'),
        tabButtons: Array.from(document.querySelectorAll('[data-guide-tab-target]')),
        tabPanels: Array.from(document.querySelectorAll('[data-guide-tab-panel]')),
    };
}

function matchesSearch(item, searchTerm) {
    if (!searchTerm) {
        return true;
    }

    return item.textContent.toLowerCase().includes(searchTerm);
}

function matchesFilter(item, activeFilter) {
    if (activeFilter === 'all') {
        return true;
    }

    const tags = String(item.dataset.helpTags || '').toLowerCase().split(/\s+/).filter(Boolean);
    return tags.includes(activeFilter);
}

function updateHelpResults(elements, visibleCount) {
    const { emptyState, resultsCount } = elements;

    if (resultsCount) {
        resultsCount.textContent = `Showing ${visibleCount} item${visibleCount === 1 ? '' : 's'}`;
    }

    if (emptyState) {
        emptyState.hidden = visibleCount > 0;
    }
}

function applyHelpFilters(elements) {
    const searchTerm = String(elements.searchInput?.value || '').trim().toLowerCase();
    const activeButton = elements.filterButtons.find((button) => button.classList.contains('is-active'));
    const activeFilter = String(activeButton?.dataset.helpFilter || 'all').toLowerCase();

    let visibleCount = 0;

    elements.items.forEach((item) => {
        const isVisible = matchesSearch(item, searchTerm) && matchesFilter(item, activeFilter);
        item.hidden = !isVisible;

        if (isVisible) {
            visibleCount += 1;
        }
    });

    updateHelpResults(elements, visibleCount);
}

function setupHelpFilters(elements) {
    elements.filterButtons.forEach((button) => {
        button.addEventListener('click', () => {
            elements.filterButtons.forEach((entry) => entry.classList.remove('is-active'));
            button.classList.add('is-active');
            applyHelpFilters(elements);
        });
    });

    if (elements.searchInput) {
        elements.searchInput.addEventListener('input', () => applyHelpFilters(elements));
    }

    document.addEventListener('keydown', (event) => {
        if (event.key !== '/' || !elements.searchInput) {
            return;
        }

        const activeTag = document.activeElement?.tagName?.toLowerCase();
        if (activeTag === 'input' || activeTag === 'textarea') {
            return;
        }

        event.preventDefault();
        elements.searchInput.focus();
    });
}

function setupFaqAccordion(elements) {
    const detailItems = elements.items.filter((item) => item.tagName.toLowerCase() === 'details');

    detailItems.forEach((item) => {
        item.addEventListener('toggle', () => {
            if (!item.open) {
                return;
            }

            detailItems.forEach((entry) => {
                if (entry !== item) {
                    entry.open = false;
                }
            });
        });
    });
}

function setupGuideTabs(elements) {
    if (elements.tabButtons.length === 0 || elements.tabPanels.length === 0) {
        return;
    }

    const activateTab = (targetId) => {
        elements.tabButtons.forEach((button) => {
            const isActive = button.dataset.guideTabTarget === targetId;
            button.classList.toggle('is-active', isActive);
            button.setAttribute('aria-selected', isActive ? 'true' : 'false');
        });

        elements.tabPanels.forEach((panel) => {
            const isActive = panel.id === targetId;
            panel.classList.toggle('is-active', isActive);
            panel.hidden = !isActive;
        });
    };

    elements.tabButtons.forEach((button) => {
        button.addEventListener('click', () => {
            activateTab(String(button.dataset.guideTabTarget || ''));
            applyHelpFilters(elements);
        });
    });

    const initialTarget = String(elements.tabButtons.find((button) => button.classList.contains('is-active'))?.dataset.guideTabTarget || '').trim();
    if (initialTarget) {
        activateTab(initialTarget);
    }
}

function readChecklistState() {
    try {
        const rawValue = localStorage.getItem(HELP_CHECKLIST_STORAGE_KEY);
        return rawValue ? (JSON.parse(rawValue) || {}) : {};
    } catch (error) {
        console.warn('Unable to read help checklist state:', error);
        return {};
    }
}

function readAutoDetectedState() {
    try {
        const rawValue = localStorage.getItem(HELP_AUTODETECT_STORAGE_KEY);
        return rawValue ? (JSON.parse(rawValue) || {}) : {};
    } catch (error) {
        console.warn('Unable to read auto-detected checklist state:', error);
        return {};
    }
}

function writeAutoDetectedState(state) {
    try {
        localStorage.setItem(HELP_AUTODETECT_STORAGE_KEY, JSON.stringify(state));
    } catch (error) {
        console.warn('Unable to store auto-detected checklist state:', error);
    }
}

function writeChecklistState(checklistState) {
    try {
        localStorage.setItem(HELP_CHECKLIST_STORAGE_KEY, JSON.stringify(checklistState));
    } catch (error) {
        console.warn('Unable to store help checklist state:', error);
    }
}

function syncGuideItemStates() {
    const guideList = document.getElementById('help-list');
    if (!guideList) {
        return;
    }

    const guideItems = Array.from(guideList.querySelectorAll('.help-guide-item'));
    if (guideItems.length === 0) {
        return;
    }

    guideItems.forEach((item, index) => {
        if (!item.dataset.guideOrder) {
            item.dataset.guideOrder = String(index);
        }

        const checkbox = item.querySelector('[data-guide-check]');
        const isCompleted = Boolean(checkbox?.checked);
        item.classList.toggle('is-completed', isCompleted);
    });

    const sortedItems = [...guideItems].sort((leftItem, rightItem) => {
        const leftCompleted = leftItem.classList.contains('is-completed');
        const rightCompleted = rightItem.classList.contains('is-completed');

        if (leftCompleted !== rightCompleted) {
            return leftCompleted ? 1 : -1;
        }

        return Number(leftItem.dataset.guideOrder || 0) - Number(rightItem.dataset.guideOrder || 0);
    });

    sortedItems.forEach((item) => guideList.appendChild(item));
}

function updateChecklistProgress() {
    const checkboxes = Array.from(document.querySelectorAll('[data-guide-check]'));
    const completedCount = checkboxes.filter((checkbox) => checkbox.checked).length;
    const totalCount = checkboxes.length;
    const percentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

    const statusEl = document.getElementById('help-checklist-status');
    if (statusEl) {
        statusEl.textContent = `${completedCount}/${totalCount} completed`;
    }

    const progressFill = document.getElementById('help-progress-fill');
    if (progressFill) {
        progressFill.style.width = `${percentage}%`;
    }

    const progressBar = document.querySelector('.help-progress-bar[role="progressbar"]');
    if (progressBar) {
        progressBar.setAttribute('aria-valuenow', String(percentage));
    }

    syncGuideItemStates();
}

async function detectGuideTaskCompletion() {
    const detectedState = readAutoDetectedState();
    const currentPath = String(window.location.pathname.split('/').pop() || '').toLowerCase();

    // Visiting dashboard page is treated as first completion for dashboard review.
    if (currentPath === 'dashboard.html') {
        detectedState['dashboard-review'] = true;
    }

    try {
        const [assets, incidents, riskByAsset] = await Promise.all([
            apiClient.getAssets(),
            apiClient.getIncidents(),
            apiClient.getRiskByAsset(),
        ]);

        if (Array.isArray(incidents) && incidents.length > 0) {
            detectedState['incident-report'] = true;
            detectedState['incident-tracking'] = true;
        }

        const hasRiskData = Array.isArray(riskByAsset)
            ? riskByAsset.length > 0
            : Array.isArray(riskByAsset?.riskByAsset) && riskByAsset.riskByAsset.length > 0;
        if (hasRiskData) {
            detectedState['risk-review'] = true;
        }

        if (Array.isArray(assets) && assets.length > 0 && Array.isArray(incidents) && incidents.length > 0) {
            detectedState['report-export'] = true;
        }
    } catch (error) {
        console.warn('Guide auto-detection skipped due to data fetch error:', error);
    }

    writeAutoDetectedState(detectedState);
    return detectedState;
}

function setupGuideActions() {
    const actionButtons = Array.from(document.querySelectorAll('.help-guide-action[data-guide-action]'));

    actionButtons.forEach((button) => {
        button.addEventListener('click', () => {
            const actionKey = String(button.dataset.guideAction || '').trim();
            const route = GUIDE_TASK_ROUTES[actionKey];
            if (!route) {
                return;
            }

            const checklistState = readChecklistState();
            checklistState[actionKey] = true;
            writeChecklistState(checklistState);
            window.location.href = route;
        });
    });
}

async function setupGuideChecklist() {
    const checkboxes = Array.from(document.querySelectorAll('[data-guide-check]'));
    if (checkboxes.length === 0) {
        return;
    }

    const checklistState = readChecklistState();
    const detectedState = await detectGuideTaskCompletion();

    checkboxes.forEach((checkbox) => {
        const key = checkbox.dataset.guideCheck || '';
        if (key && detectedState[key] === true) {
            checklistState[key] = true;
        }

        if (key && checklistState[key] === true) {
            checkbox.checked = true;
        }

        checkbox.addEventListener('change', () => {
            if (!key) {
                updateChecklistProgress();
                return;
            }

            checklistState[key] = checkbox.checked;
            writeChecklistState(checklistState);
            updateChecklistProgress();
        });
    });

    writeChecklistState(checklistState);

    setupGuideActions();

    updateChecklistProgress();
}

async function initializeHelpPage() {
    const elements = getHelpPageElements();
    if (elements.items.length === 0) {
        return;
    }

    setupHelpFilters(elements);
    setupGuideTabs(elements);

    if (elements.pageType === 'faq') {
        setupFaqAccordion(elements);
    }

    if (elements.pageType === 'guide') {
        await setupGuideChecklist();
    }

    applyHelpFilters(elements);
}

document.addEventListener('DOMContentLoaded', initializeHelpPage);
