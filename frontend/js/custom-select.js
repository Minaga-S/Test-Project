// NOTE: Custom select dropdown handler with theme styling and smooth animations.

function setupCustomSelects() {
    const selectElements = Array.from(document.querySelectorAll('select:not([data-custom-select="true"])'));
    
    selectElements.forEach((nativeSelect) => {
        // Skip if already converted
        if (nativeSelect.closest('.custom-select-container')) {
            return;
        }

        // Create container
        const container = document.createElement('div');
        container.className = 'custom-select-container';

        // Create trigger button
        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = `custom-select-trigger ${nativeSelect.className}`;
        trigger.setAttribute('aria-haspopup', 'listbox');
        trigger.setAttribute('aria-expanded', 'false');
        
        const initialValue = nativeSelect.options[nativeSelect.selectedIndex]?.text || 'Select...';
        trigger.textContent = initialValue;

        // Create dropdown
        const dropdown = document.createElement('ul');
        dropdown.className = 'custom-select-dropdown';
        dropdown.setAttribute('role', 'listbox');

        // Populate options
        Array.from(nativeSelect.options).forEach((option, index) => {
            const optionElement = document.createElement('li');
            optionElement.className = 'custom-select-option';
            optionElement.textContent = option.text;
            optionElement.setAttribute('data-value', option.value);
            optionElement.setAttribute('role', 'option');
            optionElement.setAttribute('aria-selected', index === nativeSelect.selectedIndex ? 'true' : 'false');

            if (index === nativeSelect.selectedIndex) {
                optionElement.classList.add('is-selected');
            }

            optionElement.addEventListener('click', (event) => {
                event.preventDefault();
                selectOption(nativeSelect, trigger, dropdown, option.value, optionElement);
            });

            optionElement.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    selectOption(nativeSelect, trigger, dropdown, option.value, optionElement);
                }
            });

            dropdown.appendChild(optionElement);
        });

        // Trigger click handler
        trigger.addEventListener('click', (event) => {
            event.preventDefault();
            toggleDropdown(trigger, dropdown);
        });

        // Keyboard navigation
        trigger.addEventListener('keydown', (event) => {
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                
                if (!dropdown.classList.contains('is-open')) {
                    openDropdown(trigger, dropdown);
                } else {
                    const options = Array.from(dropdown.querySelectorAll('.custom-select-option'));
                    const currentIndex = options.findIndex((opt) => opt.classList.contains('is-selected'));
                    const nextIndex = event.key === 'ArrowDown'
                        ? Math.min(currentIndex + 1, options.length - 1)
                        : Math.max(currentIndex - 1, 0);

                    if (options[nextIndex]) {
                        options[nextIndex].focus();
                    }
                }
            } else if (event.key === 'Escape') {
                closeDropdown(trigger, dropdown);
            }
        });

        // Close on blur
        container.addEventListener('blur', () => {
            setTimeout(() => {
                if (!container.contains(document.activeElement)) {
                    closeDropdown(trigger, dropdown);
                }
            }, 50);
        });

        // Build structure
        container.appendChild(trigger);
        container.appendChild(dropdown);

        // Hide native select
        nativeSelect.style.display = 'none';
        nativeSelect.setAttribute('data-custom-select', 'true');

        // Replace native select with custom
        nativeSelect.parentNode.insertBefore(container, nativeSelect);
    });

    // Global close on outside click
    document.addEventListener('click', (event) => {
        const containers = document.querySelectorAll('.custom-select-container');
        containers.forEach((container) => {
            if (!container.contains(event.target)) {
                const trigger = container.querySelector('.custom-select-trigger');
                const dropdown = container.querySelector('.custom-select-dropdown');
                closeDropdown(trigger, dropdown);
            }
        });
    }, true);
}

function toggleDropdown(trigger, dropdown) {
    if (dropdown.classList.contains('is-open')) {
        closeDropdown(trigger, dropdown);
    } else {
        openDropdown(trigger, dropdown);
    }
}

function openDropdown(trigger, dropdown) {
    trigger.classList.add('is-open');
    dropdown.classList.add('is-open');
    trigger.setAttribute('aria-expanded', 'true');
    
    const selectedOption = dropdown.querySelector('.is-selected');
    if (selectedOption) {
        selectedOption.focus();
        selectedOption.scrollIntoView({ block: 'nearest' });
    }
}

function closeDropdown(trigger, dropdown) {
    trigger.classList.remove('is-open');
    dropdown.classList.remove('is-open');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.focus();
}

function selectOption(nativeSelect, trigger, dropdown, value, optionElement) {
    // Update native select
    nativeSelect.value = value;

    // Update trigger text
    trigger.textContent = optionElement.textContent;

    // Update selected state
    const allOptions = dropdown.querySelectorAll('.custom-select-option');
    allOptions.forEach((opt) => {
        opt.classList.remove('is-selected');
        opt.setAttribute('aria-selected', 'false');
    });

    optionElement.classList.add('is-selected');
    optionElement.setAttribute('aria-selected', 'true');

    // Trigger change event on native select
    const changeEvent = new Event('change', { bubbles: true });
    nativeSelect.dispatchEvent(changeEvent);

    // Close dropdown
    closeDropdown(trigger, dropdown);
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setupCustomSelects();
    });
} else {
    // DOM already loaded
    setupCustomSelects();
}

// Also watch for dynamically added selects
const observer = new MutationObserver(() => {
    setupCustomSelects();
});

observer.observe(document.body, {
    childList: true,
    subtree: true,
});
