// app.js - Client-side JavaScript for Elvik

function togglePasswordInput(inputEl, buttonEl) {
    if (!inputEl) return;
    if (inputEl.type === 'password') {
        inputEl.type = 'text';
        if (buttonEl) buttonEl.textContent = 'Hide';
    } else {
        inputEl.type = 'password';
        if (buttonEl) buttonEl.textContent = 'Show';
    }
}

/**
 * Simple grid search function (no filters, just search)
 * @param {string} gridId - ID of the grid container
 * @param {string} searchInputId - ID of the search input
 * @param {string} noResultsId - ID of the no results message element
 */
function initGridSearch(gridId, searchInputId, noResultsId) {
    const searchInput = document.getElementById(searchInputId);
    const grid = document.getElementById(gridId);

    if (!searchInput || !grid) return;

    const cards = grid.children;

    // Add search input listener
    searchInput.addEventListener('input', searchGrid);

    // Search grid function
    function searchGrid() {
        const searchValue = searchInput.value.toLowerCase();
        let visibleCount = 0;

        for (let i = 0; i < cards.length; i++) {
            const card = cards[i];

            // Get text content from the card
            const cardText = card.textContent.toLowerCase();

            // Check search match
            const matchesSearch = searchValue === '' || cardText.includes(searchValue);

            // Show/hide card
            if (matchesSearch) {
                card.style.display = '';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        }

        // Show/hide no results message
        const noResults = document.getElementById(noResultsId);
        if (noResults) {
            if (visibleCount === 0) {
                noResults.style.display = 'block';
                grid.style.display = 'none';
            } else {
                noResults.style.display = 'none';
                grid.style.display = 'grid';
            }
        }
    }
}

/**
 * Simple table search function (no filters, just search)
 * @param {string} tableId - ID of the table to search
 * @param {string} searchInputId - ID of the search input
 * @param {string} noResultsId - ID of the no results message element
 * @param {Array} searchColumns - Array of column indices to search
 */
function initTableSearch(tableId, searchInputId, noResultsId, searchColumns) {
    const searchInput = document.getElementById(searchInputId);
    const table = document.getElementById(tableId);

    if (!searchInput || !table) return;

    const tbody = table.getElementsByTagName('tbody')[0];
    if (!tbody) return;

    // Add search input listener
    searchInput.addEventListener('input', searchTable);

    // Search table function
    function searchTable() {
        const searchValue = searchInput.value.toLowerCase();
        const rows = tbody.getElementsByTagName('tr');
        let visibleCount = 0;

        for (let i = 0; i < rows.length; i++) {
            const row = rows[i];

            // Check search match across specified columns
            let matchesSearch = searchValue === '';
            if (!matchesSearch) {
                const columnsToSearch = searchColumns || Array.from({ length: row.cells.length }, (_, i) => i);
                matchesSearch = columnsToSearch.some(colIndex => {
                    if (row.cells[colIndex]) {
                        return row.cells[colIndex].textContent.toLowerCase().includes(searchValue);
                    }
                    return false;
                });
            }

            // Show/hide row
            if (matchesSearch) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        }

        // Show/hide no results message
        if (noResultsId) {
            const noResults = document.getElementById(noResultsId);
            if (noResults) {
                if (visibleCount === 0) {
                    noResults.style.display = 'block';
                    table.style.display = 'none';
                } else {
                    noResults.style.display = 'none';
                    table.style.display = 'table';
                }
            }
        }
    }
}

/**
 * Reusable table search and filter function
 * @param {string} tableId - ID of the table to filter
 * @param {string} searchInputId - ID of the search input
 * @param {string} filterButtonClass - Class name for filter buttons (optional)
 * @param {string} noResultsId - ID of the no results message element (optional)
 * @param {Array} searchColumns - Array of column indices to search (default: all columns)
 */
function initTableFilter(tableId, searchInputId, filterButtonClass = null, noResultsId = null, searchColumns = null) {
    const searchInput = document.getElementById(searchInputId);
    const table = document.getElementById(tableId);

    if (!searchInput || !table) return;

    const tbody = table.getElementsByTagName('tbody')[0];
    if (!tbody) return;

    let currentFilter = 'all';
    const filterButtons = filterButtonClass ? document.querySelectorAll(`.${filterButtonClass}`) : [];

    // Add search input listener
    searchInput.addEventListener('input', filterTable);

    // Add filter button listeners if provided
    if (filterButtons.length > 0) {
        filterButtons.forEach(button => {
            button.addEventListener('click', function () {
                currentFilter = this.getAttribute('data-filter') || this.getAttribute('data-role') || 'all';

                // Update active button
                filterButtons.forEach(btn => btn.classList.remove('active'));
                this.classList.add('active');

                // Apply filter
                filterTable();
            });
        });
    }

    // Search and filter table function
    function filterTable() {
        const searchValue = searchInput.value.toLowerCase();
        const rows = tbody.getElementsByTagName('tr');
        let visibleCount = 0;

        for (let i = 0; i < rows.length; i++) {
            const row = rows[i];
            const rowFilterAttr = row.getAttribute('data-filter') || row.getAttribute('data-role') || 'all';

            // Check search match across specified columns (or all if not specified)
            let matchesSearch = searchValue === '';
            if (!matchesSearch) {
                const columnsToSearch = searchColumns || Array.from({ length: row.cells.length }, (_, i) => i);
                matchesSearch = columnsToSearch.some(colIndex => {
                    if (row.cells[colIndex]) {
                        return row.cells[colIndex].textContent.toLowerCase().includes(searchValue);
                    }
                    return false;
                });
            }

            // Check filter match
            const matchesFilter = currentFilter === 'all' || rowFilterAttr === currentFilter;

            // Show/hide row
            if (matchesSearch && matchesFilter) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        }

        // Show/hide no results message if provided
        if (noResultsId) {
            const noResults = document.getElementById(noResultsId);
            if (noResults) {
                if (visibleCount === 0) {
                    noResults.style.display = 'block';
                    table.style.display = 'none';
                } else {
                    noResults.style.display = 'none';
                    table.style.display = 'table';
                }
            }
        }
    }
}

// attach once DOM is ready (no inline script)
document.addEventListener('DOMContentLoaded', () => {
    // Password toggle functionality
    document.querySelectorAll('.password-toggle').forEach((btn) => {
        const selector = btn.getAttribute('data-target');
        const input = selector ? document.querySelector(selector) : null;
        btn.addEventListener('click', () => togglePasswordInput(input, btn));
    });

    // User management filtering - using reusable function
    if (document.getElementById('usersTable')) {
        initTableFilter('usersTable', 'searchInput', 'filter-btn', 'noResults', [0, 1, 2]); // Search ID, Name, Email columns
    }

    // Products management search - using simple search (no filters)
    if (document.getElementById('productsTable')) {
        initTableSearch('productsTable', 'searchInput', 'noResults', [0, 1, 2, 4]); // Search Product, Category, Price, Seller columns
    }

    // Customer product browsing - using simple search (no filters)
    if (document.getElementById('productsGrid')) {
        initGridSearch('productsGrid', 'searchInput', 'noResults');
    }

    // Delete confirmation for forms
    const deleteForms = document.querySelectorAll('.delete-form');
    deleteForms.forEach(form => {
        form.addEventListener('submit', function (e) {
            if (!confirm('Are you sure you want to delete this user?')) {
                e.preventDefault();
            }
        });
    });

    // Password reset verification code input handler
    const codeInput = document.querySelector('.popup-input');
    if (codeInput) {
        codeInput.focus();
        codeInput.addEventListener('input', function () {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
    }
});