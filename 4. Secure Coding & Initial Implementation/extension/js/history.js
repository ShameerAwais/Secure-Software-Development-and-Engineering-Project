// DOM elements
const notAuthenticated = document.getElementById('not-authenticated');
const historyContent = document.getElementById('history-content');
const errorMessage = document.getElementById('error-message');
const loading = document.getElementById('loading');
const emptyState = document.getElementById('empty-state');
const historyTableContainer = document.getElementById('history-table-container');
const historyBody = document.getElementById('history-body');
const pagination = document.getElementById('pagination');
const totalChecks = document.getElementById('total-checks');
const safeUrls = document.getElementById('safe-urls');
const unsafeUrls = document.getElementById('unsafe-urls');
const safePercentage = document.getElementById('safe-percentage');
const timeFilterButtons = document.querySelectorAll('.time-button');

// State
let authState = {
  isAuthenticated: false,
  user: null
};

let currentPage = 1;
let itemsPerPage = 10;
let totalPages = 1;
let timeRange = 'month';

// Check authentication status
async function checkAuthStatus() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getAuthStatus' });
    
    if (response && response.success) {
      authState.isAuthenticated = response.isAuthenticated;
      authState.user = response.user;
      
      // Update UI based on auth state
      updateUI();
      
      if (authState.isAuthenticated) {
        // Load stats and history if authenticated
        loadStats();
        loadHistory();
      }
    } else {
      console.error('Error getting auth status:', response?.error || 'Unknown error');
      showError(response?.error || 'Failed to get authentication status');
      authState.isAuthenticated = false;
      updateUI();
    }
  } catch (error) {
    console.error('Error checking auth status:', error);
    showError('Error connecting to authentication service');
    authState.isAuthenticated = false;
    updateUI();
  }
}

// Update UI based on authentication status
function updateUI() {
  if (authState.isAuthenticated && authState.user) {
    notAuthenticated.classList.add('hidden');
    historyContent.classList.remove('hidden');
  } else {
    notAuthenticated.classList.remove('hidden');
    historyContent.classList.add('hidden');
  }
}

// Load URL history statistics
async function loadStats() {
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'getUserStats',
      timeRange
    });
    
    if (response && response.success && response.stats) {
      const stats = response.stats;
      
      // Update stats display with null checks for each value
      totalChecks.textContent = stats.totalChecks || 0;
      safeUrls.textContent = stats.safeUrls || 0;
      unsafeUrls.textContent = stats.unsafeUrls || 0;
      
      // Calculate and format safe percentage
      const percentage = stats.safePercentage || 0;
      safePercentage.textContent = `${Math.round(percentage)}%`;
      
    } else {
      console.error('Error loading stats:', response?.message || 'Unknown error');
      showError(response?.message || 'Failed to load URL statistics');
      
      // Initialize to zero values as fallback
      totalChecks.textContent = '0';
      safeUrls.textContent = '0';
      unsafeUrls.textContent = '0';
      safePercentage.textContent = '0%';
    }
  } catch (error) {
    console.error('Error loading stats:', error);
    showError('Error connecting to authentication service');
    
    // Initialize to zero values as fallback
    totalChecks.textContent = '0';
    safeUrls.textContent = '0';
    unsafeUrls.textContent = '0';
    safePercentage.textContent = '0%';
  }
}

// Load URL check history
async function loadHistory() {
  try {
    // Show loading state
    loading.classList.remove('hidden');
    historyTableContainer.classList.add('hidden');
    emptyState.classList.add('hidden');
    
    const response = await chrome.runtime.sendMessage({
      action: 'getUserHistory',
      page: currentPage,
      limit: itemsPerPage,
      timeRange: timeRange
    });
    
    // Hide loading state
    loading.classList.add('hidden');
    
    if (response && response.success) {
      const { history, pagination: paginationData } = response;
      
      // Update pagination data
      totalPages = paginationData.pages || 1;
      
      // Check if we have history data
      if (history && history.length > 0) {
        // Show table and populate data
        historyTableContainer.classList.remove('hidden');
        populateHistoryTable(history);
        updatePagination();
      } else {
        // Show empty state
        emptyState.classList.remove('hidden');
      }
    } else {
      console.error('Error loading history:', response?.message || 'Unknown error');
      showError(response?.message || 'Failed to load URL history');
      
      // Show empty state as fallback
      emptyState.classList.remove('hidden');
    }
  } catch (error) {
    console.error('Error loading history:', error);
    showError('Error connecting to authentication service');
    loading.classList.add('hidden');
    emptyState.classList.remove('hidden');
  }
}

// Populate history table with data
function populateHistoryTable(historyData) {
  // Clear existing data
  historyBody.innerHTML = '';
  
  // Create table rows
  historyData.forEach(item => {
    const tr = document.createElement('tr');
    
    // URL cell (truncated if too long)
    const urlCell = document.createElement('td');
    const url = item.url;
    urlCell.textContent = truncateUrl(url);
    urlCell.title = url; // Full URL on hover
    
    // Date cell (formatted)
    const dateCell = document.createElement('td');
    dateCell.textContent = formatDate(item.timestamp);
    
    // Status cell with badge
    const statusCell = document.createElement('td');
    const statusBadge = document.createElement('span');
    
    // Check if result exists and has isSafe property, otherwise use a safe default
    const isSafe = item.result && typeof item.result.isSafe === 'boolean' ? item.result.isSafe : 
                  (item.isSafe !== undefined ? item.isSafe : null);
    
    // Handle case where safety status is unknown
    if (isSafe === null || isSafe === undefined) {
      statusBadge.className = 'status-badge status-unknown';
      statusBadge.textContent = 'Unknown';
    } else {
      statusBadge.className = `status-badge ${isSafe ? 'status-safe' : 'status-unsafe'}`;
      statusBadge.textContent = isSafe ? 'Safe' : 'Unsafe';
    }
    
    statusCell.appendChild(statusBadge);
    
    // Action cell with badge
    const actionCell = document.createElement('td');
    const actionBadge = document.createElement('span');
    actionBadge.className = 'action-badge';
    actionBadge.textContent = capitalizeFirstLetter(item.userAction || 'proceeded');
    actionCell.appendChild(actionBadge);
    
    // Add cells to row
    tr.appendChild(urlCell);
    tr.appendChild(dateCell);
    tr.appendChild(statusCell);
    tr.appendChild(actionCell);
    
    // Add row to table body
    historyBody.appendChild(tr);
  });
}

// Update pagination controls
function updatePagination() {
  // Clear existing pagination
  pagination.innerHTML = '';
  
  // Add previous button
  const prevButton = document.createElement('button');
  prevButton.className = 'pagination-button';
  prevButton.textContent = 'Previous';
  prevButton.disabled = currentPage === 1;
  prevButton.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      loadHistory();
    }
  });
  pagination.appendChild(prevButton);
  
  // Add page buttons (max 5)
  const startPage = Math.max(1, currentPage - 2);
  const endPage = Math.min(totalPages, startPage + 4);
  
  for (let i = startPage; i <= endPage; i++) {
    const pageButton = document.createElement('button');
    pageButton.className = `pagination-button ${i === currentPage ? 'pagination-current' : ''}`;
    pageButton.textContent = i;
    
    if (i !== currentPage) {
      pageButton.addEventListener('click', () => {
        currentPage = i;
        loadHistory();
      });
    }
    
    pagination.appendChild(pageButton);
  }
  
  // Add next button
  const nextButton = document.createElement('button');
  nextButton.className = 'pagination-button';
  nextButton.textContent = 'Next';
  nextButton.disabled = currentPage === totalPages;
  nextButton.addEventListener('click', () => {
    if (currentPage < totalPages) {
      currentPage++;
      loadHistory();
    }
  });
  pagination.appendChild(nextButton);
}

// Helper function to show error message
function showError(message) {
  errorMessage.textContent = message;
  errorMessage.style.display = 'block';
  
  // Hide after 5 seconds
  setTimeout(() => {
    errorMessage.style.display = 'none';
  }, 5000);
}

// Helper function to truncate URL
function truncateUrl(url) {
  try {
    const urlObj = new URL(url);
    const host = urlObj.hostname;
    const path = urlObj.pathname;
    
    if (path === '/' || !path) {
      return host;
    }
    
    const truncatedPath = path.length > 20 ? path.substring(0, 17) + '...' : path;
    return `${host}${truncatedPath}`;
  } catch (error) {
    return url.length > 30 ? url.substring(0, 27) + '...' : url;
  }
}

// Helper function to format date
function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Helper function to capitalize first letter
function capitalizeFirstLetter(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

// Handle time filter changes
function handleTimeFilterChange(e) {
  const newRange = e.target.dataset.range;
  if (newRange === timeRange) return;
  
  // Update active button
  timeFilterButtons.forEach(btn => {
    btn.classList.toggle('active', btn.dataset.range === newRange);
  });
  
  // Update time range and reload data
  timeRange = newRange;
  
  // Reset to first page when changing time filter
  currentPage = 1;
  
  // Reload both stats and history data with new time range
  loadStats();
  loadHistory();
}

// Set up time filter button event listeners
function setupEventListeners() {
  timeFilterButtons.forEach(button => {
    button.addEventListener('click', handleTimeFilterChange);
  });
}

// Initialize page
document.addEventListener('DOMContentLoaded', () => {
  checkAuthStatus();
  setupEventListeners();
});