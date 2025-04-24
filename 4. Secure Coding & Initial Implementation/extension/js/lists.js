/**
 * Allow/Block Lists Management
 * This module handles the user interface for managing trusted and blocked domains
 */

// DOM elements - Tabs
const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');

// DOM elements - Authentication
const notAuthenticated = document.getElementById('not-authenticated');
const listsContent = document.getElementById('lists-content');
const errorMessage = document.getElementById('error-message');
const successMessage = document.getElementById('success-message');

// DOM elements - Allow List
const allowListTable = document.getElementById('allow-list-table');
const allowListEmpty = document.getElementById('allow-list-empty');
const addAllowForm = document.getElementById('add-allow-form');
const allowUrlInput = document.getElementById('allow-url');

// DOM elements - Block List
const blockListTable = document.getElementById('block-list-table');
const blockListEmpty = document.getElementById('block-list-empty');
const addBlockForm = document.getElementById('add-block-form');
const blockUrlInput = document.getElementById('block-url');

// State
let authState = {
  isAuthenticated: false,
  user: null
};

let listsState = {
  allowList: [],
  blockList: []
};

/**
 * Initialize the lists page
 */
async function initLists() {
  // Set up tab switching
  setupTabs();
  
  // Set up form submission handlers
  setupFormHandlers();
  
  // Check authentication status
  await checkAuthStatus();
  
  // If authenticated, load lists
  if (authState.isAuthenticated) {
    await loadLists();
  }
}

/**
 * Setup tab functionality
 */
function setupTabs() {
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabId = button.getAttribute('data-tab');
      
      // Update button active states
      tabButtons.forEach(btn => {
        btn.classList.toggle('active', btn === button);
      });
      
      // Show the selected tab content
      tabContents.forEach(tab => {
        tab.classList.toggle('active', tab.id === tabId);
      });
    });
  });
}

/**
 * Setup form handlers for adding new items
 */
function setupFormHandlers() {
  // Allow List form
  addAllowForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = formatUrl(allowUrlInput.value);
    
    if (!validateUrl(url)) {
      showError('Please enter a valid domain name (e.g. example.com)');
      return;
    }
    
    await addToList('allowList', url);
    allowUrlInput.value = '';
  });
  
  // Block List form
  addBlockForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = formatUrl(blockUrlInput.value);
    
    if (!validateUrl(url)) {
      showError('Please enter a valid domain name (e.g. example.com)');
      return;
    }
    
    await addToList('blockList', url);
    blockUrlInput.value = '';
  });
}

/**
 * Check authentication status
 */
async function checkAuthStatus() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getAuthStatus' });
    
    if (response && response.success) {
      authState.isAuthenticated = response.isAuthenticated;
      authState.user = response.user;
      
      // Update UI based on auth state
      updateAuthUI();
      
      return response.isAuthenticated;
    } else {
      console.error('Error getting auth status:', response?.error || 'Unknown error');
      showError('Failed to get authentication status. Please try logging in again.');
      authState.isAuthenticated = false;
      updateAuthUI();
      
      return false;
    }
  } catch (error) {
    console.error('Error checking auth status:', error);
    showError('Error connecting to authentication service. Please check your connection.');
    authState.isAuthenticated = false;
    updateAuthUI();
    
    return false;
  }
}

/**
 * Update UI based on authentication state
 */
function updateAuthUI() {
  if (authState.isAuthenticated) {
    notAuthenticated.classList.add('hidden');
    listsContent.classList.remove('hidden');
  } else {
    notAuthenticated.classList.remove('hidden');
    listsContent.classList.add('hidden');
  }
}

/**
 * Load user's allow and block lists
 */
async function loadLists() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getProfile' });
    
    if (response && response.success) {
      // Update lists state
      listsState.allowList = response.user.allowList || [];
      listsState.blockList = response.user.blockList || [];
      
      // Render the lists
      renderAllowList();
      renderBlockList();
    } else {
      console.error('Error loading lists:', response?.message || 'Unknown error');
      
      if (response?.message?.includes('authentication') || response?.message?.includes('401')) {
        showError('Your session has expired. Please log in again.');
        authState.isAuthenticated = false;
        updateAuthUI();
      } else {
        showError('Failed to load lists. Please try again.');
      }
    }
  } catch (error) {
    console.error('Error loading lists:', error);
    showError('Network error while loading lists');
  }
}

/**
 * Render the allow list table
 */
function renderAllowList() {
  const tbody = allowListTable.querySelector('tbody');
  tbody.innerHTML = '';
  
  if (listsState.allowList.length === 0) {
    allowListTable.classList.add('hidden');
    allowListEmpty.classList.remove('hidden');
    return;
  }
  
  allowListTable.classList.remove('hidden');
  allowListEmpty.classList.add('hidden');
  
  // Sort by most recent first
  const sortedList = [...listsState.allowList].sort((a, b) => 
    new Date(b.addedAt) - new Date(a.addedAt)
  );
  
  sortedList.forEach(item => {
    const tr = document.createElement('tr');
    
    const urlCell = document.createElement('td');
    urlCell.textContent = item.url;
    tr.appendChild(urlCell);
    
    const dateCell = document.createElement('td');
    dateCell.textContent = formatDate(item.addedAt);
    tr.appendChild(dateCell);
    
    const actionsCell = document.createElement('td');
    const removeButton = document.createElement('button');
    removeButton.className = 'action-btn delete';
    removeButton.innerHTML = '<i class="fas fa-trash"></i>';
    removeButton.title = 'Remove from allow list';
    removeButton.addEventListener('click', () => removeFromList('allowList', item.url));
    actionsCell.appendChild(removeButton);
    tr.appendChild(actionsCell);
    
    tbody.appendChild(tr);
  });
}

/**
 * Render the block list table
 */
function renderBlockList() {
  const tbody = blockListTable.querySelector('tbody');
  tbody.innerHTML = '';
  
  if (listsState.blockList.length === 0) {
    blockListTable.classList.add('hidden');
    blockListEmpty.classList.remove('hidden');
    return;
  }
  
  blockListTable.classList.remove('hidden');
  blockListEmpty.classList.add('hidden');
  
  // Sort by most recent first
  const sortedList = [...listsState.blockList].sort((a, b) => 
    new Date(b.addedAt) - new Date(a.addedAt)
  );
  
  sortedList.forEach(item => {
    const tr = document.createElement('tr');
    
    const urlCell = document.createElement('td');
    urlCell.textContent = item.url;
    tr.appendChild(urlCell);
    
    const dateCell = document.createElement('td');
    dateCell.textContent = formatDate(item.addedAt);
    tr.appendChild(dateCell);
    
    const actionsCell = document.createElement('td');
    const removeButton = document.createElement('button');
    removeButton.className = 'action-btn delete';
    removeButton.innerHTML = '<i class="fas fa-trash"></i>';
    removeButton.title = 'Remove from block list';
    removeButton.addEventListener('click', () => removeFromList('blockList', item.url));
    actionsCell.appendChild(removeButton);
    tr.appendChild(actionsCell);
    
    tbody.appendChild(tr);
  });
}

/**
 * Add a URL to a list
 */
async function addToList(listType, url) {
  try {
    // Check if URL is already in the list
    const list = listsState[listType];
    if (list.some(item => item.url === url)) {
      showError(`${url} is already in your ${formatListName(listType)}`);
      return;
    }
    
    // Check if URL is in the other list
    const otherListType = listType === 'allowList' ? 'blockList' : 'allowList';
    if (listsState[otherListType].some(item => item.url === url)) {
      const confirmMove = confirm(
        `"${url}" is currently in your ${formatListName(otherListType)}. ` +
        `Would you like to move it to your ${formatListName(listType)}?`
      );
      
      if (confirmMove) {
        await removeFromList(otherListType, url, false);
      } else {
        return;
      }
    }
    
    const response = await chrome.runtime.sendMessage({
      action: 'updateLists',
      listAction: 'add',
      listType: listType,
      url: url
    });
    
    if (response && response.success) {
      // Update local state
      listsState[listType] = response[listType];
      
      // Re-render the list
      if (listType === 'allowList') {
        renderAllowList();
      } else {
        renderBlockList();
      }
      
      showSuccess(`${url} added to your ${formatListName(listType)}`);
    } else {
      showError(response?.message || `Failed to add ${url} to your ${formatListName(listType)}`);
    }
  } catch (error) {
    console.error(`Error adding to ${listType}:`, error);
    showError(`Error adding ${url} to your ${formatListName(listType)}`);
  }
}

/**
 * Remove a URL from a list
 */
async function removeFromList(listType, url, showConfirmation = true) {
  try {
    if (showConfirmation) {
      const confirmRemove = confirm(`Are you sure you want to remove "${url}" from your ${formatListName(listType)}?`);
      if (!confirmRemove) {
        return;
      }
    }
    
    const response = await chrome.runtime.sendMessage({
      action: 'updateLists',
      listAction: 'remove',
      listType: listType,
      url: url
    });
    
    if (response && response.success) {
      // Update local state
      listsState[listType] = response[listType];
      
      // Re-render the list
      if (listType === 'allowList') {
        renderAllowList();
      } else {
        renderBlockList();
      }
      
      if (showConfirmation) {
        showSuccess(`${url} removed from your ${formatListName(listType)}`);
      }
    } else {
      showError(response?.message || `Failed to remove ${url} from your ${formatListName(listType)}`);
    }
  } catch (error) {
    console.error(`Error removing from ${listType}:`, error);
    showError(`Error removing ${url} from your ${formatListName(listType)}`);
  }
}

/**
 * Format a URL to ensure it's just a domain
 * Strip http://, https://, www. and any path components
 */
function formatUrl(url) {
  // Remove protocol
  let formatted = url.replace(/^(https?:\/\/)?(www\.)?/i, '');
  
  // Remove path and query parameters
  formatted = formatted.split('/')[0];
  
  // Remove port if present
  formatted = formatted.split(':')[0];
  
  // Trim any whitespace
  formatted = formatted.trim();
  
  return formatted;
}

/**
 * Validate a URL to ensure it's a valid domain
 */
function validateUrl(url) {
  // Simple domain validation regex
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  
  return url && domainRegex.test(url);
}

/**
 * Format a date string into a human-readable format
 */
function formatDate(dateString) {
  if (!dateString) return 'Unknown';
  
  try {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return 'Invalid date';
  }
}

/**
 * Format list type into a human-readable name
 */
function formatListName(listType) {
  switch (listType) {
    case 'allowList': return 'trusted sites';
    case 'blockList': return 'blocked sites';
    default: return listType;
  }
}

/**
 * Show error message
 */
function showError(message) {
  errorMessage.textContent = message;
  errorMessage.style.display = 'block';
  successMessage.style.display = 'none';
  
  // Hide after 5 seconds
  setTimeout(() => {
    errorMessage.style.display = 'none';
  }, 5000);
}

/**
 * Show success message
 */
function showSuccess(message) {
  successMessage.textContent = message;
  successMessage.style.display = 'block';
  errorMessage.style.display = 'none';
  
  // Hide after 5 seconds
  setTimeout(() => {
    successMessage.style.display = 'none';
  }, 5000);
}

// Initialize the page when DOM is loaded
document.addEventListener('DOMContentLoaded', initLists);