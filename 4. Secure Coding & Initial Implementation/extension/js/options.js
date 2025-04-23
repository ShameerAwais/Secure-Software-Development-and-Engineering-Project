// Options page script for Web Safety Scanner

// DOM elements
const apiEndpointInput = document.getElementById('api-endpoint');
const offlineModeToggle = document.getElementById('offline-mode');
const autoFallbackToggle = document.getElementById('auto-fallback');
const dataSharingConsentToggle = document.getElementById('data-sharing-consent');
const saveButton = document.getElementById('save-button');
const checkConnectionButton = document.getElementById('check-connection');
const clearHistoryButton = document.getElementById('clear-history');
const serverIndicator = document.getElementById('server-indicator');
const statusText = document.getElementById('status-text');

// Load saved settings when page opens
document.addEventListener('DOMContentLoaded', loadSettings);

// Event listeners
saveButton.addEventListener('click', saveSettings);
checkConnectionButton.addEventListener('click', checkConnection);
clearHistoryButton.addEventListener('click', clearHistory);

// Function to load settings from storage
async function loadSettings() {
  try {
    const settings = await chrome.storage.local.get([
      'apiUrl',
      'fallbackApiUrls',
      'offlineMode',
      'autoFallback',
      'dataSharingConsent',
      'lastServerStatus'
    ]);
    
    // Set API endpoint
    apiEndpointInput.value = settings.apiUrl || 'http://localhost:5000/api/v1';
    
    // Set toggle switches
    offlineModeToggle.checked = settings.offlineMode || false;
    autoFallbackToggle.checked = settings.autoFallback !== undefined ? settings.autoFallback : true;
    dataSharingConsentToggle.checked = settings.dataSharingConsent !== undefined ? settings.dataSharingConsent : true;
    
    // Set server status message
    updateServerStatusUI(settings.lastServerStatus);
    
    console.log('Settings loaded', settings);
  } catch (error) {
    console.error('Error loading settings:', error);
    showNotification('Error loading settings: ' + error.message, true);
  }
}

// Function to save settings
async function saveSettings() {
  try {
    // Validate API endpoint
    if (!apiEndpointInput.value.trim()) {
      showNotification('API endpoint cannot be empty', true);
      return;
    }
    
    // Validate API URL
    if (!isValidUrl(apiEndpointInput.value.trim())) {
      showNotification('Please enter a valid API URL', true);
      apiEndpointInput.focus();
      return;
    }
    
    // Visual feedback that save is in progress
    saveButton.disabled = true;
    saveButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    
    // Gather settings from form
    const settings = {
      apiUrl: apiEndpointInput.value.trim(),
      offlineMode: offlineModeToggle.checked,
      autoFallback: autoFallbackToggle.checked,
      dataSharingConsent: dataSharingConsentToggle.checked
    };
    
    // Define fallback API URLs if not already set
    const currentStorage = await chrome.storage.local.get(['fallbackApiUrls']);
    if (!currentStorage.fallbackApiUrls) {
      settings.fallbackApiUrls = [
        'http://localhost:5000/api/v1',
        'http://localhost:3000/api/v1',
        'https://api.websafetyscanner.example.com/api/v1'
      ];
    }
    
    // Set Safe Browsing API timeout settings
    settings.apiTimeouts = {
      safeBrowsing: 5000,  // 5 second timeout for Safe Browsing API
      backend: 8000,       // 8 second timeout for backend server
      maxRetries: 1        // Only retry once to avoid long waits
    };
    
    // Save to storage
    await chrome.storage.local.set(settings);
    
    // Check connection if not in offline mode
    if (!settings.offlineMode) {
      await checkConnection();
    } else {
      updateServerStatusUI({
        isAvailable: false,
        lastChecked: new Date().toISOString(),
        activeUrl: settings.apiUrl,
        message: 'Offline mode enabled'
      });
    }
    
    // Show success message
    showNotification('Settings saved successfully!');
    
    console.log('Settings saved', settings);
  } catch (error) {
    console.error('Error saving settings:', error);
    showNotification('Failed to save settings: ' + error.message, true);
  } finally {
    // Reset save button
    saveButton.disabled = false;
    saveButton.innerHTML = '<i class="fas fa-save"></i> Save Settings';
  }
}

// Function to check server connection
async function checkConnection() {
  try {
    // Update UI to show checking state
    serverIndicator.className = 'status-indicator';
    statusText.textContent = 'Checking connection...';
    statusText.className = 'loading';
    
    // Send message to background script to check connection
    const result = await chrome.runtime.sendMessage({ action: 'checkServerAvailability' });
    
    // Update UI based on result
    const settings = await chrome.storage.local.get(['lastServerStatus']);
    updateServerStatusUI(settings.lastServerStatus);
    
  } catch (error) {
    console.error('Error checking connection:', error);
    serverIndicator.className = 'status-indicator offline';
    statusText.textContent = 'Error checking connection';
    statusText.className = '';
  }
}

// Function to clear history
async function clearHistory() {
  try {
    // Confirm with user
    if (!confirm('Are you sure you want to clear all scan history and results?')) {
      return;
    }
    
    // Clear scan history from storage
    await chrome.storage.local.remove(['scanHistory', 'lastScanResults']);
    
    showNotification('Scan history cleared successfully');
  } catch (error) {
    console.error('Error clearing history:', error);
    showNotification('Failed to clear history: ' + error.message, true);
  }
}

// Function to update server status UI
function updateServerStatusUI(serverStatus) {
  statusText.className = ''; // Remove loading animation
  
  if (!serverStatus) {
    serverIndicator.className = 'status-indicator offline';
    statusText.textContent = 'Unknown server status';
    return;
  }
  
  if (serverStatus.isAvailable) {
    serverIndicator.className = 'status-indicator online';
    statusText.textContent = `Connected (Last checked: ${formatDate(serverStatus.lastChecked)})`;
  } else {
    serverIndicator.className = 'status-indicator offline';
    const message = serverStatus.message || 'Server unavailable';
    statusText.textContent = `${message} (Last checked: ${formatDate(serverStatus.lastChecked)})`;
  }
}

// Function to show notification message
function showNotification(message, isError = false) {
  const notification = document.createElement('div');
  notification.textContent = message;
  notification.style.position = 'fixed';
  notification.style.bottom = '20px';
  notification.style.right = '20px';
  notification.style.padding = '12px 20px';
  notification.style.backgroundColor = isError ? 'var(--error-bg)' : 'var(--success-bg)';
  notification.style.color = isError ? 'var(--error-color)' : 'var(--success-color)';
  notification.style.borderRadius = 'var(--border-radius)';
  notification.style.boxShadow = 'var(--box-shadow)';
  notification.style.zIndex = '1000';
  notification.style.maxWidth = '300px';
  notification.style.animation = 'fadeIn 0.3s ease-in-out';
  
  // Add animation
  document.head.insertAdjacentHTML('beforeend', `
    <style>
      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @keyframes fadeOut {
        from { opacity: 1; transform: translateY(0); }
        to { opacity: 0; transform: translateY(10px); }
      }
      .fadeOut {
        animation: fadeOut 0.3s ease-in-out forwards;
      }
    </style>
  `);
  
  document.body.appendChild(notification);
  
  // Remove notification after 3 seconds
  setTimeout(() => {
    notification.classList.add('fadeOut');
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300); // Wait for animation to complete
  }, 3000);
}

// Format date for display
function formatDate(dateString) {
  if (!dateString) return 'Never';
  
  const date = new Date(dateString);
  return date.toLocaleString();
}

// Function to validate URL
function isValidUrl(url) {
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}