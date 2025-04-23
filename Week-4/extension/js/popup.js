// Popup script for Web Safety Scanner

// DOM elements
const statusContainer = document.getElementById('status-container');
const statusMessage = document.getElementById('status-message');
const statusDetails = document.getElementById('status-details');
const checkButton = document.getElementById('check-button');
const reportButton = document.getElementById('report-button');
const settingsLink = document.getElementById('settings-link');
const currentUrlElement = document.getElementById('current-url');
const serverIndicator = document.getElementById('server-indicator');
const serverStatusText = document.getElementById('server-status-text');

// Function to check current tab URL safety
async function checkCurrentPage() {
  try {
    // Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url;
    
    // Update URL display
    currentUrlElement.textContent = url;
    
    // Update UI to checking state
    updateStatus('checking', 'Checking website safety...', 'Analyzing URL patterns and security features');
    
    // Send message to content script to perform the check
    chrome.tabs.sendMessage(tab.id, { action: 'checkCurrentPage' }, (error) => {
      // Check for error in content script communication
      if (chrome.runtime.lastError) {
        console.log('Content script error:', chrome.runtime.lastError);
      }
    });
    
    // Create a promise with timeout for the background script message
    const checkUrlPromise = new Promise((resolve, reject) => {
      // Set timeout to prevent hanging
      const timeoutId = setTimeout(() => {
        reject(new Error('Connection timeout. Server did not respond.'));
      }, 10000); // 10 second timeout
      
      // Send message to background script to check URL
      chrome.runtime.sendMessage({ action: 'checkUrl', url }, (response) => {
        clearTimeout(timeoutId);
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(response);
      });
    });
    
    // Wait for the response with timeout protection
    const response = await checkUrlPromise;
    
    // Handle no response case
    if (!response) {
      updateStatus('unsafe', 'Error checking website', 'No response from security service');
      return;
    }
    
    // Handle successful response
    if (response.success) {
      const { isSafe, threatType, phishingScore, details } = response.data;
      
      if (isSafe) {
        updateStatus('safe', 'Website appears to be safe', 'No threats detected');
      } else if (isSafe === null) {
        // For the case where we're in offline mode or couldn't determine
        updateStatus('warning', 'Limited scan only', 'Only local checks were performed. Full security scan unavailable.');
      } else {
        // Create detailed message for unsafe site
        let detailMessage = `Threat type: ${threatType || 'Unknown'}`;
        
        // Add phishing score if available
        if (phishingScore !== undefined) {
          detailMessage += `<br>Phishing Score: ${phishingScore}/100`;
        }
        
        // Add specific threat indicators if available
        if (details && details.threatIndicators && details.threatIndicators.length > 0) {
          detailMessage += '<br><br>Detected issues:';
          detailMessage += '<ul style="margin: 5px 0; padding-left: 15px;">';
          details.threatIndicators.forEach(indicator => {
            detailMessage += `<li>${indicator}</li>`;
          });
          detailMessage += '</ul>';
        }
        
        updateStatus('unsafe', 'Potential security threat detected', detailMessage);
      }
    } else {
      // If falling back to local checks
      if (response.fallback) {
        updateStatus('warning', 'Limited scan only', 
          'Security service unavailable. Only local checks were performed: ' + 
          (response.error || 'Server connection failed'));
      } else {
        updateStatus('unsafe', 'Error checking website', response.error || 'Unknown error');
      }
    }
    
    // Check server status and update indicator
    checkServerStatus();
  } catch (error) {
    console.error('Error checking URL:', error);
    
    // Provide specific error message for network failures
    if (error.message.includes('Failed to fetch') || 
        error.message.includes('NetworkError') ||
        error.message.includes('timeout') ||
        error.message.includes('Network request failed')) {
      updateStatus(
        'warning',
        'Connection error',
        'Failed to connect to security service. Please check your internet connection and try again.'
      );
    } else {
      updateStatus(
        'unsafe',
        'Error checking website',
        `Service error: ${error.message || 'Unknown error occurred'}`
      );
    }
    
    // Check server status on error too
    checkServerStatus();
  }
}

// Function to update status UI with icons
function updateStatus(type, message, details) {
  // Remove all status classes
  statusContainer.classList.remove('safe', 'unsafe', 'warning', 'checking');
  
  // Add appropriate class
  statusContainer.classList.add(type);
  
  // Update icon based on status type
  let iconClass = 'fa-sync-alt';
  if (type === 'safe') iconClass = 'fa-check-circle';
  if (type === 'unsafe') iconClass = 'fa-exclamation-triangle';
  if (type === 'warning') iconClass = 'fa-exclamation-circle';
  
  // Update icon, message and details
  statusContainer.querySelector('.status-icon i').className = `fas ${iconClass}`;
  statusMessage.textContent = message;
  statusDetails.innerHTML = details;
}

// Function to check server status and update indicator
async function checkServerStatus() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'checkServerAvailability' });
    
    if (response && response.success) {
      if (response.isAvailable) {
        serverIndicator.className = 'status-indicator online';
        serverStatusText.textContent = 'Server Status: Online';
      } else {
        serverIndicator.className = 'status-indicator offline';
        serverStatusText.textContent = 'Server Status: Offline';
      }
    } else {
      serverIndicator.className = 'status-indicator offline';
      serverStatusText.textContent = 'Server Status: Unknown';
    }
  } catch (error) {
    console.error('Error checking server status:', error);
    serverIndicator.className = 'status-indicator offline';
    serverStatusText.textContent = 'Server Status: Error';
  }
}

// Function to open options page
function openOptionsPage() {
  chrome.runtime.openOptionsPage();
}

// Function to report current website
function reportWebsite() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = encodeURIComponent(tabs[0].url);
    chrome.tabs.create({ 
      url: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${url}` 
    });
  });
}

// Event listeners
checkButton.addEventListener('click', checkCurrentPage);
reportButton.addEventListener('click', reportWebsite);
settingsLink.addEventListener('click', openOptionsPage);

// Initialize popup when it opens
document.addEventListener('DOMContentLoaded', async () => {
  // Display current URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentUrlElement.textContent = tab.url;
  } catch (error) {
    currentUrlElement.textContent = 'Unable to retrieve URL';
  }
  
  // Set initial status
  statusMessage.textContent = 'Click "Scan Again" to check for threats';
  statusDetails.textContent = 'No scan performed yet';
  
  // Check server status on load
  checkServerStatus();
});