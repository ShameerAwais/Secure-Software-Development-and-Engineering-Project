// Popup script for PhishGuard

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

// Auth-related DOM elements
const authSection = document.getElementById('auth-section');
const authStatus = document.getElementById('auth-status');
const authStatusText = document.getElementById('auth-status-text');
const authButtons = document.getElementById('auth-buttons');
const userMenu = document.getElementById('user-menu');
const loginButton = document.getElementById('login-button');
const registerButton = document.getElementById('register-button');
const profileButton = document.getElementById('profile-button');
const historyButton = document.getElementById('history-button');
const listsButton = document.getElementById('lists-button');
const logoutButton = document.getElementById('logout-button');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginFormElement = document.getElementById('login-form-element');
const registerFormElement = document.getElementById('register-form-element');
const loginBackButton = document.getElementById('login-back-button');
const registerBackButton = document.getElementById('register-back-button');
const loginError = document.getElementById('login-error');
const registerError = document.getElementById('register-error');
const loginEmail = document.getElementById('login-email');
const loginPassword = document.getElementById('login-password');
const registerName = document.getElementById('register-name');
const registerEmail = document.getElementById('register-email');
const registerPassword = document.getElementById('register-password');
const urlActions = document.getElementById('url-actions');
const addToAllowlist = document.getElementById('add-to-allowlist');
const addToBlocklist = document.getElementById('add-to-blocklist');

// Current URL and auth state
let currentUrl = '';
let authState = {
  isAuthenticated: false,
  user: null
};

// Function to check current tab URL safety
async function checkCurrentPage() {
  try {
    // Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentUrl = tab.url;
    
    // Update URL display
    currentUrlElement.textContent = currentUrl;
    
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
      chrome.runtime.sendMessage({ action: 'checkUrl', url: currentUrl }, (response) => {
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
    
    // Handle scan result
    handleScanResult(response);
    
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

// Function to handle scan result
function handleScanResult(response) {
  console.log("Full scan result:", response);
  
  if (response && response.success) {
    // Handle successful scan
    const { isSafe, threatType, details } = response.data;
    const source = details?.source;
    const indicators = details?.threatIndicators || [];
    
    // Check if there are phishing indicators even if isSafe flag is set
    const hasPhishingIndicators = indicators.length > 0;
    
    // Check if the URL uses HTTP
    const isHttp = currentUrl.startsWith('http:') && !currentUrl.startsWith('https:');
    
    console.log("Safety check:", { 
      isSafe, 
      hasPhishingIndicators, 
      indicators, 
      isHttp
    });
    
    // Always mark HTTP as unsafe regardless of other checks
    if (isHttp) {
      indicators.push('Non-secure HTTP connection (not using HTTPS)');
      updateStatus(
        'unsafe', 
        'Insecure connection detected', 
        'This site uses HTTP instead of HTTPS, which means your connection is not encrypted. Any information you submit could be intercepted.'
      );
      return;
    }
    
    // Truly safe only if explicitly marked safe AND no indicators AND using HTTPS
    if (isSafe === true && !hasPhishingIndicators) {
      updateStatus(
        'safe', 
        'Website appears to be safe', 
        source ? `No threats detected<br><small>Source: ${source}</small>` : 'No threats detected'
      );
    } else if (isSafe === null) {
      // Case where we couldn't definitively determine (neutral) or limited scan
      // Always show indicators if they exist
      if (hasPhishingIndicators) {
        let detailMessage = `Suspicious patterns detected:<br>`;
        detailMessage += '<ul style="margin: 5px 0; padding-left: 15px;">';
        indicators.forEach(indicator => {
          detailMessage += `<li>${indicator}</li>`;
        });
        detailMessage += '</ul>';
        
        if (source) {
          detailMessage += `<small>Source: ${source}</small>`;
        }
        
        updateStatus('warning', 'Security concerns detected', detailMessage);
      } else {
        // No indicators, but couldn't fully determine
        updateStatus(
          'warning', 
          'Limited security assessment', 
          source ? 
            `Only basic checks were performed. Full security scan unavailable.<br><small>Source: ${source}</small>` : 
            'Only basic checks were performed. Full security scan unavailable.'
        );
      }
    } else {
      // Explicitly flagged as unsafe or has indicators
      let detailMessage = threatType ? `Threat type: ${threatType}` : 'Security issues detected';
      
      // Add source information if available
      if (source) {
        detailMessage += `<br><small>Source: ${source}</small>`;
      }
      
      // Add specific threat indicators if available
      if (hasPhishingIndicators) {
        detailMessage += '<br><br>Detected issues:';
        detailMessage += '<ul style="margin: 5px 0; padding-left: 15px;">';
        indicators.forEach(indicator => {
          detailMessage += `<li>${indicator}</li>`;
        });
        detailMessage += '</ul>';
      }
      
      // Categorize threats for clearer warning messages
      if (indicators.some(ind => ind.toLowerCase().includes('brand') || ind.toLowerCase().includes('impersonation') || ind.toLowerCase().includes('spoofing'))) {
        updateStatus('unsafe', 'Potential brand impersonation detected', detailMessage);
      } else if (indicators.some(ind => ind.toLowerCase().includes('http:'))) {
        updateStatus('unsafe', 'Insecure connection detected', detailMessage);
      } else {
        updateStatus('unsafe', 'Security threat detected', detailMessage);
      }
    }
    
    // Show URL actions for authenticated users only
    if (authState.isAuthenticated) {
      urlActions.classList.remove('hidden');
    }

    // Display AI analysis (if available)
    displayAiAnalysis(response.data);
  } else {
    // If falling back to local checks
    if (response.fallback) {
      const source = response.data?.details?.source;
      const sourceText = source ? `<br><small>Source: ${source}</small>` : '';
      
      // Check if the fallback response has threat indicators
      const indicators = response.data?.details?.threatIndicators || [];
      
      // Check if the URL uses HTTP (even in fallback mode)
      const isHttp = currentUrl.startsWith('http:') && !currentUrl.startsWith('https:');
      
      if (isHttp) {
        // Always warn about HTTP
        updateStatus(
          'unsafe',
          'Insecure connection detected',
          'This site uses HTTP instead of HTTPS, which means your connection is not encrypted. Any information you submit could be intercepted.'
        );
      } else if (indicators.length > 0) {
        let detailMessage = `Local security scan found issues:${sourceText}`;
        detailMessage += '<ul style="margin: 5px 0; padding-left: 15px;">';
        indicators.forEach(indicator => {
          detailMessage += `<li>${indicator}</li>`;
        });
        detailMessage += '</ul>';
        
        updateStatus(
          'warning',
          'Suspicious patterns detected',
          detailMessage
        );
      } else {
        updateStatus(
          'warning', 
          'Limited scan only', 
          `Security service unavailable. Only basic checks were performed.${sourceText}<br><small>Error: ${response.error || 'Server connection failed'}</small>`
        );
      }
    } else if (response.requiresAuth) {
      updateStatus(
        'warning', 
        'Authentication Required', 
        'Please log in to enable full website scanning'
      );
    } else {
      updateStatus(
        'unsafe', 
        'Error checking website', 
        `${response.error || 'Unknown error'}`
      );
    }
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

/**
 * Display AI analysis results in the popup
 * @param {Object} data - Scan result data with AI analysis
 */
function displayAiAnalysis(data) {
  // Create AI analysis section if it doesn't exist
  let aiAnalysisSection = document.querySelector('.ai-analysis');
  if (!aiAnalysisSection) {
    aiAnalysisSection = document.createElement('div');
    aiAnalysisSection.className = 'ai-analysis';
    
    const heading = document.createElement('h2');
    heading.innerHTML = '<i class="material-icons">psychology</i> Security Analysis';
    aiAnalysisSection.appendChild(heading);
    
    document.querySelector('.container').appendChild(aiAnalysisSection);
  } else {
    // Clear existing content except heading
    const heading = aiAnalysisSection.querySelector('h2');
    aiAnalysisSection.innerHTML = '';
    aiAnalysisSection.appendChild(heading);
  }

  // Check for Google Safe Browsing results first
  if (data.details?.safeBrowsing || 
      (data.details?.source && data.details.source.includes("Google Safe Browsing"))) {
    
    // Display Google Safe Browsing results
    const safeBrowsingContainer = document.createElement('div');
    safeBrowsingContainer.className = 'google-sb-result';
    safeBrowsingContainer.style.marginBottom = '15px';
    
    const sbVerdict = document.createElement('div');
    sbVerdict.style.padding = '10px';
    sbVerdict.style.borderRadius = '4px';
    sbVerdict.style.marginBottom = '15px';
    
    if (data.isSafe) {
      sbVerdict.style.backgroundColor = '#e8f5e9';
      sbVerdict.style.color = '#2e7d32';
      sbVerdict.textContent = 'No known threats detected';
    } else {
      sbVerdict.style.backgroundColor = '#ffebee';
      sbVerdict.style.color = '#c62828';
      sbVerdict.textContent = `Threat detected: ${data.threatType || 'Malicious website'}`;
    }
    
    safeBrowsingContainer.appendChild(sbVerdict);
    aiAnalysisSection.appendChild(safeBrowsingContainer);
    
    // If Google Safe Browsing found it unsafe, don't show ML score
    if (!data.isSafe) return;
  }
  
  // Check if we have ML score data
  if (!data.mlScore && !data.phishingScore) {
    return; // No AI analysis data available
  }
  
  // Use whatever score is available
  const score = data.mlScore || data.phishingScore || 0;
  
  // Create phishing score gauge
  const scoreContainer = document.createElement('div');
  scoreContainer.className = 'ai-score-container';
  
  // Calculate safe percentage for the gauge
  const safePercent = 100 - score;
  
  // Create gauge element
  const scoreGauge = document.createElement('div');
  scoreGauge.className = 'ai-score-gauge';
  scoreGauge.style.setProperty('--safe-percent', `${safePercent}%`);
  
  const scoreValue = document.createElement('div');
  scoreValue.className = 'ai-score-value';
  scoreValue.textContent = score;
  scoreGauge.appendChild(scoreValue);
  
  // Create score details
  const scoreDetails = document.createElement('div');
  scoreDetails.className = 'ai-score-details';
  
  const scoreLabel = document.createElement('div');
  scoreLabel.className = 'ai-score-label';
  
  // Determine risk level based on the score
  let riskLevel, scoreDescription;
  if (score < 30) {
    riskLevel = 'Low Risk';
    scoreDescription = 'Our ML model indicates this site is likely legitimate.';
  } else if (score < 70) {
    riskLevel = 'Medium Risk';
    scoreDescription = 'Some suspicious patterns detected, exercise caution.';
  } else {
    riskLevel = 'High Risk';
    scoreDescription = 'Multiple phishing indicators detected by our ML model.';
  }
  
  scoreLabel.textContent = `ML Phishing Score: ${riskLevel}`;
  
  const scoreDesc = document.createElement('div');
  scoreDesc.className = 'ai-score-description';
  scoreDesc.textContent = scoreDescription;
  
  scoreDetails.appendChild(scoreLabel);
  scoreDetails.appendChild(scoreDesc);
  
  // Assemble score container
  scoreContainer.appendChild(scoreGauge);
  scoreContainer.appendChild(scoreDetails);
  aiAnalysisSection.appendChild(scoreContainer);
  
  // Add contributing features if available
  if (data.importantFeatures && data.importantFeatures.length > 0) {
    const featuresContainer = document.createElement('div');
    featuresContainer.className = 'ai-features';
    
    // Add heading for features
    const featuresHeading = document.createElement('div');
    featuresHeading.style.fontSize = '14px';
    featuresHeading.style.fontWeight = '500';
    featuresHeading.style.marginBottom = '10px';
    featuresHeading.textContent = 'Top Contributing Factors';
    featuresContainer.appendChild(featuresHeading);
    
    // Add each feature
    data.importantFeatures.forEach(feature => {
      const featureElement = document.createElement('div');
      featureElement.className = 'ai-feature';
      
      // Icon based on contribution value
      const iconType = parseFloat(feature.contribution) > 0.05 ? 'warning' : 'info';
      
      featureElement.innerHTML = `
        <div class="ai-feature-icon">
          <i class="material-icons">${iconType}</i>
        </div>
        <div class="ai-feature-name">${feature.name}</div>
        <div class="ai-feature-confidence">
          <div class="ai-feature-confidence-bar" 
               style="width: ${Math.min(parseFloat(feature.contribution) * 200, 100)}%"></div>
        </div>
        <div class="ai-feature-confidence-text">${Math.round(parseFloat(feature.contribution) * 100)}%</div>
      `;
      
      featuresContainer.appendChild(featureElement);
    });
    
    aiAnalysisSection.appendChild(featuresContainer);
  } else if (data.details?.threatIndicators && data.details.threatIndicators.length > 0) {
    // Add threat indicators as features
    const featuresContainer = document.createElement('div');
    featuresContainer.className = 'ai-features';
    
    // Add heading for features
    const featuresHeading = document.createElement('div');
    featuresHeading.style.fontSize = '14px';
    featuresHeading.style.fontWeight = '500';
    featuresHeading.style.marginBottom = '10px';
    featuresHeading.textContent = 'Detected Issues';
    featuresContainer.appendChild(featuresHeading);
    
    // Add each indicator as a feature
    data.details.threatIndicators.forEach(indicator => {
      const featureElement = document.createElement('div');
      featureElement.className = 'ai-feature';
      
      featureElement.innerHTML = `
        <div class="ai-feature-icon">
          <i class="material-icons">warning</i>
        </div>
        <div class="ai-feature-name" style="flex: 1">${indicator}</div>
      `;
      
      featuresContainer.appendChild(featureElement);
    });
    
    aiAnalysisSection.appendChild(featuresContainer);
  }
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

// Function to check authentication status
async function checkAuthStatus() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getAuthStatus' });
    
    if (response && response.success) {
      authState.isAuthenticated = response.isAuthenticated;
      authState.user = response.user;
      
      // Update UI based on auth state
      updateAuthUI();
    } else {
      console.error('Error getting auth status:', response?.error || 'Unknown error');
      authState.isAuthenticated = false;
      authState.user = null;
      updateAuthUI();
    }
  } catch (error) {
    console.error('Error checking auth status:', error);
    authState.isAuthenticated = false;
    authState.user = null;
    updateAuthUI();
  }
}

// Function to update authentication UI
function updateAuthUI() {
  if (authState.isAuthenticated && authState.user) {
    // User is logged in
    authStatus.classList.remove('not-logged-in');
    authStatus.classList.add('logged-in');
    authStatusText.textContent = `Logged in as ${authState.user.name || authState.user.email}`;
    
    // Show user menu, hide login/register buttons
    authButtons.classList.add('hidden');
    userMenu.classList.remove('hidden');
    
    // Show URL actions section if we have a URL
    if (currentUrl) {
      urlActions.classList.remove('hidden');
    }
    
    // Hide forms
    loginForm.classList.add('hidden');
    registerForm.classList.add('hidden');
    
    // Enable scan functionality
    checkButton.disabled = false;
    
    // Show scan instructions
    if (statusMessage.textContent === 'Authentication Required') {
      updateStatus('checking', 'Click "Scan Again" to check for threats', 'Ready to scan with user preferences');
    }
  } else {
    // User is not logged in
    authStatus.classList.add('not-logged-in');
    authStatus.classList.remove('logged-in');
    authStatusText.textContent = 'Not logged in';
    
    // Show login/register buttons, hide user menu
    authButtons.classList.remove('hidden');
    userMenu.classList.add('hidden');
    urlActions.classList.add('hidden');
    
    // Hide forms by default
    loginForm.classList.add('hidden');
    registerForm.classList.add('hidden');
    
    // Show authentication required message
    updateStatus('warning', 'Scanning Disabled', 'Please log in to enable website scanning');
    
    // Allow unauthenticated users to click scan to see the "no scanning" message
    checkButton.disabled = false;
  }
}

// Function to handle login
async function handleLogin(e) {
  e.preventDefault();
  
  // Get form values
  const email = loginEmail.value.trim();
  const password = loginPassword.value;
  
  // Basic validation
  if (!email || !password) {
    showLoginError('Email and password are required');
    return;
  }
  
  try {
    // Show loading state
    const submitBtn = loginFormElement.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Logging in...';
    
    // Send login request
    const response = await chrome.runtime.sendMessage({
      action: 'login',
      credentials: { email, password }
    });
    
    // Reset form state
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
    
    if (response && response.success) {
      // Update auth state
      authState.isAuthenticated = true;
      authState.user = response.user;
      
      // Clear form
      loginFormElement.reset();
      loginError.classList.add('hidden');
      loginForm.classList.add('hidden');
      
      // Update UI
      updateAuthUI();
      
      // Check URL again with authenticated user
      if (currentUrl) {
        checkCurrentPage();
      }
    } else {
      // Show error
      showLoginError(response?.message || 'Login failed. Please try again.');
    }
  } catch (error) {
    console.error('Login error:', error);
    showLoginError('Error connecting to authentication service');
  }
}

// Function to handle registration
async function handleRegister(e) {
  e.preventDefault();
  
  // Get form values
  const name = registerName.value.trim();
  const email = registerEmail.value.trim();
  const password = registerPassword.value;
  
  // Basic validation
  if (!email || !password) {
    showRegisterError('Email and password are required');
    return;
  }
  
  if (password.length < 8) {
    showRegisterError('Password must be at least 8 characters');
    return;
  }
  
  try {
    // Show loading state
    const submitBtn = registerFormElement.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating account...';
    
    // Send register request
    const response = await chrome.runtime.sendMessage({
      action: 'register',
      userData: { name, email, password }
    });
    
    // Reset form state
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
    
    if (response && response.success) {
      // Update auth state
      authState.isAuthenticated = true;
      authState.user = response.user;
      
      // Clear form
      registerFormElement.reset();
      registerError.classList.add('hidden');
      registerForm.classList.add('hidden');
      
      // Update UI
      updateAuthUI();
      
      // Check URL again with authenticated user
      if (currentUrl) {
        checkCurrentPage();
      }
    } else {
      // Show error
      showRegisterError(response?.message || 'Registration failed. Please try again.');
    }
  } catch (error) {
    console.error('Registration error:', error);
    showRegisterError('Error connecting to authentication service');
  }
}

// Function to handle logout
async function handleLogout() {
  try {
    await chrome.runtime.sendMessage({ action: 'logout' });
    
    // Update auth state
    authState.isAuthenticated = false;
    authState.user = null;
    
    // Update UI
    updateAuthUI();
  } catch (error) {
    console.error('Logout error:', error);
  }
}

// Function to add URL to allowlist
async function addToAllowlistHandler() {
  if (!authState.isAuthenticated || !currentUrl) {
    return;
  }
  
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'updateLists',
      listAction: 'add',
      listType: 'allowList',
      url: new URL(currentUrl).hostname
    });
    
    if (response && response.success) {
      // Show success message
      updateStatus('safe', 'Added to trusted sites', 'This domain has been added to your trusted sites list');
      
      // Re-check the URL with updated lists
      setTimeout(checkCurrentPage, 1000);
    } else {
      console.error('Error adding to allowlist:', response?.message || 'Unknown error');
    }
  } catch (error) {
    console.error('Error adding to allowlist:', error);
  }
}

// Function to add URL to blocklist
async function addToBlocklistHandler() {
  if (!authState.isAuthenticated || !currentUrl) {
    return;
  }
  
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'updateLists',
      listAction: 'add',
      listType: 'blockList',
      url: new URL(currentUrl).hostname
    });
    
    if (response && response.success) {
      // Show success message
      updateStatus('unsafe', 'Added to blocked sites', 'This domain has been added to your blocked sites list');
      
      // Re-check the URL with updated lists
      setTimeout(checkCurrentPage, 1000);
    } else {
      console.error('Error adding to blocklist:', response?.message || 'Unknown error');
    }
  } catch (error) {
    console.error('Error adding to blocklist:', error);
  }
}

// Helper functions for forms
function showLoginForm() {
  loginForm.classList.remove('hidden');
  registerForm.classList.add('hidden');
  authButtons.classList.add('hidden');
  loginEmail.focus();
}

function showRegisterForm() {
  registerForm.classList.remove('hidden');
  loginForm.classList.add('hidden');
  authButtons.classList.add('hidden');
  registerName.focus();
}

function hideAuthForms() {
  loginForm.classList.add('hidden');
  registerForm.classList.add('hidden');
  authButtons.classList.remove('hidden');
}

function showLoginError(message) {
  loginError.textContent = message;
  loginError.classList.remove('hidden');
}

function showRegisterError(message) {
  registerError.textContent = message;
  registerError.classList.remove('hidden');
}

// Function to open options page
function openOptionsPage() {
  chrome.runtime.openOptionsPage();
}

// Function to open history page
function openHistoryPage() {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/history.html') });
}

// Function to open profile page
function openProfilePage() {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/profile.html') });
}

// Function to open lists management page
function openListsPage() {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/lists.html') });
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

// Authentication event listeners
loginButton.addEventListener('click', showLoginForm);
registerButton.addEventListener('click', showRegisterForm);
loginBackButton.addEventListener('click', hideAuthForms);
registerBackButton.addEventListener('click', hideAuthForms);
loginFormElement.addEventListener('submit', handleLogin);
registerFormElement.addEventListener('submit', handleRegister);
logoutButton.addEventListener('click', handleLogout);
profileButton.addEventListener('click', openProfilePage);
historyButton.addEventListener('click', openHistoryPage);
listsButton.addEventListener('click', openListsPage);
addToAllowlist.addEventListener('click', addToAllowlistHandler);
addToBlocklist.addEventListener('click', addToBlocklistHandler);

// Initialize popup when it opens
document.addEventListener('DOMContentLoaded', async () => {
  // Check authentication status
  await checkAuthStatus();
  
  // Display current URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentUrl = tab.url;
    currentUrlElement.textContent = currentUrl;
  } catch (error) {
    currentUrlElement.textContent = 'Unable to retrieve URL';
  }
  
  // Set initial status based on auth state
  if (!authState.isAuthenticated) {
    updateStatus('warning', 'Scanning Disabled', 'Please log in to enable website scanning');
    checkButton.disabled = false;
  } else {
    statusMessage.textContent = 'Click "Scan Again" to check for threats';
    statusDetails.textContent = 'No scan performed yet';
    checkButton.disabled = false;
  }
  
  // Check server status on load
  checkServerStatus();
  
  // Set up listener for auth state changes (from other tabs/windows)
  document.addEventListener('auth_state_changed', (event) => {
    console.log('Auth state change detected:', event.detail);
    // Update our local auth state
    authState.isAuthenticated = event.detail.isAuthenticated;
    authState.user = event.detail.user;
    // Update UI
    updateAuthUI();
  });
});