/**
 * User Profile and Statistics Management
 */

// DOM elements - Profile
const notAuthenticated = document.getElementById('not-authenticated');
const profileContent = document.getElementById('profile-content');
const errorMessage = document.getElementById('error-message');
const successMessage = document.getElementById('success-message');
const userEmail = document.getElementById('user-email');
const userName = document.getElementById('user-name');
const userRole = document.getElementById('user-role');
const userSince = document.getElementById('user-since');

// DOM elements - Statistics
const periodWeekBtn = document.getElementById('period-week');
const periodMonthBtn = document.getElementById('period-month');
const periodYearBtn = document.getElementById('period-year');
const statsLoading = document.getElementById('stats-loading');
const statTotalScans = document.getElementById('stat-total-scans');
const statUniqueDomains = document.getElementById('stat-unique-domains');
const statSafeSites = document.getElementById('stat-safe-sites');
const statThreats = document.getElementById('stat-threats');
const noStats = document.getElementById('no-stats');

// DOM elements - Overview stats
const overviewSafeSites = document.getElementById('overview-safe-sites');
const overviewThreats = document.getElementById('overview-threats');

// DOM elements - Account settings
const displayNameInput = document.getElementById('display-name');
const emailAddressInput = document.getElementById('email-address');
const currentPasswordInput = document.getElementById('current-password');
const newPasswordInput = document.getElementById('new-password');
const confirmPasswordInput = document.getElementById('confirm-password');
const accountForm = document.getElementById('account-form');

// DOM elements - Notification settings
const notifyThreats = document.getElementById('notify-threats');
const notifyUpdates = document.getElementById('notify-updates');
const notifySummary = document.getElementById('notify-summary');
const notificationLevel = document.getElementById('notification-level');
const notificationsForm = document.getElementById('notifications-form');

// Navigation elements
const sidebarLinks = document.querySelectorAll('.sidebar-link');
const tabContents = document.querySelectorAll('.tab-content');

// State
let authState = {
  isAuthenticated: false,
  user: null
};

let statsState = {
  currentPeriod: 'week',
  isLoading: false
};

/**
 * Initialize the profile page
 */
async function initProfile() {
  // Check authentication first
  await checkAuthStatus();
  
  // Set up event listeners for statistics period buttons
  periodWeekBtn.addEventListener('click', () => changeStatsPeriod('week'));
  periodMonthBtn.addEventListener('click', () => changeStatsPeriod('month'));
  periodYearBtn.addEventListener('click', () => changeStatsPeriod('year'));
  
  // Set up account form submission handler
  if (accountForm) {
    accountForm.addEventListener('submit', saveAccountSettings);
  }
  
  // Set up notifications form submission handler
  if (notificationsForm) {
    notificationsForm.addEventListener('submit', saveNotificationSettings);
  }
  
  // Set up sidebar navigation
  setupNavigation();
  
  // Check if user is authenticated and load appropriate data
  if (authState.isAuthenticated) {
    await fetchFreshProfileData();
    await loadStatistics(statsState.currentPeriod);
  }
}

/**
 * Set up sidebar navigation and tab switching
 */
function setupNavigation() {
  sidebarLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      
      // Check if this is a tab switch or external link
      const tabId = link.getAttribute('data-tab');
      const targetPage = link.getAttribute('data-target');
      
      if (tabId) {
        // Tab navigation within the page
        switchTab(tabId);
      } else if (targetPage) {
        // Navigate to another page
        window.location.href = targetPage;
      }
    });
  });
}

/**
 * Switch tabs in the profile page
 */
function switchTab(tabId) {
  // Update sidebar active state
  sidebarLinks.forEach(link => {
    if (link.getAttribute('data-tab') === tabId) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
  
  // Show the selected tab content
  tabContents.forEach(tab => {
    if (tab.id === tabId) {
      tab.classList.add('active');
    } else {
      tab.classList.remove('active');
    }
  });
  
  // If switching to statistics tab, refresh the data
  if (tabId === 'tab-statistics') {
    loadStatistics(statsState.currentPeriod);
  }
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
      updateUI();
      
      return response.isAuthenticated;
    } else {
      console.error('Error getting auth status:', response?.error || 'Unknown error');
      showError('Failed to get authentication status. Please try logging in again.');
      authState.isAuthenticated = false;
      updateUI();
      
      return false;
    }
  } catch (error) {
    console.error('Error checking auth status:', error);
    showError('Error connecting to authentication service. Please check your connection.');
    authState.isAuthenticated = false;
    updateUI();
    
    return false;
  }
}

/**
 * Fetch fresh profile data from the server
 */
async function fetchFreshProfileData() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getProfile' });
    
    if (response && response.success) {
      // Update auth state with fresh user data
      authState.user = response.user;
      
      // Update UI with fresh data
      updateUI();
      
      console.log('Profile data refreshed successfully');
      return true;
    } else {
      console.error('Error fetching profile data:', response?.message || 'Unknown error');
      if (response?.message?.includes('authentication') || response?.message?.includes('401')) {
        showError('Your session has expired. Please log in again.');
        authState.isAuthenticated = false;
        updateUI();
      } else {
        showError('Failed to refresh profile data');
      }
      
      return false;
    }
  } catch (error) {
    console.error('Error fetching fresh profile data:', error);
    showError('Network error while refreshing profile data');
    return false;
  }
}

/**
 * Update UI based on authentication state
 */
function updateUI() {
  if (authState.isAuthenticated && authState.user) {
    notAuthenticated.classList.add('hidden');
    profileContent.classList.remove('hidden');
    
    // Update account info
    userEmail.textContent = authState.user.email || 'Not provided';
    userName.textContent = authState.user.name || 'Not provided';
    userRole.textContent = capitalizeFirstLetter(authState.user.role || 'user');
    
    // Format and display creation date
    let createdDate = 'Unknown';
    if (authState.user.createdAt) {
      try {
        createdDate = new Date(authState.user.createdAt).toLocaleDateString();
      } catch (e) {
        console.error('Error formatting date:', e);
      }
    }
    userSince.textContent = createdDate;
    
    // Update account form fields
    if (displayNameInput) {
      displayNameInput.value = authState.user.name || '';
    }
    
    if (emailAddressInput) {
      emailAddressInput.value = authState.user.email || '';
    }
    
    // Update notification settings if available
    if (authState.user.preferences) {
      if (notifyThreats) {
        notifyThreats.checked = authState.user.preferences.notifyThreats !== undefined ? 
          authState.user.preferences.notifyThreats : true;
      }
      
      if (notifyUpdates) {
        notifyUpdates.checked = authState.user.preferences.notifyUpdates !== undefined ? 
          authState.user.preferences.notifyUpdates : true;
      }
      
      if (notifySummary) {
        notifySummary.checked = authState.user.preferences.notifySummary !== undefined ? 
          authState.user.preferences.notifySummary : true;
      }
      
      if (notificationLevel) {
        notificationLevel.value = authState.user.preferences.notificationLevel || 'all';
      }
    } else {
      // Default notification settings
      if (notifyThreats) notifyThreats.checked = true;
      if (notifyUpdates) notifyUpdates.checked = true;
      if (notifySummary) notifySummary.checked = true;
      if (notificationLevel) notificationLevel.value = 'all';
    }
    
    // Fetch monthly stats for overview if we're authenticated
    loadOverviewStats();
  } else {
    notAuthenticated.classList.remove('hidden');
    profileContent.classList.add('hidden');
  }
}

/**
 * Handle account settings form submission
 */
async function saveAccountSettings(e) {
  e.preventDefault();
  
  if (!authState.isAuthenticated) {
    showError('You must be logged in to update account settings');
    return;
  }
  
  // Get form values
  const displayName = displayNameInput.value.trim();
  const currentPassword = currentPasswordInput.value;
  const newPassword = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;
  
  // Basic validation
  if (!displayName) {
    showError('Display name cannot be empty');
    return;
  }
  
  // Check if password is being updated
  let passwordUpdate = false;
  if (newPassword || confirmPassword) {
    passwordUpdate = true;
    
    if (!currentPassword) {
      showError('Current password is required to change password');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      showError('New passwords do not match');
      return;
    }
    
    if (newPassword.length < 8) {
      showError('New password must be at least 8 characters');
      return;
    }
  }
  
  // Create update object
  const accountUpdate = {
    name: displayName
  };
  
  if (passwordUpdate) {
    accountUpdate.currentPassword = currentPassword;
    accountUpdate.newPassword = newPassword;
  }
  
  // Show loading state
  const submitBtn = accountForm.querySelector('button[type="submit"]');
  const originalText = submitBtn.innerHTML;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
  
  try {
    // This action needs to be implemented in the background script
    const response = await chrome.runtime.sendMessage({
      action: 'updateAccount',
      accountUpdate
    });
    
    // Reset button
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
    
    if (response && response.success) {
      showSuccess('Account settings updated successfully');
      
      // Clear password fields
      currentPasswordInput.value = '';
      newPasswordInput.value = '';
      confirmPasswordInput.value = '';
      
      // Fetch fresh profile data to ensure we have the latest
      await fetchFreshProfileData();
    } else {
      showError(response?.message || 'Failed to update account settings');
    }
  } catch (error) {
    console.error('Error updating account settings:', error);
    showError('Error connecting to authentication service');
    
    // Reset button
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
  }
}

/**
 * Handle notification settings form submission
 */
async function saveNotificationSettings(e) {
  e.preventDefault();
  
  if (!authState.isAuthenticated) {
    showError('You must be logged in to update notification settings');
    return;
  }
  
  // Create notification preferences object
  const notificationPreferences = {
    notifyThreats: notifyThreats.checked,
    notifyUpdates: notifyUpdates.checked,
    notifySummary: notifySummary.checked,
    notificationLevel: notificationLevel.value
  };
  
  // Show loading state
  const submitBtn = notificationsForm.querySelector('button[type="submit"]');
  const originalText = submitBtn.innerHTML;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
  
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'updatePreferences',
      preferences: notificationPreferences
    });
    
    // Reset button
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
    
    if (response && response.success) {
      showSuccess('Notification settings saved successfully');
      
      // Update local user state
      if (authState.user) {
        authState.user.preferences = {
          ...authState.user.preferences,
          ...notificationPreferences
        };
      }
    } else {
      showError(response?.message || 'Failed to save notification settings');
    }
  } catch (error) {
    console.error('Error saving notification settings:', error);
    showError('Error connecting to authentication service');
    
    // Reset button
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
  }
}

/**
 * Load user statistics for a specific time period
 */
async function loadStatistics(period) {
  if (!authState.isAuthenticated) {
    return;
  }
  
  // Update UI to show loading
  setStatsLoadingState(true);
  statsState.currentPeriod = period;
  
  // Update period buttons
  periodWeekBtn.classList.toggle('active', period === 'week');
  periodMonthBtn.classList.toggle('active', period === 'month');
  periodYearBtn.classList.toggle('active', period === 'year');
  
  try {
    // Fetch actual stats from the background script/server
    // For now we'll simulate statistics data (replace this with actual API call when backend is ready)
    const mockStats = getMockStatsData(period);
    displayStatistics(mockStats);
    
    // The actual API call would look like this:
    /*
    const response = await chrome.runtime.sendMessage({
      action: 'getUserStats',
      timeRange: period
    });
    
    if (response && response.success) {
      displayStatistics(response.stats);
    } else {
      console.error('Error loading statistics:', response?.message || 'Unknown error');
      resetStatistics('Error loading statistics');
      
      if (response?.message?.includes('authentication') || response?.message?.includes('401')) {
        // Handle authentication issues
        showError('Your session has expired. Please log in again.');
        await checkAuthStatus(); // This will update UI if needed
      }
    }
    */
  } catch (error) {
    console.error('Error loading statistics:', error);
    resetStatistics('Network error');
  } finally {
    setStatsLoadingState(false);
  }
}

/**
 * Generate mock statistics data for demonstration
 * Remove this when connected to actual backend
 */
function getMockStatsData(period) {
  // Scale factors based on period
  const scaleFactor = period === 'week' ? 1 : period === 'month' ? 4 : 52;
  
  // Generate some reasonable numbers
  const totalScans = Math.floor(Math.random() * 50) + 10 * scaleFactor;
  const uniqueDomains = Math.floor(totalScans * 0.7);
  const threats = Math.floor(Math.random() * 5) * scaleFactor;
  const safeSites = totalScans - threats;
  
  return {
    totalScans,
    uniqueDomains,
    safeSites,
    threats
  };
}

/**
 * Load statistics for the overview section
 */
async function loadOverviewStats() {
  if (!authState.isAuthenticated || !overviewSafeSites || !overviewThreats) {
    return;
  }
  
  try {
    // Use mock data for now (replace with actual API call when backend is ready)
    const mockStats = getMockStatsData('month');
    overviewSafeSites.textContent = mockStats.safeSites;
    overviewThreats.textContent = mockStats.threats;
    
    // The actual API call would look like this:
    /*
    const response = await chrome.runtime.sendMessage({
      action: 'getUserStats',
      timeRange: 'month'
    });
    
    if (response && response.success) {
      overviewSafeSites.textContent = response.stats?.safeSites || 0;
      overviewThreats.textContent = response.stats?.threats || 0;
    } else {
      overviewSafeSites.textContent = '-';
      overviewThreats.textContent = '-';
    }
    */
  } catch (error) {
    console.error('Error loading overview statistics:', error);
    overviewSafeSites.textContent = '-';
    overviewThreats.textContent = '-';
  }
}

/**
 * Display statistics data in the UI
 */
function displayStatistics(stats) {
  if (!stats || Object.keys(stats).length === 0) {
    noStats.classList.remove('hidden');
    resetStatistics('No data');
    return;
  }
  
  noStats.classList.add('hidden');
  
  // Update statistics values
  statTotalScans.textContent = stats.totalScans || 0;
  statUniqueDomains.textContent = stats.uniqueDomains || 0;
  statSafeSites.textContent = stats.safeSites || 0;
  statThreats.textContent = stats.threats || 0;
}

/**
 * Reset statistics display
 */
function resetStatistics(placeholder = '-') {
  statTotalScans.textContent = placeholder;
  statUniqueDomains.textContent = placeholder;
  statSafeSites.textContent = placeholder;
  statThreats.textContent = placeholder;
}

/**
 * Change the statistics time period
 */
function changeStatsPeriod(period) {
  if (statsState.isLoading || statsState.currentPeriod === period) return;
  loadStatistics(period);
}

/**
 * Set loading state for statistics
 */
function setStatsLoadingState(isLoading) {
  statsState.isLoading = isLoading;
  
  if (isLoading) {
    statsLoading.classList.remove('hidden');
  } else {
    statsLoading.classList.add('hidden');
  }
}

/**
 * Helper function to show error message
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
 * Helper function to show success message
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

/**
 * Helper function to capitalize first letter
 */
function capitalizeFirstLetter(string) {
  if (!string) return '';
  return string.charAt(0).toUpperCase() + string.slice(1);
}

// Initialize the profile page when DOM is loaded
document.addEventListener('DOMContentLoaded', initProfile);