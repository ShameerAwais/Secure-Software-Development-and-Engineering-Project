// Background service worker for Web Safety Scanner
const API_BASE_URL = "http://localhost:5001/api/v1";
const FALLBACK_API_URLS = [
  "http://localhost:5001/api/v1",
  "http://localhost:3000/api/v1", // Alternative local port
  "https://api.websafetyscanner.example.com/api/v1" // Example production URL
];

// Import auth service using ES module import
import authService from './auth.js';

// Initialize extension settings
chrome.runtime.onInstalled.addListener(() => {
  console.log('Extension installed/updated - initializing settings');
  
  // Store default API URL and fallback options with improved timeout settings
  chrome.storage.local.set({
    apiUrl: API_BASE_URL,
    fallbackApiUrls: FALLBACK_API_URLS,
    lastServerStatus: {
      isAvailable: false,
      lastChecked: null,
      activeUrl: API_BASE_URL
    },
    autoFallback: true, // Enable auto-fallback to alternative servers
    offlineMode: false, // Start in online mode by default
    apiTimeouts: {
      safeBrowsing: 5000,  // 5 second timeout for Safe Browsing API
      backend: 8000,       // 8 second timeout for backend server
      maxRetries: 1        // Only retry once to avoid long waits
    }
  }, () => {
    console.log('Settings initialized with API URL:', API_BASE_URL);
    // Run an initial server availability check
    checkServerAvailability();
  });
});

// Check if the server is available - returns a promise
async function checkServerAvailability() {
  try {
    const settings = await chrome.storage.local.get([
      "apiUrl", 
      "fallbackApiUrls", 
      "lastServerStatus", 
      "autoFallback", 
      "offlineMode"
    ]);
    
    // If offline mode is enabled, don't check server
    if (settings.offlineMode) {
      console.log("Offline mode enabled, skipping server check");
      return false;
    }
    
    const currentApiUrl = settings.apiUrl || API_BASE_URL;
    let isAvailable = false;
    let activeUrl = currentApiUrl;
    
    // Try the current API URL first
    try {
      console.log(`Checking server availability: ${currentApiUrl}`);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      const response = await fetch(`${currentApiUrl}/status`, {
        method: "GET",
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        isAvailable = true;
        console.log("Primary server is available");
      }
    } catch (error) {
      console.warn(`Primary server unavailable: ${error.message}`);
      
      // If auto-fallback is enabled, try fallback URLs
      if (settings.autoFallback && settings.fallbackApiUrls && settings.fallbackApiUrls.length > 0) {
        console.log("Trying fallback servers...");
        
        // Try each fallback URL
        for (const fallbackUrl of settings.fallbackApiUrls) {
          if (fallbackUrl === currentApiUrl) continue; // Skip the current URL
          
          try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            
            const response = await fetch(`${fallbackUrl}/status`, {
              method: "GET",
              signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
              isAvailable = true;
              activeUrl = fallbackUrl;
              
              // Update active API URL since fallback is working
              await chrome.storage.local.set({ apiUrl: fallbackUrl });
              console.log(`Switched to fallback server: ${fallbackUrl}`);
              break;
            }
          } catch (fallbackError) {
            console.warn(`Fallback server ${fallbackUrl} unavailable: ${fallbackError.message}`);
          }
        }
      }
    }
    
    // Update server status
    const serverStatus = {
      isAvailable,
      lastChecked: new Date().toISOString(),
      activeUrl
    };
    
    await chrome.storage.local.set({ lastServerStatus: serverStatus });
    console.log(`Server availability: ${isAvailable ? 'Online' : 'Offline'}`);
    console.log(`Active API URL: ${activeUrl}`);
    
    return isAvailable;
  } catch (error) {
    console.error("Error checking server availability:", error);
    return false;
  }
}

// Listen for messages from content script or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // URL scanning - check auth first
  if (message.action === "checkUrl") {
    // Check if user is authenticated
    authService.loadAuthState().then(state => {
      if (!state.isAuthenticated) {
        // User is not authenticated, return a "no scanning" response
        sendResponse({
          success: true, // Changed to true so UI can handle it properly
          noScanning: true, // New flag to indicate no scanning option
          requiresAuth: true,
          data: {
            url: message.url,
            isSafe: null,
            threatType: null,
            analysisPhase: "NO_SCANNING",
            details: {
              message: "Scanning disabled. Please log in to use the scanning feature."
            }
          }
        });
      } else {
        // User is authenticated, proceed with URL analysis
        analyzeUrl(message.url, message.pageContent)
          .then(result => sendResponse(result))
          .catch(error => sendResponse({ success: false, error: error.message }));
      }
    }).catch(error => {
      console.error("Error checking auth state:", error);
      sendResponse({ success: false, error: "Error checking authentication status" });
    });
    
    return true; // Required for async sendResponse
  }
  
  // New action to open extension popup from content script
  if (message.action === "openPopup") {
    // Can't directly open the popup, but we can create a notification that when clicked will focus on the extension
    chrome.notifications.create({
      type: 'basic',
      iconUrl: '/images/icon128.jpg',
      title: 'Web Safety Scanner',
      message: 'Click here to open the Web Safety Scanner and log in',
      priority: 2
    }, (notificationId) => {
      // Add listener for notification click
      chrome.notifications.onClicked.addListener(function notificationClickHandler(clickedId) {
        if (clickedId === notificationId) {
          // Try to open the popup programmatically
          chrome.action.openPopup();
          // Remove this specific listener after it's used
          chrome.notifications.onClicked.removeListener(notificationClickHandler);
        }
      });
    });
    
    sendResponse({ success: true });
    return true;
  }
  
  // Server availability check
  if (message.action === "checkServerAvailability") {
    checkServerAvailability()
      .then(isAvailable => sendResponse({ success: true, isAvailable }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Required for async sendResponse
  }
  
  // Authentication requests
  if (message.action === "register") {
    console.log("Registration request received in background.js:", { 
      email: message.userData.email,
      name: message.userData.name,
      // Don't log password
    });
    
    // Check server availability first
    checkServerAvailability().then(isAvailable => {
      if (!isAvailable) {
        console.warn("Server unavailable, registration might fail");
      }
      
      // Make sure authService has the current API URL
      return chrome.storage.local.get(["apiUrl"]);
    })
    .then(result => {
      console.log("Using API URL for registration:", result.apiUrl || API_BASE_URL);
      
      // Make sure to wait for the auth state to load
      return authService.loadAuthState();
    })
    .then(() => {
      // Now perform registration
      return authService.register(message.userData);
    })
    .then(result => {
      console.log("Registration result:", result);
      sendResponse(result);
    })
    .catch(error => {
      console.error("Registration error in background.js:", error);
      sendResponse({ 
        success: false, 
        error: error.message,
        message: "Error during registration: " + error.message 
      });
    });
    return true;
  }
  
  if (message.action === "login") {
    console.log("Login request received in background.js:", { 
      email: message.credentials.email,
      // Don't log password
    });
    
    // Check server availability first
    checkServerAvailability().then(isAvailable => {
      if (!isAvailable) {
        console.warn("Server unavailable, login might fail");
      }
      
      // Make sure authService has the current API URL
      return chrome.storage.local.get(["apiUrl"]);
    })
    .then(result => {
      console.log("Using API URL for login:", result.apiUrl || API_BASE_URL);
      
      // Make sure to wait for the auth state to load
      return authService.loadAuthState();
    })
    .then(() => {
      // Now perform login
      return authService.login(message.credentials);
    })
    .then(result => {
      console.log("Login result:", result);
      sendResponse(result);
    })
    .catch(error => {
      console.error("Login error in background.js:", error);
      sendResponse({ 
        success: false, 
        error: error.message,
        message: "Error during login: " + error.message 
      });
    });
    return true;
  }
  
  if (message.action === "logout") {
    authService.logout()
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  // Profile and account features - ensure they require authentication
  if (["getProfile", "updatePreferences", "updateAccount", "updateLists", "getUserHistory", "getUserStats"].includes(message.action)) {
    // First check if user is authenticated
    authService.loadAuthState().then(state => {
      if (!state.isAuthenticated) {
        sendResponse({
          success: false,
          requiresAuth: true,
          message: "Authentication required to access this feature"
        });
      } else {
        // User is authenticated, proceed with the requested action
        switch (message.action) {
          case "getProfile":
            authService.getProfile()
              .then(result => sendResponse(result))
              .catch(error => sendResponse({ success: false, error: error.message }));
            break;
            
          case "updatePreferences":
            authService.updatePreferences(message.preferences)
              .then(result => sendResponse(result))
              .catch(error => sendResponse({ success: false, error: error.message }));
            break;
            
          case "updateAccount":
            handleAccountUpdate(message, sendResponse);
            break;
            
          case "updateLists":
            authService.updateLists(message.listAction, message.listType, message.url)
              .then(result => sendResponse(result))
              .catch(error => sendResponse({ success: false, error: error.message }));
            break;
            
          case "getUserHistory":
            authService.getUserHistory(message.page, message.limit)
              .then(result => sendResponse(result))
              .catch(error => sendResponse({ success: false, error: error.message }));
            break;
            
          case "getUserStats":
            authService.getUserStats(message.timeRange)
              .then(result => sendResponse(result))
              .catch(error => sendResponse({ success: false, error: error.message }));
            break;
        }
      }
    }).catch(error => {
      console.error(`Error checking auth state for ${message.action}:`, error);
      sendResponse({ success: false, error: "Error checking authentication status" });
    });
    
    return true; // Required for async sendResponse
  }
  
  if (message.action === "getAuthStatus") {
    console.log("Auth status request received");
    
    authService.loadAuthState()
      .then(state => {
        console.log("Auth state loaded:", {
          isAuthenticated: state.isAuthenticated,
          user: state.user ? state.user.email : null
        });
        
        sendResponse({
          success: true,
          isAuthenticated: state.isAuthenticated,
          user: state.user
        });
      })
      .catch(error => {
        console.error("Auth status error:", error);
        sendResponse({ 
          success: false, 
          error: error.message,
          isAuthenticated: false
        });
      });
    return true;
  }
});

// Helper function to handle account update
function handleAccountUpdate(message, sendResponse) {
  console.log("Account update request received in background.js:", { 
    name: message.accountUpdate.name,
    passwordUpdate: message.accountUpdate.currentPassword ? true : false
  });
  
  // Check server availability first
  checkServerAvailability().then(isAvailable => {
    if (!isAvailable) {
      console.warn("Server unavailable, account update might fail");
      return { success: false, message: "Server is unavailable" };
    }
    
    // Make sure authService has the current API URL
    return chrome.storage.local.get(["apiUrl"]);
  })
  .then(result => {
    console.log("Using API URL for account update:", result.apiUrl || API_BASE_URL);
    
    if (result.success === false) {
      return result; // Pass through the error from server availability check
    }
    
    // Make sure to wait for the auth state to load
    return authService.loadAuthState();
  })
  .then((result) => {
    if (result && result.success === false) {
      return result; // Pass through the error
    }
    
    // Create updateAccountData function in auth service if it doesn't exist yet
    if (!authService.updateAccountData) {
      authService.updateAccountData = async function(accountData) {
        if (!this.isAuthenticated) {
          return {
            success: false,
            message: 'Not authenticated'
          };
        }
        
        try {
          const response = await fetch(`${this.API_URL}/auth/update-account`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify(accountData)
          });
          
          const data = await response.json();
          
          if (data.success) {
            // Update local user data
            this.user = {
              ...this.user,
              name: data.user.name,
              email: data.user.email
            };
            
            await this.saveAuthState();
          }
          
          return data;
        } catch (error) {
          console.error('Update account error:', error);
          return {
            success: false,
            message: 'Network or server error updating account'
          };
        }
      };
    }
    
    // Now perform account update
    return authService.updateAccountData(message.accountUpdate);
  })
  .then(result => {
    console.log("Account update result:", result);
    sendResponse(result);
  })
  .catch(error => {
    console.error("Account update error in background.js:", error);
    sendResponse({ 
      success: false, 
      error: error.message,
      message: "Error during account update: " + error.message 
    });
  });
}

// URL Analyzer function - first step in the architecture
async function analyzeUrl(url, pageContent = null) {
  // Ensure user is authenticated
  const authState = await authService.loadAuthState();
  if (!authState.isAuthenticated) {
    return {
      success: false,
      requiresAuth: true,
      data: {
        url,
        isSafe: null,
        threatType: null,
        analysisPhase: "AUTH_REQUIRED",
        details: {
          message: "Authentication required to analyze URLs"
        }
      }
    };
  }
  
  try {
    console.log("URL Analyzer: Analyzing URL", url);
    
    // Extract domain from URL for list checking
    let domain;
    try {
      domain = new URL(url).hostname;
      // Remove www. if present
      domain = domain.replace(/^www\./, '');
    } catch (e) {
      console.warn("Invalid URL format:", url);
      domain = url;
    }
    
    // Check if domain is in user's allow list
    if (authState.user && authState.user.allowList && 
        authState.user.allowList.some(item => domain.includes(item.url) || item.url.includes(domain))) {
      console.log("URL is in user's allow list:", domain);
      return {
        success: true,
        data: {
          url,
          isSafe: true,
          threatType: null,
          analysisPhase: "ALLOW_LIST",
          details: {
            reason: "Domain is in your trusted sites list",
            listMatch: "allowList"
          }
        }
      };
    }
    
    // Check if domain is in user's block list
    if (authState.user && authState.user.blockList && 
        authState.user.blockList.some(item => domain.includes(item.url) || item.url.includes(domain))) {
      console.log("URL is in user's block list:", domain);
      return {
        success: true,
        data: {
          url,
          isSafe: false,
          threatType: "BLOCKLIST",
          analysisPhase: "BLOCK_LIST",
          details: {
            reason: "Domain is in your blocked sites list",
            listMatch: "blockList"
          }
        }
      };
    }
    
    // Skip local URL pattern analysis and rely entirely on Google Safe Browsing API
    // for URL scanning to reduce false positives
    
    // Extract page content for analysis if available
    let contentAnalysis = null;
    if (pageContent && !pageContent.error) {
      console.log("Content Analyzer: Analyzing webpage content");
      contentAnalysis = analyzePageContent(pageContent);
    }
    
    // Use backend service for URL scanning (Google Safe Browsing API) 
    // and page content analysis
    console.log("Sending URL to backend for Google Safe Browsing analysis");
    
    // Use authenticated endpoint if user is logged in
    if (authService.isAuthenticated) {
      console.log("User is authenticated. Using personalized URL checking");
      return await checkUrlWithAuthenticatedBackend(url, contentAnalysis);
    } else {
      return await checkUrlWithBackend(url, contentAnalysis);
    }
  } catch (error) {
    console.error("Error in URL analysis:", error);
    return { 
      success: false, 
      error: error.message,
      fallback: true,
      data: {
        url,
        isSafe: true, // Default to safe if analysis fails
        threatType: null,
        analysisPhase: "ERROR"
      }
    };
  }
}

/**
 * Check URL with authenticated backend services
 * @param {string} url - URL to check
 * @param {object} contentAnalysis - Result of local content analysis
 * @returns {object} Safety check result
 */
async function checkUrlWithAuthenticatedBackend(url, contentAnalysis = null) {
  try {
    // Get API URL from storage
    const result = await chrome.storage.local.get(['apiUrl']);
    const apiUrl = result.apiUrl || API_BASE_URL;
    
    // Get timeout settings
    const timeoutSettings = await chrome.storage.local.get(['apiTimeouts']);
    const timeout = timeoutSettings.apiTimeouts?.backend || 8000;
    
    // Set up abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    // Prepare request payload
    const payload = {
      url,
      includeContentAnalysis: !!contentAnalysis,
      contentScore: contentAnalysis?.score || 0,
      threatIndicators: contentAnalysis?.indicators || []
    };
    
    // Make the request to authenticated endpoint
    const response = await fetch(`${apiUrl}/urls/user-check`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${authService.token}`
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    // Process response
    if (response.ok) {
      const data = await response.json();
      
      // Handle both response formats - new format has 'result' property
      const resultData = data.result || data.data || {};
      
      console.log("Authenticated backend response:", resultData);
      
      return {
        success: true,
        data: {
          url,
          isSafe: resultData.isSafe,
          threatType: resultData.threatType,
          analysisPhase: "BACKEND_FULL",
          phishingScore: resultData.phishingScore,
          details: resultData.details || {}
        }
      };
    } else {
      // Handle error responses
      return {
        success: false,
        error: `Backend error: ${response.status}`,
        fallback: true,
        data: {
          url,
          isSafe: null,
          threatType: null,
          analysisPhase: "ERROR",
          details: {
            message: `Error from backend service: ${response.statusText}`
          }
        }
      };
    }
  } catch (error) {
    // Handle network errors or timeouts
    console.error("Error checking URL with backend:", error);
    
    // For timeouts, provide a specific message
    if (error.name === "AbortError") {
      return {
        success: false,
        error: "Request timed out",
        fallback: true,
        data: {
          url,
          isSafe: null,
          threatType: null,
          analysisPhase: "TIMEOUT",
          details: {
            message: "Backend service request timed out"
          }
        }
      };
    }
    
    // For other errors
    return {
      success: false,
      error: error.message,
      fallback: true,
      data: {
        url,
        isSafe: null,
        threatType: null,
        analysisPhase: "ERROR",
        details: {
          message: `Network or server error: ${error.message}`
        }
      }
    };
  }
}

/**
 * Check URL with unauthenticated backend services
 * @param {string} url - URL to check
 * @param {object} contentAnalysis - Result of local content analysis
 * @returns {object} Safety check result
 */
async function checkUrlWithBackend(url, contentAnalysis = null) {
  try {
    // Get API URL from storage
    const result = await chrome.storage.local.get(['apiUrl']);
    const apiUrl = result.apiUrl || API_BASE_URL;
    
    // Get timeout settings
    const timeoutSettings = await chrome.storage.local.get(['apiTimeouts']);
    const timeout = timeoutSettings.apiTimeouts?.backend || 8000;
    
    // Set up abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    // Prepare request payload
    const payload = {
      url,
      includeContentAnalysis: !!contentAnalysis,
      contentScore: contentAnalysis?.score || 0,
      threatIndicators: contentAnalysis?.indicators || []
    };
    
    // Make the request to unauthenticated endpoint
    const response = await fetch(`${apiUrl}/urls/check`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    // Process response
    if (response.ok) {
      const data = await response.json();
      
      // Handle both response formats - new format has 'result' property
      const resultData = data.result || data.data || {};
      
      console.log("Backend response:", resultData);
      
      return {
        success: true,
        data: {
          url,
          isSafe: resultData.isSafe,
          threatType: resultData.threatType,
          analysisPhase: "BACKEND_BASIC",
          phishingScore: resultData.phishingScore,
          details: resultData.details || {}
        }
      };
    } else {
      // Handle error responses
      return {
        success: false,
        error: `Backend error: ${response.status}`,
        fallback: true,
        data: {
          url,
          isSafe: null,
          threatType: null,
          analysisPhase: "ERROR",
          details: {
            message: `Error from backend service: ${response.statusText}`
          }
        }
      };
    }
  } catch (error) {
    // Handle network errors or timeouts
    console.error("Error checking URL with backend:", error);
    
    // For timeouts, provide a specific message
    if (error.name === "AbortError") {
      return {
        success: false,
        error: "Request timed out",
        fallback: true,
        data: {
          url,
          isSafe: null,
          threatType: null,
          analysisPhase: "TIMEOUT",
          details: {
            message: "Backend service request timed out"
          }
        }
      };
    }
    
    // For other errors
    return {
      success: false,
      error: error.message,
      fallback: true,
      data: {
        url,
        isSafe: null,
        threatType: null,
        analysisPhase: "ERROR",
        details: {
          message: `Network or server error: ${error.message}`
        }
      }
    };
  }
}
