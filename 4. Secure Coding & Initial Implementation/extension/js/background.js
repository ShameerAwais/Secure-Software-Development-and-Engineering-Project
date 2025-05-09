/**
 * Background Script
 * 
 * This script runs in the extension's background and coordinates the
 * phishing detection system:
 * 1. Receives data from content scripts monitoring web pages
 * 2. Communicates with the backend API for NLP analysis
 * 3. Makes final phishing determinations combining all signals
 * 4. Manages user notifications and protection responses
 */

// Configuration
const API_CONFIG = {
  baseUrl: 'http://localhost:5001/api/v1',
  endpoints: {
    analyzeContent: '/urls/user-check',
    checkUrl: '/urls/check',
    reportPhishing: '/urls/user-action',
    login: '/auth/login',
    register: '/auth/register',
    logout: '/auth/logout',
    profile: '/auth/profile',
    lists: '/auth/lists'
  },
  headers: {
    'Content-Type': 'application/json'
  }
};

// Track analysis results across tabs
const tabAnalysisData = {};
const phishingAlerts = {};
const safeUrls = new Set();
const suspiciousUrls = new Set();
const confirmedPhishingUrls = new Set();

// Initialize extension
chrome.runtime.onInstalled.addListener(initializeExtension);
setupListeners();

/**
 * Initialize the extension
 */
function initializeExtension() {
  console.log('[PhishGuard] Extension initialized');
  
  // Reset extension state
  resetExtensionState();
  
  // Set default badge color
  chrome.action.setBadgeBackgroundColor({ color: '#5D87E8' });
}

/**
 * Set up all message and event listeners
 */
function setupListeners() {
  // Listen for messages from content scripts
  chrome.runtime.onMessage.addListener(handleMessages);
  
  // Listen for tab updates to reset data and start scans
  chrome.tabs.onUpdated.addListener(handleTabUpdated);
  
  // Listen for tab removal to clean up data
  chrome.tabs.onRemoved.addListener(handleTabRemoved);
}

/**
 * Handle messages from content scripts
 * @param {Object} message - Message data
 * @param {Object} sender - Message sender
 * @param {Function} sendResponse - Response function
 * @returns {boolean} Whether response will be async
 */
function handleMessages(message, sender, sendResponse) {
  // Handle messages from popup and content scripts
  if (message.action === 'getAuthStatus') {
    // Get auth state from storage
    chrome.storage.local.get(['isAuthenticated', 'user'], (result) => {
      sendResponse({
        success: true,
        isAuthenticated: result.isAuthenticated || false,
        user: result.user || null
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'login') {
    // Make login request to backend
    fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.login, {
      method: 'POST',
      headers: API_CONFIG.headers,
      body: JSON.stringify(message.credentials),
      credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Save auth state to storage
        chrome.storage.local.set({
          isAuthenticated: true,
          user: data.user,
          token: data.token,
          refreshToken: data.refreshToken,
          tokenExpiry: data.tokenExpiry
        });
      }
      sendResponse(data);
    })
    .catch(error => {
      console.error('Login error:', error);
      sendResponse({
        success: false,
        message: 'Error connecting to authentication service'
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'register') {
    // Make register request to backend
    fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.register, {
      method: 'POST',
      headers: API_CONFIG.headers,
      body: JSON.stringify(message.userData),
      credentials: 'include'
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      if (data.success) {
        // Save auth state to storage
        chrome.storage.local.set({
          isAuthenticated: true,
          user: data.user,
          token: data.token,
          refreshToken: data.refreshToken,
          tokenExpiry: data.tokenExpiry
        });
      }
      sendResponse(data);
    })
    .catch(error => {
      console.error('Registration error:', error);
      sendResponse({
        success: false,
        message: `Error creating account: ${error.message}`
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'refreshProfile') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const url = API_CONFIG.baseUrl + API_CONFIG.endpoints.profile;
      console.log('Fetching profile from:', url);
      
      // Make profile request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Update stored user data
          chrome.storage.local.set({
            user: data.user
          });
          sendResponse({
            success: true,
            user: data.user
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to refresh profile'
          });
        }
      })
      .catch(error => {
        console.error('Profile refresh error:', error);
        sendResponse({
          success: false,
          message: `Error refreshing profile data: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'getProfile') {
    // Get stored token
    chrome.storage.local.get(['token', 'user'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      // First check if we have a cached user profile and it's recent
      if (result.user && result.user.lastFetched && 
          (Date.now() - result.user.lastFetched < 300000)) { // 5 minutes cache
        console.log('Using cached profile data');
        sendResponse({
          success: true,
          user: result.user
        });
        return;
      }

      const url = API_CONFIG.baseUrl + API_CONFIG.endpoints.profile;
      console.log('Fetching fresh profile from:', url);
      
      // Make profile request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Add timestamp to user data
          const userData = {
            ...data.user,
            lastFetched: Date.now()
          };
          
          // Update stored user data
          chrome.storage.local.set({
            user: userData
          });
          
          sendResponse({
            success: true,
            user: userData
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to get profile data'
          });
        }
      })
      .catch(error => {
        console.error('Profile fetch error:', error);
        
        // If we have cached data, return it as fallback
        if (result.user) {
          sendResponse({
            success: true,
            user: result.user,
            message: 'Using cached profile data (fetch failed)'
          });
        } else {
          sendResponse({
            success: false,
            message: `Error getting profile data: ${error.message}`
          });
        }
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'getLists') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const url = API_CONFIG.baseUrl + API_CONFIG.endpoints.lists;
      console.log('Fetching lists from:', url);
      
      // Make lists request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Store lists data
          chrome.storage.local.set({
            allowList: data.allowList || [],
            blockList: data.blockList || []
          });
          sendResponse({
            success: true,
            allowList: data.allowList || [],
            blockList: data.blockList || []
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to load lists'
          });
        }
      })
      .catch(error => {
        console.error('Lists loading error:', error);
        sendResponse({
          success: false,
          message: `Error loading lists: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'updateLists') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const url = `${API_CONFIG.baseUrl}/lists/${message.listType}`;
      console.log(`${message.listAction} to ${message.listType}:`, url, message.url);
      
      // Determine HTTP method based on action
      const method = message.listAction === 'add' ? 'POST' : 'DELETE';
      
      // Make request to backend
      fetch(url, {
        method: method,
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        body: JSON.stringify({ url: message.url }),
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Update stored lists
          chrome.storage.local.get([message.listType], (listResult) => {
            const currentList = listResult[message.listType] || [];
            let updatedList = [...currentList];
            
            if (message.listAction === 'add' && !currentList.includes(message.url)) {
              updatedList.push(message.url);
            } else if (message.listAction === 'remove') {
              updatedList = currentList.filter(item => item !== message.url);
            }
            
            const updateObj = {};
            updateObj[message.listType] = updatedList;
            chrome.storage.local.set(updateObj);
          });
          
          sendResponse({
            success: true,
            message: `${message.url} ${message.listAction === 'add' ? 'added to' : 'removed from'} ${message.listType}`
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || `Failed to ${message.listAction} to ${message.listType}`
          });
        }
      })
      .catch(error => {
        console.error(`Error updating ${message.listType}:`, error);
        sendResponse({
          success: false,
          message: `Error updating ${message.listType}: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'logout') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      const token = result.token;
      
      // Clear auth state first (even if API call fails)
      chrome.storage.local.remove(['isAuthenticated', 'user', 'token', 'refreshToken', 'tokenExpiry', 'allowList', 'blockList'], () => {
        console.log('Cleared auth state from storage');
      });
      
      // If we have a token, try to properly logout on server
      if (token) {
        fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.logout, {
          method: 'POST',
          headers: {
            ...API_CONFIG.headers,
            'Authorization': `Bearer ${token}`
          },
          credentials: 'include'
        })
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
          }
          return response.json();
        })
        .then(data => {
          sendResponse({
            success: true,
            message: 'Logged out successfully'
          });
        })
        .catch(error => {
          console.error('Logout API error:', error);
          // Still consider logout successful even if API call fails
          sendResponse({
            success: true,
            message: 'Logged out locally'
          });
        });
      } else {
        // No token means we're not logged in anyway
        sendResponse({
          success: true,
          message: 'Not logged in'
        });
      }
    });
    return true; // Indicate async response
  }

  if (message.action === 'checkServerAvailability') {
    // Check if server is available by making a request to the health endpoint
    // Add cache-busting query parameter to prevent 304 responses
    const timestamp = new Date().getTime();
    fetch(`http://localhost:5001/health?_=${timestamp}`)
      .then(response => {
        if (response.ok) {
          sendResponse({
            success: true,
            isAvailable: true
          });
        } else {
          sendResponse({
            success: true,
            isAvailable: false
          });
        }
      })
      .catch(error => {
        console.error('Server availability check failed:', error);
        sendResponse({
          success: true,
          isAvailable: false
        });
      });
    return true; // Indicate async response
  }

  if (message.action === 'checkUrl') {
    const url = message.url;
    try {
      // Parse the URL to get the domain
      const parsedUrl = new URL(url);
      const domain = parsedUrl.hostname;
      
      console.log('Checking URL:', url, 'Domain:', domain);
      
      // First check if it's in our known lists
      if (confirmedPhishingUrls.has(url) || confirmedPhishingUrls.has(domain)) {
        sendResponse({
          success: true,
          data: {
            isSafe: false,
            threatType: 'Known phishing site',
            details: {
              threatIndicators: ['URL matches known phishing pattern']
            }
          }
        });
        return true;
      }
      
      if (safeUrls.has(url) || safeUrls.has(domain)) {
        sendResponse({
          success: true,
          data: {
            isSafe: true,
            threatType: null,
            details: {}
          }
        });
        return true;
      }
      
      // Perform basic client-side checks
      const basicCheckResult = performBasicUrlCheck(url, domain);
      
      // Check authentication for full scan
      chrome.storage.local.get(['isAuthenticated', 'token'], (result) => {
        if (!result.isAuthenticated || !result.token) {
          // Not authenticated, return limited scan
          sendResponse({
            success: true,
            requiresAuth: true,
            fallback: false,
            data: {
              isSafe: basicCheckResult.isSafe,
              threatType: basicCheckResult.isSafe ? null : 'Suspicious URL pattern',
              details: {
                threatIndicators: basicCheckResult.indicators
              }
            }
          });
          return;
        }
        
        // Check if server is available then proceed with API check
        checkServerAndMakeApiRequest();
        
        // Function to handle server check and API request flow
        function checkServerAndMakeApiRequest() {
          const timestamp = new Date().getTime();
          
          // Step 1: Check server availability
          fetch(`http://localhost:5001/health?_=${timestamp}`)
            .then(response => {
              if (!response.ok) {
                throw new Error('Health check failed');
              }
              return true;
            })
            .then(serverAvailable => {
              // Step 2: Make API request since server is available
              return fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.checkUrl, {
                method: 'POST',
                headers: {
                  ...API_CONFIG.headers,
                  'Authorization': `Bearer ${result.token}`
                },
                body: JSON.stringify({
                  url: url,
                  domain: domain
                }),
                credentials: 'include'
              });
            })
            .then(response => {
              // Step 3: Handle API response
              if (response.status === 404) {
                throw new Error('API endpoint not found');
              }
              if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
              }
              return response.json();
            })
            .then(data => {
              // Step 4: Process API data
              if (data.success) {
                // Check for Safe Browsing data
                const safeBrowsingResult = data.data?.details?.safeBrowsing;
                const isSafeBrowsingSource = data.data?.details?.source === "Google Safe Browsing API";
                
                // If Google Safe Browsing detected a threat, it's authoritative
                if ((safeBrowsingResult && !safeBrowsingResult.isSafe) || 
                    (isSafeBrowsingSource && !data.data.isSafe)) {
                  console.log('Google Safe Browsing detected unsafe URL');
                  
                  // Save to confirmed phishing URLs
                  confirmedPhishingUrls.add(url);
                  confirmedPhishingUrls.add(domain);
                }
                
                // Build response
                sendResponse({
                  success: true,
                  data: data.data || {
                    isSafe: data.isSafe,
                    threatType: data.isSafe ? null : data.threatType,
                    details: data.details || {}
                  }
                });
                
                // Save results to our caches
                if (data.data?.isSafe) {
                  safeUrls.add(url);
                  safeUrls.add(domain);
                } else if (data.data?.isPhishing || !data.data?.isSafe) {
                  confirmedPhishingUrls.add(url);
                  confirmedPhishingUrls.add(domain);
                }
              } else {
                // API responded but indicated an error
                sendResponse({
                  success: false,
                  error: data.message || 'Server returned an error',
                  fallback: true,
                  data: {
                    isSafe: basicCheckResult.isSafe,
                    threatType: basicCheckResult.isSafe ? null : 'Suspicious URL pattern',
                    details: {
                      threatIndicators: basicCheckResult.indicators
                    }
                  }
                });
              }
            })
            .catch(error => {
              // Handle any errors in the promise chain
              console.error('URL check error:', error);
              
              // Use fallback data for response
              sendResponse({
                success: true, // Using fallback, so consider it "successful" but with fallback data
                error: `Error checking URL: ${error.message}`,
                fallback: true,
                data: {
                  isSafe: basicCheckResult.isSafe,
                  threatType: basicCheckResult.isSafe ? null : 'Suspicious URL pattern',
                  details: {
                    threatIndicators: basicCheckResult.indicators
                  }
                }
              });
            });
        }
      });
      
      return true; // Indicate async response
    } catch (error) {
      // Error parsing URL
      console.error('URL parsing error:', error);
      sendResponse({
        success: false,
        error: `Invalid URL: ${error.message}`,
        data: { isSafe: null }
      });
      return true;
    }
  }

  if (message.action === 'getUserStats') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const timeRange = message.timeRange || 'month';
      const url = `${API_CONFIG.baseUrl}/urls/user-stats?range=${timeRange}`;
      console.log('Fetching user stats from:', url);
      
      // Make stats request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          sendResponse({
            success: true,
            stats: data.data || {}
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to fetch statistics'
          });
        }
      })
      .catch(error => {
        console.error('Stats fetch error:', error);
        sendResponse({
          success: false,
          message: `Error fetching statistics: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'getUserHistory') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const page = message.page || 1;
      const limit = message.limit || 10;
      const timeRange = message.timeRange || 'month';
      const url = `${API_CONFIG.baseUrl}/urls/user-history?page=${page}&limit=${limit}&range=${timeRange}`;
      console.log('Fetching user history from:', url);
      
      // Make history request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          sendResponse({
            success: true,
            history: data.data || [],
            pagination: data.pagination || {
              page: 1,
              pages: 1,
              total: 0
            }
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to fetch history'
          });
        }
      })
      .catch(error => {
        console.error('History fetch error:', error);
        sendResponse({
          success: false,
          message: `Error fetching history: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  // Only process messages from content scripts with tab IDs
  if (!sender.tab || !sender.tab.id) return false;
  
  const tabId = sender.tab.id;
  
  switch (message.action) {
    case 'analyzePageContent':
      handleAnalyzePageContent(tabId, message.data, sendResponse);
      return true; // Indicate async response
      
    case 'reportBehaviorAnalysis':
      handleBehaviorAnalysis(tabId, message.data);
      break;
      
    case 'reportUserInteractionAnalysis':
      handleUserInteractionAnalysis(tabId, message.data);
      break;
      
    case 'reportCombinedAnalysis':
      handleCombinedAnalysis(tabId, message.data);
      break;
      
    case 'reportAnalysisUpdate':
      handleAnalysisUpdate(tabId, message.data);
      break;
  }
  
  return false;
}

/**
 * Handle tab updated event to reset data and start analysis
 * @param {number} tabId - Tab ID
 * @param {Object} changeInfo - Change info
 * @param {Object} tab - Tab data
 */
function handleTabUpdated(tabId, changeInfo, tab) {
  // Only react to URL changes and complete loads
  if (!changeInfo.url && changeInfo.status !== 'complete') return;
  
  // Skip extension pages and empty pages
  if (!tab.url || tab.url.startsWith('chrome://') || tab.url === 'about:blank') {
    return;
  }

  // Reset previous analysis for this tab
  if (changeInfo.url) {
    resetTabAnalysis(tabId);
    
    // Check if URL is already known
    const url = new URL(tab.url);
    checkKnownUrl(tabId, url.href, url.hostname);
  }
  
  // Update badge for fresh page load
  if (changeInfo.status === 'complete') {
    updateBadgeForTab(tabId, 'scanning');
  }
}

/**
 * Check if URL is already known as safe or suspicious
 * @param {number} tabId - Tab ID
 * @param {string} url - Full URL
 * @param {string} domain - Domain name
 */
function checkKnownUrl(tabId, url, domain) {
  // Check if already confirmed as phishing
  if (confirmedPhishingUrls.has(url) || confirmedPhishingUrls.has(domain)) {
    updateBadgeForTab(tabId, 'danger');
    showPhishingWarning(tabId, {
      url: url,
      domain: domain,
      reason: 'Previously confirmed phishing site'
    });
    return;
  }
  
  // Check if previously flagged as suspicious
  if (suspiciousUrls.has(url) || suspiciousUrls.has(domain)) {
    updateBadgeForTab(tabId, 'warning');
    return;
  }
  
  // Check if already confirmed as safe
  if (safeUrls.has(url) || safeUrls.has(domain)) {
    updateBadgeForTab(tabId, 'safe');
    return;
  }
  
  // Otherwise request API check
  checkUrlWithApi(tabId, url, domain);
}

/**
 * Check URL with backend API
 * @param {number} tabId - Tab ID
 * @param {string} url - Full URL
 * @param {string} domain - Domain name
 */
function checkUrlWithApi(tabId, url, domain) {
  // Make API request to check URL
  fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.checkUrl, {
    method: 'POST',
    headers: API_CONFIG.headers,
    body: JSON.stringify({
      url: url,
      domain: domain
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.isPhishing) {
      // Add to confirmed phishing list
      confirmedPhishingUrls.add(url);
      confirmedPhishingUrls.add(domain);
      
      // Update UI
      updateBadgeForTab(tabId, 'danger');
      showPhishingWarning(tabId, {
        url: url,
        domain: domain,
        reason: data.reason || 'URL matches known phishing patterns'
      });
    }
    else if (data.isSafe) {
      // Add to safe URLs
      safeUrls.add(url);
      safeUrls.add(domain);
      updateBadgeForTab(tabId, 'safe');
    }
    // Otherwise wait for content analysis results
  })
  .catch(error => {
    console.error('[PhishGuard] URL check API error:', error);
  });
}

/**
 * Handle content analysis request
 * @param {number} tabId - Tab ID
 * @param {Object} contentData - Page content data
 * @param {Function} sendResponse - Response function
 */
function handleAnalyzePageContent(tabId, contentData, sendResponse) {
  // Store content data
  if (!tabAnalysisData[tabId]) {
    tabAnalysisData[tabId] = {};
  }
  
  tabAnalysisData[tabId].contentData = contentData;
  
  // Make API request to analyze content
  fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.analyzeContent, {
    method: 'POST',
    headers: API_CONFIG.headers,
    body: JSON.stringify({
      url: contentData.url,
      domain: contentData.domain,
      title: contentData.title,
      description: contentData.metaDescription,
      textSample: contentData.textSample,
      hasLoginForm: contentData.hasLoginForm,
      forms: contentData.forms.map(form => ({
        action: form.action,
        method: form.method,
        isLoginForm: form.isLoginForm,
        isExternalAction: form.isExternalAction,
        inputCount: form.inputs ? form.inputs.length : 0,
        hasPasswordField: form.inputs ? form.inputs.some(input => input.type === 'password') : false
      }))
    })
  })
  .then(response => response.json())
  .then(data => {
    // Store NLP results
    tabAnalysisData[tabId].nlpResults = data;
    
    // Send results back to content script
    sendResponse({ nlpResults: data });
    
    // Also send to active tab in case response wasn't delivered
    chrome.tabs.sendMessage(tabId, {
      action: 'nlpResultsReady',
      data: data
    }).catch(err => {
      // Tab might be navigating or closed, ignore error
    });
  })
  .catch(error => {
    console.error('[PhishGuard] Content analysis API error:', error);
    sendResponse({ error: 'API request failed' });
  });
}

/**
 * Handle behavior analysis results
 * @param {number} tabId - Tab ID
 * @param {Object} data - Behavior analysis data
 */
function handleBehaviorAnalysis(tabId, data) {
  // Initialize tab data if needed
  if (!tabAnalysisData[tabId]) {
    tabAnalysisData[tabId] = {};
  }
  
  // Store behavior results
  tabAnalysisData[tabId].behaviorResults = data;
  
  // Check if this is high risk
  if (data.behaviorScore >= 70) {
    // Update badge immediately for high-risk behavior
    updateBadgeForTab(tabId, 'danger');
    
    // Get tab info to determine if warning needed
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError) return; // Tab closed
      
      // Show phishing warning if not already shown
      if (!phishingAlerts[tabId]) {
        showPhishingWarning(tabId, {
          url: tab.url,
          domain: new URL(tab.url).hostname,
          reason: 'Suspicious JavaScript behavior detected',
          details: data.detectedPatterns.map(p => p.details).flat().slice(0, 3),
          score: data.behaviorScore
        });
      }
    });
  }
  // Moderate risk - update badge only
  else if (data.behaviorScore >= 40) {
    updateBadgeForTab(tabId, 'warning');
  }
}

/**
 * Handle user interaction analysis results
 * @param {number} tabId - Tab ID
 * @param {Object} data - User interaction analysis data
 */
function handleUserInteractionAnalysis(tabId, data) {
  // Initialize tab data if needed
  if (!tabAnalysisData[tabId]) {
    tabAnalysisData[tabId] = {};
  }
  
  // Store interaction results
  tabAnalysisData[tabId].interactionResults = data;
  
  // Check if this is high risk
  if (data.interactionScore >= 70 && data.isLikelyPhishing) {
    // Update badge for high-risk user interaction patterns
    updateBadgeForTab(tabId, 'danger');
    
    // Get tab info to determine if warning needed
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError) return; // Tab closed
      
      // Show phishing warning if not already shown
      if (!phishingAlerts[tabId]) {
        showPhishingWarning(tabId, {
          url: tab.url,
          domain: new URL(tab.url).hostname,
          reason: 'Suspicious user interface/interaction patterns',
          details: data.details.slice(0, 3),
          score: data.interactionScore
        });
      }
    });
  }
  // Moderate risk - update badge only
  else if (data.interactionScore >= 50) {
    updateBadgeForTab(tabId, 'warning');
  }
}

/**
 * Handle combined analysis results
 * @param {number} tabId - Tab ID
 * @param {Object} data - Combined analysis data
 */
function handleCombinedAnalysis(tabId, data) {
  // Update full analysis data
  tabAnalysisData[tabId] = {
    ...tabAnalysisData[tabId],
    combinedResults: data,
    lastAnalysisTime: Date.now()
  };
  
  // Update badge based on combined risk
  if (data.isLikelyPhishing) {
    updateBadgeForTab(tabId, 'danger');
    
    // Add to suspicious URLs list
    suspiciousUrls.add(data.url);
    suspiciousUrls.add(data.domain);
    
    // Show warning if it's clearly phishing
    if (data.combinedScore >= 80 && !phishingAlerts[tabId]) {
      showPhishingWarning(tabId, {
        url: data.url,
        domain: data.domain,
        reason: 'Multiple phishing indicators detected',
        score: data.combinedScore
      });
      
      // Report to API if high confidence
      if (data.combinedScore >= 90) {
        reportPhishingToApi(data);
      }
    }
  } 
  else if (data.combinedScore >= 40) {
    updateBadgeForTab(tabId, 'warning');
    suspiciousUrls.add(data.url);
  }
  else {
    updateBadgeForTab(tabId, 'safe');
    safeUrls.add(data.url);
    safeUrls.add(data.domain);
  }
}

/**
 * Handle analysis update
 * @param {number} tabId - Tab ID
 * @param {Object} data - Analysis update data
 */
function handleAnalysisUpdate(tabId, data) {
  // Skip if we don't have previous data
  if (!tabAnalysisData[tabId] || !tabAnalysisData[tabId].combinedResults) return;
  
  // Get previous combined results
  const previous = tabAnalysisData[tabId].combinedResults;
  
  // Check if risk level increased significantly
  const behaviorIncrease = data.behavior.behaviorScore - 
                          (previous.behavior ? previous.behavior.behaviorScore : 0);
  
  const interactionIncrease = data.interaction.interactionScore -
                             (previous.interaction ? previous.interaction.interactionScore : 0);
  
  // If significant risk increase, update badge and potentially warn
  if (behaviorIncrease > 20 || interactionIncrease > 20) {
    // Recalculate combined score
    const nlpWeight = previous.nlp ? 0.4 : 0;
    const behaviorWeight = 0.35;
    const interactionWeight = 0.25;
    
    const newScore = Math.round(
      (previous.nlp ? (previous.nlp.nlpScore * nlpWeight) : 0) +
      (data.behavior.behaviorScore * behaviorWeight) +
      (data.interaction.interactionScore * interactionWeight)
    );
    
    // Update stored data
    tabAnalysisData[tabId].combinedResults.combinedScore = newScore;
    tabAnalysisData[tabId].combinedResults.isLikelyPhishing = newScore >= 70;
    tabAnalysisData[tabId].combinedResults.behavior = data.behavior;
    tabAnalysisData[tabId].combinedResults.interaction = data.interaction;
    
    // Update UI based on new score
    if (newScore >= 70) {
      updateBadgeForTab(tabId, 'danger');
      
      // Show warning if significant change and not already warned
      if (!phishingAlerts[tabId] && (behaviorIncrease > 30 || interactionIncrease > 30)) {
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError) return; // Tab closed
          
          showPhishingWarning(tabId, {
            url: tab.url,
            domain: new URL(tab.url).hostname,
            reason: 'Phishing behavior detected after page interaction',
            score: newScore
          });
        });
      }
    }
    else if (newScore >= 40) {
      updateBadgeForTab(tabId, 'warning');
    }
  }
}

/**
 * Update badge for tab
 * @param {number} tabId - Tab ID
 * @param {string} status - Status ('safe', 'warning', 'danger', 'scanning')
 */
function updateBadgeForTab(tabId, status) {
  let text = '';
  let color = '#5D87E8';
  
  switch (status) {
    case 'safe':
      text = '✓';
      color = '#4CAF50';
      break;
    case 'warning':
      text = '!';
      color = '#FF9800';
      break;
    case 'danger':
      text = '!!';
      color = '#F44336';
      break;
    case 'scanning':
      text = '...';
      color = '#5D87E8';
      break;
  }
  
  chrome.action.setBadgeText({ text: text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
}

/**
 * Show phishing warning
 * @param {number} tabId - Tab ID
 * @param {Object} data - Warning data
 */
function showPhishingWarning(tabId, data) {
  try {
    // Record that we've shown an alert for this tab
    phishingAlerts[tabId] = true;
    
    // Check if notifications API is available
    if (chrome.notifications && typeof chrome.notifications.create === 'function') {
      // Create notification
      chrome.notifications.create(`phishing-alert-${tabId}`, {
        type: 'basic',
        iconUrl: '../images/icon128.jpg',
        title: 'Phishing Warning!',
        message: `Suspicious site detected: ${data.domain}\nReason: ${data.reason}`,
        priority: 2,
        buttons: [
          { title: 'Close Tab' },
          { title: 'Ignore' }
        ]
      }, notificationId => {
        // Handle potential error in notification creation
        if (chrome.runtime.lastError) {
          console.warn('Notification creation error:', chrome.runtime.lastError);
        }
      });
      
      // Handle notification button clicks
      chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
        if (notificationId === `phishing-alert-${tabId}`) {
          if (buttonIndex === 0) {
            // Close the tab
            chrome.tabs.remove(tabId);
          } else {
            // Ignore - dismiss notification
            chrome.notifications.clear(notificationId);
          }
        }
      });
    } else {
      // Notification API not available, fallback to console warning
      console.warn('Notifications API not available. Phishing site detected:', data.domain);
      
      // Update badge as a visual indicator
      updateBadgeForTab(tabId, 'danger');
    }
    
    // Update popup with alert info (do this regardless of notification availability)
    if (tabAnalysisData[tabId]) {
      tabAnalysisData[tabId].alert = {
        timestamp: Date.now(),
        url: data.url,
        domain: data.domain,
        reason: data.reason,
        details: data.details || [],
        score: data.score || 0
      };
    }
  } catch (error) {
    // Catch any other errors to prevent the extension from crashing
    console.error('Error showing phishing warning:', error);
  }
}

/**
 * Report phishing site to API
 * @param {Object} data - Phishing data
 */
function reportPhishingToApi(data) {
  fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.reportPhishing, {
    method: 'POST',
    headers: API_CONFIG.headers,
    body: JSON.stringify({
      url: data.url,
      domain: data.domain,
      score: data.combinedScore,
      nlpScore: data.nlp.nlpScore,
      behaviorScore: data.behavior.behaviorScore,
      interactionScore: data.interaction.interactionScore,
      indicators: [
        ...(data.nlp.indicators || []),
        ...(data.behavior.detectedPatterns || []).map(p => p.type + ': ' + p.details.join(', ')),
        ...(data.interaction.details || [])
      ],
      timestamp: Date.now()
    })
  })
  .then(response => response.json())
  .then(result => {
    console.log('[PhishGuard] Phishing report submitted:', result);
    
    // If confirmed, add to confirmed list
    if (result.confirmed) {
      confirmedPhishingUrls.add(data.url);
      confirmedPhishingUrls.add(data.domain);
    }
  })
  .catch(error => {
    console.error('[PhishGuard] Error reporting phishing:', error);
  });
}

/**
 * Handle tab removed
 * @param {number} tabId - Tab ID
 */
function handleTabRemoved(tabId) {
  // Clean up data for this tab
  delete tabAnalysisData[tabId];
  delete phishingAlerts[tabId];
}

/**
 * Reset tab analysis data
 * @param {number} tabId - Tab ID
 */
function resetTabAnalysis(tabId) {
  tabAnalysisData[tabId] = {};
  phishingAlerts[tabId] = false;
}

/**
 * Reset extension state
 */
function resetExtensionState() {
  // Clear all stored data
  Object.keys(tabAnalysisData).forEach(key => delete tabAnalysisData[key]);
  Object.keys(phishingAlerts).forEach(key => delete phishingAlerts[key]);
  
  // Maintain small cache of known URLs
  if (confirmedPhishingUrls.size > 1000) {
    confirmedPhishingUrls.clear();
  }
  if (suspiciousUrls.size > 1000) {
    suspiciousUrls.clear();
  }
  if (safeUrls.size > 5000) {
    safeUrls.clear();
  }
}

/**
 * Perform basic client-side URL check
 * @param {string} url - Full URL
 * @param {string} domain - Domain name
 * @returns {Object} Check result
 */
function performBasicUrlCheck(url, domain) {
  const indicators = [];
  let isSafe = true;
  
  // Check for IP address instead of domain
  if (/^https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
    indicators.push('IP address used instead of domain name');
    isSafe = false;
  }
  
  // Check for suspicious TLDs
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz'];
  if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
    indicators.push('Domain uses suspicious TLD');
    isSafe = false;
  }
  
  // Check for too many subdomains
  const subdomainCount = domain.split('.').length - 1;
  if (subdomainCount > 3) {
    indicators.push('Excessive number of subdomains');
    isSafe = false;
  }
  
  // Check for unusual port
  const urlObj = new URL(url);
  if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
    indicators.push('Unusual port number in URL');
    isSafe = false;
  }
  
  // Check for encoded characters
  if (/%[0-9a-f]{2}/i.test(url)) {
    indicators.push('URL contains encoded characters');
    isSafe = false;
  }
  
  // Enhanced brand impersonation check - more comprehensive list of brands
  const commonBrands = [
    'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix', 
    'instagram', 'xfinity', 'comcast', 'chase', 'bankofamerica', 'wellsfargo', 
    'linkedin', 'twitter', 'gmail', 'outlook', 'yahoo', 'dropbox', 'icloud', 
    'hotmail', 'office365', 'citibank', 'capitalone', 'amex', 'americanexpress',
    'discord', 'spotify', 'walmart', 'target', 'usps', 'fedex', 'ups', 'dhl'
  ];

  // Check for brand name in subdomain (more aggressive pattern matching)
  const domainParts = domain.split('.');
  const isSubdomain = domainParts.length > 2;
  const rootDomain = domainParts.slice(-2).join('.');
  const subdomains = domainParts.slice(0, -2).join('.');
  
  // Check for brand impersonation in subdomain
  if (isSubdomain && commonBrands.some(brand => 
    subdomains.toLowerCase().includes(brand.toLowerCase()))) {
    indicators.push('Subdomain contains major brand name (likely impersonation)');
    isSafe = false;
  }
  
  // Check for brand name but not as the main domain (original check)
  if (commonBrands.some(brand => {
    return domain.toLowerCase().includes(brand.toLowerCase()) && 
          !domain.toLowerCase().endsWith(`.${brand.toLowerCase()}.com`);
  })) {
    indicators.push('Domain contains common brand name (potential spoofing)');
    isSafe = false;
  }
  
  // Check for suspicious numeric patterns in subdomains (common in phishing)
  if (/[a-z]+\d{4,}/.test(subdomains)) {
    indicators.push('Subdomain contains suspicious numeric sequence');
    isSafe = false;
  }
  
  // Check for free hosting services (common for phishing sites)
  const freeHostingServices = [
    'weebly.com', 'wix.com', 'blogspot.com', 'wordpress.com', 'site123.com',
    'webnode.com', 'glitch.me', 'netlify.app', 'pages.dev', 'github.io',
    'vercel.app', 'herokuapp.com', 'repl.co', '000webhostapp.com', 'webs.com',
    'yolasite.com', 'strikingly.com', 'carrd.co', 'squarespace.com'
  ];
  
  if (freeHostingServices.some(service => domain.toLowerCase().endsWith(service))) {
    // If it's a free hosting service AND contains a brand name, it's very suspicious
    if (commonBrands.some(brand => domain.toLowerCase().includes(brand.toLowerCase()))) {
      indicators.push('Brand impersonation on free hosting platform (high risk)');
      isSafe = false;
    } else {
      indicators.push('Site hosted on free website platform');
      // Make it suspicious but not definitively unsafe
      if (isSafe === true) isSafe = null;
    }
  }
  
  // Default to neutral if no indicators but no positive signals
  if (indicators.length === 0) {
    isSafe = null; // Neutral assessment
  }
  
  return {
    isSafe,
    indicators
  };
}
