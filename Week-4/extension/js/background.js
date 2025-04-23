// Background service worker for Web Safety Scanner
const API_BASE_URL = "http://localhost:5000/api/v1";
const FALLBACK_API_URLS = [
  "http://localhost:5000/api/v1",
  "http://localhost:3000/api/v1", // Alternative local port
  "https://api.websafetyscanner.example.com/api/v1" // Example production URL
];

// Initialize extension settings
chrome.runtime.onInstalled.addListener(() => {
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
  });
  
  // Run an initial server availability check
  checkServerAvailability();
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
    
    return isAvailable;
  } catch (error) {
    console.error("Error checking server availability:", error);
    return false;
  }
}

// Listen for messages from content script or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkUrl") {
    analyzeUrl(message.url)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Required for async sendResponse
  }
  
  if (message.action === "checkServerAvailability") {
    checkServerAvailability()
      .then(isAvailable => sendResponse({ success: true, isAvailable }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Required for async sendResponse
  }
});

// URL Analyzer function - first step in the architecture
async function analyzeUrl(url) {
  try {
    console.log("URL Analyzer: Analyzing URL", url);
    
    // Step 1: Basic URL pattern checks (local analysis)
    const urlPattern = analyzeUrlPattern(url);
    if (!urlPattern.isSafe) {
      return {
        success: true,
        data: {
          url,
          isSafe: false,
          threatType: "SUSPICIOUS_URL_PATTERN",
          analysisPhase: "URL_ANALYZER",
          details: {
            reason: urlPattern.reason
          }
        }
      };
    }
    
    // Step 2: Check URL with backend services (Safe Browsing API + Phishing Engine)
    return await checkUrlWithBackend(url);
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

// Analyze URL pattern for obvious phishing attempts
function analyzeUrlPattern(url) {
  // Convert to lowercase for easier comparison
  const lowerUrl = url.toLowerCase();
  
  // Check for basic suspicious patterns
  const suspiciousTerms = [
    'login', 'signin', 'account', 'password', 'secure', 'update', 'verify',
    'wallet', 'banking', 'credit', 'authenticate', 'security'
  ];
  
  // Check for lookalike domains of popular services
  const lookalikes = {
    'google': ['g00gle', 'g0ogle', 'googie', 'gooogle'],
    'microsoft': ['micr0soft', 'rnicrosoft', 'microsofl'],
    'apple': ['appie', 'ap-ple', 'appl-e'],
    'amazon': ['arnazon', 'amaz0n', 'amazan'],
    'paypal': ['paypaI', 'paypa1', 'paypai']
  };
  
  // Check for IP address in URL instead of domain name
  const ipAddressRegex = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipAddressRegex.test(lowerUrl)) {
    return { 
      isSafe: false, 
      reason: 'IP address used instead of domain name'
    };
  }
  
  // Check for excessive subdomains
  const urlObj = new URL(url);
  const domainParts = urlObj.hostname.split('.');
  if (domainParts.length > 5) {
    return {
      isSafe: false,
      reason: 'Excessive subdomains'
    };
  }
  
  // Check for lookalike domains
  for (const [genuine, fakes] of Object.entries(lookalikes)) {
    if (fakes.some(fake => urlObj.hostname.includes(fake))) {
      return {
        isSafe: false,
        reason: `Potential lookalike domain of ${genuine}`
      };
    }
  }
  
  // Default return if no suspicious patterns found
  return { isSafe: true };
}

// Function to check URL safety via backend services
async function checkUrlWithBackend(url) {
  try {
    // Get current settings
    const settings = await chrome.storage.local.get([
      "apiUrl", 
      "lastServerStatus", 
      "offlineMode"
    ]);
    
    const apiUrl = settings.apiUrl || API_BASE_URL;
    
    console.log(`[Google Safe Browsing] Using API URL: ${apiUrl}`);
    
    // Check if we're in offline mode
    if (settings.offlineMode) {
      console.log("Operating in offline mode - skipping backend check");
      return { 
        success: true,
        fallback: true,
        data: {
          url,
          isSafe: null, 
          threatType: null,
          analysisPhase: "OFFLINE_MODE",
          details: {
            message: "Extension is in offline mode. Only local checks are applied."
          }
        }
      };
    }
    
    // Check if server is available before attempting connection
    // If we haven't checked or last check was more than 5 minutes ago
    const shouldCheckAvailability = !settings.lastServerStatus || 
      !settings.lastServerStatus.lastChecked || 
      (new Date() - new Date(settings.lastServerStatus.lastChecked)) > 5 * 60 * 1000;
      
    if (shouldCheckAvailability) {
      console.log("Checking server availability before proceeding");
      await checkServerAvailability();
      
      // Refresh settings after availability check (may have changed to fallback URL)
      const updatedSettings = await chrome.storage.local.get([
        "apiUrl", 
        "lastServerStatus"
      ]);
      
      // Use potentially updated URL
      if (updatedSettings.apiUrl) {
        console.log(`Using URL from availability check: ${updatedSettings.apiUrl}`);
      }
    }
    
    // Get the latest server status
    const latestSettings = await chrome.storage.local.get(["lastServerStatus"]);
    const serverStatus = latestSettings.lastServerStatus || { isAvailable: false };
    
    // If server is known to be unavailable, skip network requests entirely
    if (!serverStatus.isAvailable) {
      console.log("Server is known to be unavailable, skipping network requests");
      return { 
        success: true,
        fallback: true,
        data: {
          url,
          isSafe: null,
          threatType: null,
          analysisPhase: "SERVER_UNAVAILABLE",
          details: {
            message: "Security service is unavailable. Using local checks only."
          }
        }
      };
    }
    
    console.log("[Google Safe Browsing] Checking URL with backend services");
    
    // Add retry logic for network resilience
    const MAX_RETRIES = 2;
    let retries = 0;
    let lastError = null;
    
    while (retries <= MAX_RETRIES) {
      try {
        console.log(`[Google Safe Browsing] Making API request to ${apiUrl}/urls/check (attempt ${retries + 1}/${MAX_RETRIES + 1})`);
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000); // Extended timeout to 8 seconds
        
        const response = await fetch(`${apiUrl}/urls/check`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url }),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`API request failed: ${response.status} ${response.statusText}`);
        }
        
        const result = await response.json();
        console.log("[Google Safe Browsing] API response received:", result);
        
        // Enhanced response with phishing detection data
        if (result.success) {
          // Check if Google Safe Browsing detection is included
          if (result.data.details && result.data.details.safeBrowsing) {
            console.log(`[Google Safe Browsing] Result: ${result.data.details.safeBrowsing.isSafe ? 'Safe' : 'Unsafe'}`);
            if (!result.data.details.safeBrowsing.isSafe) {
              console.log(`[Google Safe Browsing] Threat type: ${result.data.details.safeBrowsing.threatType}`);
            }
          } else {
            console.warn("[Google Safe Browsing] No Safe Browsing data in response");
          }
          
          // Add phishing indicators to the threat description if detected
          if (result.data.details && 
              result.data.details.phishingAnalysis && 
              result.data.details.phishingAnalysis.isPhishing) {
            
            console.log(`Phishing detected`);
            
            // Add phishing analysis phase
            result.data.analysisPhase = "PHISHING_ENGINE";
            
            // If there are phishing indicators, add them to the details
            if (result.data.details.phishingAnalysis.indicators && 
                result.data.details.phishingAnalysis.indicators.length > 0) {
              // Gather top 3 phishing indicators for display
              const topIndicators = result.data.details.phishingAnalysis.indicators.slice(0, 3);
              result.data.details.threatIndicators = topIndicators;
            }
          } else {
            result.data.analysisPhase = "SAFE_BROWSING_API";
          }
        }
        
        return result;
        
      } catch (error) {
        lastError = error;
        console.error(`[Google Safe Browsing] API call error:`, error);
        
        // Only retry on network errors, not on API errors
        if (error.name === 'AbortError' || 
            error.message.includes('Failed to fetch') || 
            error.message.includes('NetworkError') ||
            error.message.includes('network') ||
            error.message.includes('timeout')) {
          
          retries++;
          
          if (retries <= MAX_RETRIES) {
            console.log(`[Google Safe Browsing] Network error, retrying (${retries}/${MAX_RETRIES})...`);
            // Wait before retry (exponential backoff)
            await new Promise(r => setTimeout(r, 1000 * retries));
            continue;
          }
        } else {
          // Don't retry non-network errors
          break;
        }
      }
    }
    
    // If we got here, all retries failed
    console.error("[Google Safe Browsing] Error checking URL with backend after retries:", lastError);
    
    // Create a user-friendly error message based on error type
    let errorMessage = "Unknown error occurred";
    if (lastError) {
      if (lastError.name === 'AbortError') {
        errorMessage = "Connection timed out";
      } else if (lastError.message.includes('Failed to fetch') || 
                lastError.message.includes('NetworkError')) {
        errorMessage = "Failed to connect to security service";
      } else {
        errorMessage = lastError.message;
      }
    }
    
    throw new Error(errorMessage);
    
  } catch (error) {
    console.error("[Google Safe Browsing] Error checking URL with backend:", error);
    
    // Return graceful error with notification that we're falling back to local checks
    return { 
      success: false, 
      error: error.message || "Failed to connect to security service",
      fallback: true,
      data: {
        url,
        isSafe: null, // Use null to indicate we couldn't determine safety
        threatType: null,
        analysisPhase: "CONNECTION_ERROR",
        details: {
          message: "Using local checks only. Security service is unavailable."
        }
      }
    };
  }
}
