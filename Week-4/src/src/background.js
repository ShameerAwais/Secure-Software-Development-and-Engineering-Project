import { checkPhishingURL } from './urlChecker.js';
import { secureApi } from './secureApi.js';
import { mlEngine } from './mlEngine.js';

// Initialize client ID for this extension instance
const clientId = self.crypto.randomUUID();
let sessionToken = null;

// Settings state
let settings = {
    userConsent: false,
    enableML: true,
    enableRealtime: true,
    enableNotifications: true
};

// Initialize secure session
async function initializeSecureSession() {
    try {
        // Get authentication token
        const authToken = await secureApi.generateToken(clientId);
        
        // Create session
        sessionToken = secureApi.createSession(clientId);
        
        // Initialize ML engine if enabled
        if (settings.enableML) {
            await mlEngine.initialize();
        }
    } catch (error) {
        console.error('Failed to initialize secure session:', error);
    }
}

// Load settings
chrome.storage.sync.get([
    'userConsent',
    'enableML',
    'enableRealtime',
    'enableNotifications'
], async (savedSettings) => {
    settings = {
        ...settings,
        ...savedSettings
    };
    await initializeSecureSession();
});

// Add a whitelist of trusted URLs
const trustedWhitelist = [
    "https://www.google.com",
    "https://www.github.com",
    "https://www.microsoft.com"
];

function isWhitelisted(url) {
    return trustedWhitelist.some(trustedUrl => url.startsWith(trustedUrl));
}

// Event listener to handle web navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
    // Skip if realtime protection is disabled or no user consent
    if (!settings.enableRealtime || !settings.userConsent) return;

    const url = details.url;
    if (!url || isWhitelisted(url)) return;

    try {
        // Validate session
        if (!secureApi.validateSession(sessionToken)) {
            await initializeSecureSession();
        }

        // Check if rate limit is exceeded
        if (!secureApi.checkRateLimit(clientId)) {
            console.warn('Rate limit exceeded');
            return;
        }

        // Check URL for phishing
        const isPhishing = await checkPhishingURL(url, clientId);

        if (isPhishing) {
            // Update badge
            chrome.action.setBadgeText({ text: "⚠️", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "red", tabId: details.tabId });

            // Show notification if enabled
            if (settings.enableNotifications) {
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icon48.png',
                    title: 'Phishing Alert',
                    message: 'A potential phishing site has been detected!'
                });
            }

            // Log the detection
            await secureApi.log('warning', 'Phishing site detected', { clientId }, { url });
        }
    } catch (error) {
        console.error('Error in navigation handler:', error);
        await secureApi.log('error', 'Navigation handler error', { clientId }, { error: error.message });
    }
}, { url: [{ urlMatches: "https?://.*" }] });

// Event listener for updating the badge when a page is loaded
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
    checkUrl(tab.url, tabId);
  }
});

// Function to check URL via ML model
async function checkUrl(url, tabId) {
  try {
    // Skip if no user consent
    if (!settings.userConsent) {
      console.log('User consent not given, skipping URL check');
      return;
    }

    // Validate session
    if (!secureApi.validateSession(sessionToken)) {
      await initializeSecureSession();
    }

    // Check URL for phishing
    const isPhishing = await checkPhishingURL(url, clientId);

    if (isPhishing) {
      // Update badge
      chrome.action.setBadgeText({ text: "⚠️", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "red", tabId });

      // Show notification if enabled
      if (settings.enableNotifications) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icon48.png',
          title: 'Phishing Alert',
          message: 'A potential phishing site has been detected!'
        });
      }

      // Log the detection
      await secureApi.log('warning', 'Phishing site detected', { clientId }, { url });
    } else {
      // Clear badge for safe sites
      chrome.action.setBadgeText({ text: "", tabId });
    }
  } catch (error) {
    console.error('Error checking URL:', error);
    await secureApi.log('error', 'URL check error', { clientId }, { error: error.message });
  }
}

// Message listener for popup to check URLs and handle settings
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "checkUrl" && message.url) {
        // Skip check if no user consent
        if (!settings.userConsent) {
            sendResponse({ 
                result: "Please enable user consent in settings first",
                timestamp: Date.now()
            });
            return true;
        }

        // Validate session and check URL
        if (!secureApi.validateSession(sessionToken)) {
            initializeSecureSession().then(() => {
                checkPhishingURL(message.url, clientId)
                    .then(isPhishing => {
                        sendResponse({ 
                            result: isPhishing ? "Phishing site detected" : "Safe site",
                            timestamp: Date.now()
                        });
                    })
                    .catch(error => {
                        console.error("Error checking URL:", error);
                        sendResponse({ 
                            result: "Error: " + error.message,
                            timestamp: Date.now()
                        });
                    });
            });
        } else {
            checkPhishingURL(message.url, clientId)
                .then(isPhishing => {
                    sendResponse({ 
                        result: isPhishing ? "Phishing site detected" : "Safe site",
                        timestamp: Date.now()
                    });
                })
                .catch(error => {
                    console.error("Error checking URL:", error);
                    sendResponse({ 
                        result: "Error: " + error.message,
                        timestamp: Date.now()
                    });
                });
        }
        return true; // Will respond asynchronously
    } else if (message.type === "settingsUpdated") {
        // Update settings
        settings = {
            ...settings,
            ...message.settings
        };

        // Reinitialize if ML setting changed
        if (message.settings.enableML !== undefined) {
            initializeSecureSession().catch(console.error);
        }
    }
});

// Initialize secure session when extension loads
initializeSecureSession().catch(error => {
    console.error('Failed to initialize secure session:', error);
}); 