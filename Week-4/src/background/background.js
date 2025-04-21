// Background service worker for Anti-Phishing Browser Extension
import { checkUrl } from './gsb-api.js';
import { 
  checkConsent, 
  getStatus, 
  markAsChecking, 
  markAsSafe, 
  markAsUnsafe, 
  markAsError 
} from './status-manager.js';
import * as logger from '../utils/logger.js';
import { isValidUrl } from '../utils/url-validator.js';
import * as secureStorage from '../utils/secure-storage.js';
import * as integrityChecker from '../utils/integrity-checker.js';
import { sanitizeUrl, sanitizeObject } from '../utils/input-sanitizer.js';

const MODULE_NAME = 'Background';

// Perform security checks on startup
async function performSecurityChecks() {
  logger.info(MODULE_NAME, 'Performing security checks on extension startup');
  
  // Check extension integrity
  const integrityResult = await integrityChecker.verifyIntegrity();
  if (!integrityResult.isValid) {
    logger.error(MODULE_NAME, 'Extension integrity check failed', integrityResult.issues);
    // Store the integrity issues securely for the popup to display warnings to the user
    await secureStorage.secureSet('integrity_issues', integrityResult.issues);
  } else {
    logger.info(MODULE_NAME, 'Extension integrity check passed');
    // Clear any previous integrity issues
    await secureStorage.secureRemove('integrity_issues');
  }
}

// Listen for extension install or update
chrome.runtime.onInstalled.addListener(async (details) => {
  logger.info(MODULE_NAME, `Extension ${details.reason}`, details);
  
  if (details.reason === 'install') {
    // Initialize security measures on install
    await integrityChecker.storeIntegrityState();
    logger.info(MODULE_NAME, 'Initial integrity state stored');
  } else if (details.reason === 'update') {
    // Reset integrity state after update as files have changed
    await integrityChecker.resetIntegrityState();
    logger.info(MODULE_NAME, 'Integrity state reset after update');
  }
  
  // Perform initial security checks
  await performSecurityChecks();
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Log incoming message (sanitize before logging)
  const sanitizedMessage = sanitizeObject(message, ['url']);
  logger.debug(MODULE_NAME, 'Message received', { 
    message: sanitizedMessage, 
    sender: {
      id: sender.id,
      url: sender.url ? sanitizeUrl(sender.url) : null
    }
  });
  
  try {
    // Handle different message types
    switch (message.action) {
      case 'scanUrl':
        // Sanitize URL before processing
        const sanitizedUrl = sanitizeUrl(message.url);
        if (sanitizedUrl !== message.url) {
          logger.warn(MODULE_NAME, 'URL was modified during sanitization', {
            original: message.url,
            sanitized: sanitizedUrl
          });
        }
        handleScanUrl(sanitizedUrl, message.tabId, sendResponse);
        break;
      case 'getStatus':
        handleGetStatus(message.tabId, sendResponse);
        break;
      case 'checkIntegrity':
        handleIntegrityCheck(sendResponse);
        break;
      default:
        logger.warn(MODULE_NAME, `Unknown message action: ${message.action}`);
        sendResponse({ error: 'Unknown action' });
    }
  } catch (error) {
    logger.error(MODULE_NAME, 'Error processing message', error);
    sendResponse({ error: 'Error processing message' });
  }
  
  // Return true to indicate we will send a response asynchronously
  return true;
});

/**
 * Handle integrity check request
 * @param {Function} sendResponse - Function to send response back
 */
async function handleIntegrityCheck(sendResponse) {
  try {
    const integrityResult = await integrityChecker.verifyIntegrity();
    sendResponse(integrityResult);
  } catch (error) {
    logger.error(MODULE_NAME, 'Error checking integrity', error);
    sendResponse({ isValid: false, issues: ['Error performing integrity check'] });
  }
}

/**
 * Handle URL scan request from popup or content script
 * @param {string} url - URL to scan
 * @param {number} tabId - Tab ID
 * @param {Function} sendResponse - Function to send response back
 */
async function handleScanUrl(url, tabId, sendResponse) {
  logger.info(MODULE_NAME, `Scan requested for URL: ${url} (Tab ID: ${tabId})`);
  
  // Check if URL is valid
  if (!url || !isValidUrl(url)) {
    logger.warn(MODULE_NAME, `Invalid URL for scanning: ${url}`);
    await markAsError(tabId, url, 'Invalid URL');
    sendResponse({ success: false, error: 'Invalid URL' });
    return;
  }
  
  // Check if user has consented to scanning
  const consentGranted = await checkConsent();
  if (!consentGranted) {
    logger.warn(MODULE_NAME, 'Scan rejected: User consent not granted');
    sendResponse({ success: false, error: 'User consent required' });
    return;
  }
  
  // Mark as checking
  await markAsChecking(tabId, url);
  
  try {
    // Check URL with Google Safe Browsing API
    const gsbResult = await checkUrl(url);
    // Sanitize the result before logging
    const sanitizedResult = sanitizeObject(gsbResult, ['url']);
    logger.debug(MODULE_NAME, 'GSB API result', sanitizedResult);
    
    // Store the scan result securely
    await secureStorage.secureSet(`scan_result_${tabId}`, {
      url,
      result: gsbResult,
      timestamp: Date.now()
    });
    
    if (gsbResult.isSafe) {
      // URL is safe
      await markAsSafe(tabId, url);
      sendResponse({ success: true, isSafe: true });
    } else if (gsbResult.error) {
      // Error during check
      await markAsError(tabId, url, gsbResult.error);
      sendResponse({ success: false, error: gsbResult.error });
    } else {
      // URL is unsafe
      await markAsUnsafe(tabId, url, gsbResult.threatType);
      sendResponse({ success: true, isSafe: false, threatType: gsbResult.threatType });
      
      // Redirect to blocked page if URL is unsafe
      blockUnsafePage(tabId, url, gsbResult.threatType);
    }
  } catch (error) {
    logger.error(MODULE_NAME, `Error during URL scan: ${url}`, error);
    await markAsError(tabId, url, 'Unexpected error');
    sendResponse({ success: false, error: 'Unexpected error during scan' });
  }
}

/**
 * Handle get status request
 * @param {number} tabId - Tab ID
 * @param {Function} sendResponse - Function to send response back
 */
async function handleGetStatus(tabId, sendResponse) {
  logger.debug(MODULE_NAME, `Status requested for tab ID: ${tabId}`);
  
  try {
    const status = await getStatus(tabId);
    sendResponse(status);
  } catch (error) {
    logger.error(MODULE_NAME, `Error getting status for tab ${tabId}`, error);
    sendResponse({ 
      status: 'Error retrieving status',
      type: 'error',
      url: null,
      consent: await checkConsent()
    });
  }
}

/**
 * Block access to unsafe page by redirecting to blocked page
 * @param {number} tabId - Tab ID
 * @param {string} url - Unsafe URL
 * @param {string} threatType - Type of threat detected
 */
function blockUnsafePage(tabId, url, threatType) {
  if (!tabId) {
    logger.warn(MODULE_NAME, 'Cannot block page: No tab ID provided');
    return;
  }
  
  logger.info(MODULE_NAME, `Blocking unsafe page: ${url}`, { tabId, threatType });
  
  try {
    // Sanitize the URL before encoding it
    const sanitizedUrl = sanitizeUrl(url);
    const encodedUrl = encodeURIComponent(sanitizedUrl || url);
    const blockPageUrl = chrome.runtime.getURL(
      `/src/block_page/blocked.html?url=${encodedUrl}&threat=${threatType || 'unknown'}`
    );
    
    chrome.tabs.update(tabId, { url: blockPageUrl }, () => {
      if (chrome.runtime.lastError) {
        logger.error(MODULE_NAME, `Error redirecting to blocked page: ${chrome.runtime.lastError.message}`);
      } else {
        logger.info(MODULE_NAME, `Successfully redirected to blocked page: ${blockPageUrl}`);
      }
    });
  } catch (error) {
    logger.error(MODULE_NAME, 'Error in blockUnsafePage', error);
  }
}

// Run security checks on startup
performSecurityChecks()
  .then(() => {
    logger.info(MODULE_NAME, 'Security checks completed');
  })
  .catch(error => {
    logger.error(MODULE_NAME, 'Error during security checks', error);
  });

// Log that the background script has loaded
logger.info(MODULE_NAME, 'Background script loaded with security enhancements');