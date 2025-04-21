// Content script for Anti-Phishing Browser Extension
// This script runs in the context of web pages

/**
 * Initialize content script
 */
function init() {
  console.log('Anti-Phishing Extension content script loaded');
  
  // We're implementing a manual scanning approach where the user
  // initiates scans from the popup, so this content script is minimal.
  // Future enhancements could include:
  // - Automatic scanning of pages based on user settings
  // - Scanning of links on hover
  // - Warning overlays for suspicious elements
  // - DOM analysis for phishing indicators
}

// Initialize the content script
init();

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Content script received message:', message);
  
  if (message.action === 'getPageDetails') {
    // Collect and return information about the current page
    const pageDetails = {
      url: window.location.href,
      title: document.title,
      domain: window.location.hostname
    };
    sendResponse({ success: true, details: pageDetails });
  }
  
  // Return true to indicate we will send a response asynchronously
  return true;
});