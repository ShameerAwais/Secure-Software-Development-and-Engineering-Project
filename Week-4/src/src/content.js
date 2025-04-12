// Content script for the extension
console.log('Content script loaded');

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'checkUrl') {
    // Get the current URL
    const url = window.location.href;
    sendResponse({ url });
  }
  return true;
}); 