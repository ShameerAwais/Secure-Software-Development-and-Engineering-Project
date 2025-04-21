// Popup script for the Anti-Phishing Browser Extension
import { STATUS_TYPES, STATUS_MESSAGES } from '../common/constants.js';

document.addEventListener('DOMContentLoaded', () => {
    // UI elements
    const statusTextElement = document.getElementById('status-text');
    const urlSpanElement = document.getElementById('url-span');
    const statusAreaElement = document.getElementById('status-area');
    const scanButton = document.getElementById('scanButton');
    const settingsButton = document.getElementById('settingsButton');

    // Track current tab information
    let currentTabId = null;
    let currentUrl = null;

    // Initialize the popup when it's opened
    initializePopup();

    // Button event listeners
    scanButton.addEventListener('click', handleScanButtonClick);
    settingsButton.addEventListener('click', () => chrome.runtime.openOptionsPage());

    /**
     * Initialize the popup with current tab information and status
     */
    async function initializePopup() {
        try {
            // Get current tab information
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (!tabs || tabs.length === 0) {
                updatePopupUI("Cannot get active tab", "N/A", STATUS_TYPES.ERROR, false);
                scanButton.disabled = true;
                return;
            }

            const currentTab = tabs[0];
            currentTabId = currentTab.id;
            currentUrl = currentTab.url;

            // Display current URL immediately
            updateUrl(currentUrl);

            // Request status from background script
            chrome.runtime.sendMessage({ 
                action: "getStatus", 
                tabId: currentTabId 
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Error receiving status:", chrome.runtime.lastError.message);
                    updatePopupUI(
                        "Error fetching status", 
                        currentUrl, 
                        STATUS_TYPES.ERROR, 
                        false
                    );
                    scanButton.disabled = true;
                } else if (response) {
                    console.log("Popup received initial status:", response);
                    // Use the stored URL if available and relevant, otherwise tab URL
                    const displayUrl = response.url || currentUrl;
                    updatePopupUI(
                        response.status, 
                        displayUrl, 
                        response.type, 
                        response.consent
                    );
                    scanButton.disabled = !response.consent || response.type === STATUS_TYPES.CHECKING;
                } else {
                    // No response might mean background is starting or no data stored
                    updatePopupUI(
                        STATUS_MESSAGES.READY, 
                        currentUrl, 
                        STATUS_TYPES.IDLE, 
                        true
                    );
                    scanButton.disabled = false;
                }
            });
        } catch (error) {
            console.error("Error initializing popup:", error);
            updatePopupUI("Error initializing", "N/A", STATUS_TYPES.ERROR, false);
            scanButton.disabled = true;
        }
    }

    /**
     * Handle scan button click
     */
    function handleScanButtonClick() {
        if (currentTabId && currentUrl) {
            console.log(`Popup: Requesting scan for ${currentUrl} (Tab ID: ${currentTabId})`);
            updatePopupUI(STATUS_MESSAGES.CHECKING, currentUrl, STATUS_TYPES.CHECKING, true);
            scanButton.disabled = true;

            chrome.runtime.sendMessage({ 
                action: "scanUrl", 
                url: currentUrl, 
                tabId: currentTabId 
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Error sending scan request:", chrome.runtime.lastError.message);
                    updatePopupUI("Error starting scan", currentUrl, STATUS_TYPES.ERROR, true);
                } else {
                    console.log("Scan request sent, response:", response);
                }
                
                // Refresh status after a short delay to allow background processing
                setTimeout(() => requestStatusUpdate(currentTabId, currentUrl), 500);
            });
        } else {
            console.log("Popup: Cannot scan - Invalid URL or Tab ID.");
            updatePopupUI("Cannot scan this page", currentUrl, STATUS_TYPES.ERROR, true);
        }
    }

    /**
     * Request updated status from the background script
     * @param {number} tabId - Tab ID
     * @param {string} url - Current URL 
     */
    function requestStatusUpdate(tabId, url) {
        if (!tabId) return;
        
        chrome.runtime.sendMessage({ action: "getStatus", tabId: tabId }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("Error receiving status update:", chrome.runtime.lastError.message);
            } else if (response) {
                const displayUrl = response.url || url;
                updatePopupUI(response.status, displayUrl, response.type, response.consent);
            }
        });
    }

    /**
     * Update the popup UI with the current status
     * @param {string} status - Status message
     * @param {string} url - URL being checked
     * @param {string} type - Status type (safe, unsafe, checking, error)
     * @param {boolean} consent - Whether user has given consent
     */
    function updatePopupUI(status, url, type, consent) {
        statusTextElement.textContent = status || "Status Unknown";
        updateUrl(url);

        // Remove previous type classes
        statusAreaElement.className = 'status-area'; // Reset classes

        if (!consent) {
            statusAreaElement.classList.add('disabled');
            statusTextElement.textContent = STATUS_MESSAGES.DISABLED;
            scanButton.disabled = true;
        } else if (type) {
            statusAreaElement.classList.add(type);
            scanButton.disabled = (type === STATUS_TYPES.CHECKING);
        } else {
            statusAreaElement.classList.add(STATUS_TYPES.IDLE);
            scanButton.disabled = false;
        }
    }

    /**
     * Update the displayed URL
     * @param {string} url - URL to display
     */
    function updateUrl(url) {
        if (!url) {
            urlSpanElement.textContent = "N/A";
            return;
        }
        
        // Truncate long URLs
        urlSpanElement.textContent = url.length > 50 
            ? url.substring(0, 47) + '...' 
            : url;
        
        // Add title with full URL for hover
        urlSpanElement.title = url;
    }
});