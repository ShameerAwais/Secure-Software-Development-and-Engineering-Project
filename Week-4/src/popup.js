// Import the checkPhishingURL function from urlChecker.js
import { checkPhishingURL } from './urlChecker.js';

document.addEventListener('DOMContentLoaded', () => {
  console.log("Popup script loaded and DOMContentLoaded event fired.");
  
  const scanButton = document.getElementById("scanBtn");
  const resultDiv = document.getElementById("result");
  const alertsDiv = document.getElementById("alerts");
  const settingsBtn = document.getElementById("settingsBtn");

  // Load any previous alerts
  chrome.storage.local.get(['lastPhishingUrl'], (data) => {
    if (data.lastPhishingUrl) {
      const alert = document.createElement('div');
      alert.className = 'alert-box';
      alert.textContent = `⚠️ Recent phishing attempt blocked: ${data.lastPhishingUrl}`;
      alertsDiv.appendChild(alert);
    }
  });

  // Handle scan button click
  scanButton.addEventListener('click', async () => {
    // Show loading state
    resultDiv.textContent = 'Scanning current page...';
    resultDiv.className = 'scanning';
    scanButton.disabled = true;

    try {
      // Get the current active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (!tab || !tab.url) {
        throw new Error('Could not get current tab URL');
      }

      // Send message to background script to check URL
      chrome.runtime.sendMessage({ 
        type: 'checkUrl', 
        url: tab.url 
      }, response => {
        if (response && response.result) {
          const result = response.result.toString().trim();
          
          if (result.includes('Please enable user consent')) {
            resultDiv.textContent = '⚠️ Please enable user consent in settings first';
            resultDiv.className = 'warning';
          } else if (result.includes('Phishing site detected')) {
            resultDiv.textContent = '❌ Phishing site detected!';
            resultDiv.className = 'danger';
          } else if (result.includes('Safe site')) {
            resultDiv.textContent = '✅ Safe site';
            resultDiv.className = 'safe';
          } else if (result.includes('Error')) {
            resultDiv.textContent = '❌ Error: ' + result.replace('Error:', '').trim();
            resultDiv.className = 'danger';
          } else {
            resultDiv.textContent = '❌ Error: Invalid response format';
            resultDiv.className = 'danger';
          }
        } else {
          resultDiv.textContent = '❌ Error checking URL';
          resultDiv.className = 'danger';
        }
        scanButton.disabled = false;
      });
    } catch (error) {
      console.error('Error:', error);
      resultDiv.textContent = '❌ Error: ' + error.message;
      resultDiv.className = 'danger';
      scanButton.disabled = false;
    }
  });

  // Handle settings button click
  settingsBtn.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
});
