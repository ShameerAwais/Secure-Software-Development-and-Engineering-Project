// Import the checkPhishingURL function from urlChecker.js
import { checkPhishingURL } from './urlChecker.js';

document.addEventListener('DOMContentLoaded', () => {
  console.log("Popup script loaded and DOMContentLoaded event fired.");
  
  const scanButton = document.getElementById("scanBtn");
  const resultDiv = document.getElementById("result");
  const settingsBtn = document.getElementById("settingsBtn");

  // Handle scan button click
  scanButton.addEventListener('click', async () => {
    // Show loading state
    resultDiv.textContent = 'Scanning current page...';
    resultDiv.className = 'result-container scanning';
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
            resultDiv.textContent = 'Please enable user consent in settings first';
            resultDiv.className = 'result-container warning';
          } else if (result.includes('Phishing site detected')) {
            resultDiv.textContent = 'Phishing site detected';
            resultDiv.className = 'result-container danger';
          } else if (result.includes('Safe site')) {
            resultDiv.textContent = 'Safe site';
            resultDiv.className = 'result-container safe';
          } else if (result.includes('Error')) {
            resultDiv.textContent = 'Error: ' + result.replace('Error:', '').trim();
            resultDiv.className = 'result-container danger';
          } else {
            resultDiv.textContent = 'Error: Invalid response format';
            resultDiv.className = 'result-container danger';
          }
        } else {
          resultDiv.textContent = 'Error checking URL';
          resultDiv.className = 'result-container danger';
        }
        scanButton.disabled = false;
      });
    } catch (error) {
      console.error('Error:', error);
      resultDiv.textContent = 'Error: ' + error.message;
      resultDiv.className = 'result-container danger';
      scanButton.disabled = false;
    }
  });

  // Handle settings button click
  settingsBtn.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
}); 