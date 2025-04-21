// Blocked page script
document.addEventListener('DOMContentLoaded', () => {
  // Get URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get('url') || 'Unknown URL';
  const threatType = urlParams.get('threat') || 'unknown';
  
  // DOM elements
  const urlDisplay = document.getElementById('url-display');
  const threatTypeElement = document.getElementById('threat-type');
  const threatBadge = document.getElementById('threat-badge');
  const backButton = document.getElementById('back-button');
  const advancedButton = document.getElementById('advanced-button');
  const advancedPanel = document.getElementById('advanced-panel');
  const understandRiskCheckbox = document.getElementById('understand-risk');
  const proceedButton = document.getElementById('proceed-button');
  const reportButton = document.getElementById('report-button');
  const settingsLink = document.getElementById('settings-link');
  
  // Update the UI with the blocked URL and threat information
  urlDisplay.textContent = decodeURIComponent(blockedUrl);
  threatTypeElement.textContent = threatType.toUpperCase();
  
  // Update threat badge based on threat type
  if (threatType.includes('MALWARE')) {
    threatBadge.textContent = 'Malware Detected';
  } else if (threatType.includes('SOCIAL_ENGINEERING')) {
    threatBadge.textContent = 'Phishing Attempt';
  } else if (threatType.includes('UNWANTED_SOFTWARE')) {
    threatBadge.textContent = 'Unwanted Software';
  } else {
    threatBadge.textContent = 'Security Threat';
  }
  
  // Event handlers
  backButton.addEventListener('click', () => {
    window.history.back();
  });
  
  advancedButton.addEventListener('click', () => {
    advancedPanel.classList.toggle('visible');
    advancedButton.textContent = 
      advancedPanel.classList.contains('visible') ? 'Hide Options' : 'Advanced Options';
  });
  
  understandRiskCheckbox.addEventListener('change', (e) => {
    proceedButton.disabled = !e.target.checked;
  });
  
  proceedButton.addEventListener('click', () => {
    if (understandRiskCheckbox.checked) {
      // Store this URL as temporarily allowed and redirect
      const url = decodeURIComponent(blockedUrl);
      // We'll store this in session storage as an allowed exception
      sessionStorage.setItem('phishing_exception_' + url, 'allowed');
      window.location.href = url;
    }
  });
  
  reportButton.addEventListener('click', () => {
    // Open a false positive report form
    chrome.runtime.sendMessage({
      action: 'reportFalsePositive',
      url: decodeURIComponent(blockedUrl)
    });
    alert('Thank you for reporting this issue. Our team will review this website.');
  });
  
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
  
  // Animation on page load
  document.querySelector('.alert-box').style.animation = 'fadeIn 0.5s ease-in-out';
});