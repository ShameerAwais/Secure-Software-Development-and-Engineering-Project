chrome.notifications.create({
  type: "basic",
  iconUrl: "icon48.png",
  title: "Security Alert",
  message: message,
  priority: 2,
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
    } else {
      // Clear badge for safe sites
      chrome.action.setBadgeText({ text: "", tabId });
    }
  } catch (error) {
    console.error('Error checking URL:', error);
    await secureApi.log('error', 'URL check error', { clientId }, { error: error.message });
  }
} 