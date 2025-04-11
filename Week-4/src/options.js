document.addEventListener('DOMContentLoaded', () => {
    const consentCheckbox = document.getElementById('consentCheckbox');
    const enableMLCheckbox = document.getElementById('enableMLCheckbox');
    const enableRealtimeCheckbox = document.getElementById('enableRealtimeCheckbox');
    const enableNotificationsCheckbox = document.getElementById('enableNotificationsCheckbox');
    const saveBtn = document.getElementById('saveBtn');
    const status = document.getElementById('status');
  
    // Load saved settings
    chrome.storage.sync.get([
        'userConsent',
        'enableML',
        'enableRealtime',
        'enableNotifications'
    ], (settings) => {
        consentCheckbox.checked = settings.userConsent || false;
        enableMLCheckbox.checked = settings.enableML !== false; // Default to true
        enableRealtimeCheckbox.checked = settings.enableRealtime !== false; // Default to true
        enableNotificationsCheckbox.checked = settings.enableNotifications !== false; // Default to true
    });
  
    // Save settings
    saveBtn.addEventListener('click', () => {
        const newSettings = {
            userConsent: consentCheckbox.checked,
            enableML: enableMLCheckbox.checked,
            enableRealtime: enableRealtimeCheckbox.checked,
            enableNotifications: enableNotificationsCheckbox.checked
        };
  
        chrome.storage.sync.set(newSettings, () => {
            // Show success message
            status.textContent = '✅ Settings saved successfully!';
            status.classList.add('success');
  
            // Notify background script of settings change
            chrome.runtime.sendMessage({
                type: 'settingsUpdated',
                settings: newSettings
            });
  
            // Hide success message after 2 seconds
            setTimeout(() => {
                status.textContent = '';
                status.classList.remove('success');
            }, 2000);
        });
    });
  });
  