/**
 * Anti-Phishing Extension Settings
 * Handles the settings page functionality, including loading, saving, and resetting settings.
 */

// Import the required modules
import { CONSENT_KEY, STATUS_TYPES, STATUS_MESSAGES } from '../common/constants.js';
import * as Storage from '../common/storage.js';
import * as Logger from '../utils/logger.js';

// Default settings
const DEFAULT_SETTINGS = {
  enableProtection: true,
  showWarnings: true,
  loggingLevel: 'error'
};

// Elements
const elements = {
  enableProtection: document.getElementById('enableProtection'),
  showWarnings: document.getElementById('showWarnings'),
  loggingLevel: document.getElementById('loggingLevel'),
  resetSettings: document.getElementById('resetSettings'),
  saveSettings: document.getElementById('saveSettings')
};

// Initialize settings page
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadSettings();
    setupEventListeners();
    Logger.info('Settings page initialized');
  } catch (error) {
    Logger.error('Failed to initialize settings page:', error);
    showError('Failed to load settings. Please try again.');
  }
});

// Load settings from storage
async function loadSettings() {
  const settings = await Storage.getSettings();
  
  // Apply settings to form elements
  elements.enableProtection.checked = settings.enableProtection;
  elements.showWarnings.checked = settings.showWarnings;
  elements.loggingLevel.value = settings.loggingLevel;
}

// Setup event listeners for all interactive elements
function setupEventListeners() {
  // Save and reset buttons
  elements.saveSettings.addEventListener('click', saveSettings);
  elements.resetSettings.addEventListener('click', confirmResetSettings);
}

// Save settings to storage
async function saveSettings() {
  try {
    const settings = {
      enableProtection: elements.enableProtection.checked,
      showWarnings: elements.showWarnings.checked,
      loggingLevel: elements.loggingLevel.value
    };
    
    await Storage.saveSettings(settings);
    showNotification('Settings saved successfully');
    Logger.info('Settings saved:', settings);
  } catch (error) {
    Logger.error('Failed to save settings:', error);
    showError('Failed to save settings. Please try again.');
  }
}

// Confirm reset before proceeding
function confirmResetSettings() {
  if (confirm('Are you sure you want to reset all settings to their default values?')) {
    resetSettings();
  }
}

// Reset settings to defaults
async function resetSettings() {
  try {
    await Storage.saveSettings(DEFAULT_SETTINGS);
    await loadSettings(); // Reload the UI with default settings
    showNotification('Settings have been reset to defaults');
    Logger.info('Settings reset to defaults');
  } catch (error) {
    Logger.error('Failed to reset settings:', error);
    showError('Failed to reset settings. Please try again.');
  }
}

// Show a notification to the user
function showNotification(message) {
  const notification = document.createElement('div');
  notification.classList.add('notification', 'success');
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  // Remove after 3 seconds
  setTimeout(() => {
    notification.classList.add('fade-out');
    setTimeout(() => notification.remove(), 500);
  }, 3000);
}

// Show an error message to the user
function showError(message) {
  const notification = document.createElement('div');
  notification.classList.add('notification', 'error');
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  // Remove after 3 seconds
  setTimeout(() => {
    notification.classList.add('fade-out');
    setTimeout(() => notification.remove(), 500);
  }, 3000);
}