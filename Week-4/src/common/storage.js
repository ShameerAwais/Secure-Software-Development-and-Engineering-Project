// Storage utility functions
import { TAB_STATUS_PREFIX } from './constants.js';

/**
 * Store a value in Chrome's local storage
 * @param {string} key - Storage key
 * @param {*} value - Value to store
 * @returns {Promise} - Resolves when storage is complete
 */
export const storeValue = (key, value) => {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ [key]: value }, () => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve();
      }
    });
  });
};

/**
 * Get a value from Chrome's local storage
 * @param {string} key - Storage key to retrieve
 * @returns {Promise<*>} - Resolves with the stored value
 */
export const getValue = (key) => {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get([key], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(result[key]);
      }
    });
  });
};

/**
 * Get multiple values from Chrome's local storage
 * @param {Array<string>} keys - Storage keys to retrieve
 * @returns {Promise<Object>} - Resolves with object containing the stored values
 */
export const getMultipleValues = (keys) => {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(result);
      }
    });
  });
};

/**
 * Store tab status information
 * @param {number} tabId - Tab ID
 * @param {string} url - URL being checked
 * @param {string} status - Status message
 * @param {string} type - Status type (safe, unsafe, checking, error)
 * @returns {Promise} - Resolves when storage is complete
 */
export const storeTabStatus = (tabId, url, status, type) => {
  const statusData = {
    url,
    status,
    type,
    timestamp: Date.now()
  };
  return storeValue(`${TAB_STATUS_PREFIX}${tabId}`, statusData);
};

/**
 * Get tab status information
 * @param {number} tabId - Tab ID
 * @returns {Promise<Object|null>} - Resolves with status data or null if not found
 */
export const getTabStatus = async (tabId) => {
  return getValue(`${TAB_STATUS_PREFIX}${tabId}`);
};

/**
 * Remove tab status information
 * @param {number} tabId - Tab ID
 * @returns {Promise} - Resolves when removal is complete
 */
export const removeTabStatus = (tabId) => {
  return new Promise((resolve, reject) => {
    chrome.storage.local.remove(`${TAB_STATUS_PREFIX}${tabId}`, () => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve();
      }
    });
  });
};

/**
 * Default settings for the extension
 */
const DEFAULT_SETTINGS = {
  enableProtection: true,
  showWarnings: true,
  loggingLevel: 'error'
};

/**
 * Storage key for settings
 */
const SETTINGS_KEY = 'anti_phishing_settings';

/**
 * Get extension settings
 * @returns {Promise<Object>} - Resolves with the settings object
 */
export const getSettings = async () => {
  const settings = await getValue(SETTINGS_KEY);
  return settings || DEFAULT_SETTINGS;
};

/**
 * Save extension settings
 * @param {Object} settings - Settings object to save
 * @returns {Promise} - Resolves when settings are saved
 */
export const saveSettings = async (settings) => {
  return storeValue(SETTINGS_KEY, settings);
};