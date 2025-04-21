// Status manager for tracking URL safety statuses
import { CONSENT_KEY, STATUS_TYPES, STATUS_MESSAGES, STATUS_EXPIRY_TIME } from '../common/constants.js';
import { storeTabStatus, getTabStatus, getValue } from '../common/storage.js';
import * as logger from '../utils/logger.js';

const MODULE_NAME = 'StatusManager';

/**
 * Check if user has given consent for URL scanning
 * @returns {Promise<boolean>} - Whether consent is granted
 */
export const checkConsent = async () => {
  try {
    const consent = await getValue(CONSENT_KEY);
    // Default to true if the setting doesn't exist
    return consent !== false;
  } catch (error) {
    logger.error(MODULE_NAME, 'Error checking consent', error);
    // Default to false on error to be safe
    return false;
  }
};

/**
 * Update the status for a tab
 * @param {number} tabId - Tab ID
 * @param {string} url - URL being checked
 * @param {string} status - Status message
 * @param {string} type - Status type (from STATUS_TYPES)
 * @returns {Promise<void>}
 */
export const updateStatus = async (tabId, url, status, type) => {
  if (!tabId) {
    logger.warn(MODULE_NAME, 'Cannot update status: No tab ID provided');
    return;
  }

  logger.debug(MODULE_NAME, `Updating status for tab ${tabId}`, { url, status, type });
  
  try {
    await storeTabStatus(tabId, url, status, type);
    logger.debug(MODULE_NAME, `Status updated for tab ${tabId}`);
  } catch (error) {
    logger.error(MODULE_NAME, `Error updating status for tab ${tabId}`, error);
  }
};

/**
 * Get the current status for a tab
 * @param {number} tabId - Tab ID
 * @returns {Promise<Object>} - Status object with url, status, type, and consent
 */
export const getStatus = async (tabId) => {
  if (!tabId) {
    logger.warn(MODULE_NAME, 'Cannot get status: No tab ID provided');
    return { 
      status: STATUS_MESSAGES.ERROR,
      type: STATUS_TYPES.ERROR,
      url: null,
      consent: await checkConsent() 
    };
  }

  logger.debug(MODULE_NAME, `Getting status for tab ${tabId}`);
  
  try {
    const consentGranted = await checkConsent();
    const statusData = await getTabStatus(tabId);
    
    if (!consentGranted) {
      return { 
        status: STATUS_MESSAGES.DISABLED, 
        url: statusData?.url || null, 
        type: STATUS_TYPES.DISABLED, 
        consent: false 
      };
    }
    
    if (statusData && (Date.now() - statusData.timestamp < STATUS_EXPIRY_TIME)) {
      return { ...statusData, consent: true };
    }
    
    return {
      status: STATUS_MESSAGES.READY,
      url: null,
      type: STATUS_TYPES.IDLE,
      consent: true
    };
  } catch (error) {
    logger.error(MODULE_NAME, `Error getting status for tab ${tabId}`, error);
    return { 
      status: STATUS_MESSAGES.ERROR, 
      type: STATUS_TYPES.ERROR,
      url: null, 
      consent: await checkConsent() 
    };
  }
};

/**
 * Mark a URL as checking (in-progress)
 * @param {number} tabId - Tab ID
 * @param {string} url - URL being checked
 * @returns {Promise<void>}
 */
export const markAsChecking = async (tabId, url) => {
  return updateStatus(tabId, url, STATUS_MESSAGES.CHECKING, STATUS_TYPES.CHECKING);
};

/**
 * Mark a URL as safe
 * @param {number} tabId - Tab ID
 * @param {string} url - URL that was checked
 * @returns {Promise<void>}
 */
export const markAsSafe = async (tabId, url) => {
  return updateStatus(tabId, url, STATUS_MESSAGES.SAFE, STATUS_TYPES.SAFE);
};

/**
 * Mark a URL as unsafe
 * @param {number} tabId - Tab ID
 * @param {string} url - URL that was checked
 * @param {string} threatType - Optional threat type information
 * @returns {Promise<void>}
 */
export const markAsUnsafe = async (tabId, url, threatType = null) => {
  const status = threatType 
    ? `${STATUS_MESSAGES.UNSAFE} (${threatType})` 
    : STATUS_MESSAGES.UNSAFE;
  
  return updateStatus(tabId, url, status, STATUS_TYPES.UNSAFE);
};

/**
 * Mark a URL check as having an error
 * @param {number} tabId - Tab ID
 * @param {string} url - URL that was checked
 * @param {string} errorMessage - Optional error message
 * @returns {Promise<void>}
 */
export const markAsError = async (tabId, url, errorMessage = null) => {
  const status = errorMessage 
    ? `${STATUS_MESSAGES.ERROR}: ${errorMessage}` 
    : STATUS_MESSAGES.ERROR;
  
  return updateStatus(tabId, url, status, STATUS_TYPES.ERROR);
};