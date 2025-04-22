// Key installer for securely storing the API key
import * as secureStorage from '../utils/secure-storage.js';
import * as logger from '../utils/logger.js';

const MODULE_NAME = 'KeyInstaller';

/**
 * This function installs or refreshes the Google Safe Browsing API key
 * in secure storage. The actual key is injected during the build process.
 */
export const installApiKey = async () => {
  try {
    // In production, this value is replaced during build
    // Use a string literal to avoid reference errors in browser context
    const apiKey = 'KEY_PLACEHOLDER';
    
    if (apiKey === 'KEY_PLACEHOLDER') {
      logger.error(MODULE_NAME, 'Production API key not injected during build process');
      // Try to check browser storage as a fallback
      const storedKey = await secureStorage.secureGet('gsb_api_key_backup');
      if (storedKey && storedKey !== 'KEY_PLACEHOLDER') {
        await secureStorage.secureSet('gsb_api_key', storedKey);
        logger.info(MODULE_NAME, 'API key restored from backup storage');
        return true;
      }
      return false;
    }
    
    // Store the API key securely
    await secureStorage.secureSet('gsb_api_key', apiKey);
    // Also keep a backup copy
    await secureStorage.secureSet('gsb_api_key_backup', apiKey);
    logger.info(MODULE_NAME, 'API key securely stored');
    return true;
  } catch (error) {
    logger.error(MODULE_NAME, 'Error storing API key', error);
    return false;
  }
};

/**
 * Get the stored API key from secure storage
 * @returns {Promise<string|null>} The API key or null if not found
 */
export const getApiKey = async () => {
  try {
    const apiKey = await secureStorage.secureGet('gsb_api_key');
    if (!apiKey || apiKey === 'KEY_PLACEHOLDER') {
      logger.warn(MODULE_NAME, 'API key not found or is a placeholder');
      return null;
    }
    return apiKey;
  } catch (error) {
    logger.error(MODULE_NAME, 'Error retrieving API key', error);
    return null;
  }
};