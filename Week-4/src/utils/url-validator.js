// URL validation utility functions
import * as logger from './logger.js';

const MODULE_NAME = 'URLValidator';

/**
 * Check if a URL is valid and suitable for scanning
 * @param {string} url - URL to validate
 * @returns {boolean} - Whether the URL is valid for scanning
 */
export const isValidUrl = (url) => {
  if (!url) {
    logger.debug(MODULE_NAME, 'URL is empty');
    return false;
  }

  try {
    const parsedUrl = new URL(url);
    
    // Check protocol - only http and https are valid
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      logger.debug(MODULE_NAME, `Invalid protocol: ${parsedUrl.protocol}`);
      return false;
    }
    
    // Exclude browser internal pages, extension pages, etc.
    if (parsedUrl.protocol === 'chrome:' || 
        parsedUrl.protocol === 'chrome-extension:' ||
        parsedUrl.protocol === 'about:' ||
        parsedUrl.protocol === 'data:' ||
        parsedUrl.protocol === 'file:' ||
        parsedUrl.protocol === 'view-source:') {
      logger.debug(MODULE_NAME, `URL is browser internal: ${url}`);
      return false;
    }
    
    // Make sure hostname exists
    if (!parsedUrl.hostname) {
      logger.debug(MODULE_NAME, 'URL has no hostname');
      return false;
    }
    
    return true;
  } catch (error) {
    logger.error(MODULE_NAME, `Error parsing URL: ${url}`, error);
    return false;
  }
};

/**
 * Normalize a URL for consistent comparison
 * @param {string} url - URL to normalize
 * @returns {string|null} - Normalized URL or null if invalid
 */
export const normalizeUrl = (url) => {
  if (!isValidUrl(url)) {
    return null;
  }
  
  try {
    const parsedUrl = new URL(url);
    
    // Normalize to lowercase
    let normalizedUrl = parsedUrl.protocol.toLowerCase() + '//';
    normalizedUrl += parsedUrl.hostname.toLowerCase();
    
    // Keep port if it's non-standard
    if (parsedUrl.port && 
        !((parsedUrl.protocol === 'http:' && parsedUrl.port === '80') || 
          (parsedUrl.protocol === 'https:' && parsedUrl.port === '443'))) {
      normalizedUrl += ':' + parsedUrl.port;
    }
    
    // Include path, but remove trailing slash if it's just '/'
    normalizedUrl += parsedUrl.pathname === '/' ? '' : parsedUrl.pathname;
    
    // Include query parameters
    if (parsedUrl.search) {
      normalizedUrl += parsedUrl.search;
    }
    
    // Exclude fragments (anchors) as they don't change the actual page
    
    return normalizedUrl;
  } catch (error) {
    logger.error(MODULE_NAME, `Error normalizing URL: ${url}`, error);
    return null;
  }
};

/**
 * Extract domain from URL
 * @param {string} url - URL to extract domain from
 * @returns {string|null} - Domain or null if URL is invalid
 */
export const extractDomain = (url) => {
  if (!isValidUrl(url)) {
    return null;
  }
  
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch (error) {
    logger.error(MODULE_NAME, `Error extracting domain: ${url}`, error);
    return null;
  }
};