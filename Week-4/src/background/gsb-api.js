// Google Safe Browsing API integration
import { SAFE_BROWSING_API_URL, THREAT_TYPES, PLATFORM_TYPES } from '../common/constants.js';
import { GSB_CONFIG } from '../utils/config.js';
import * as logger from '../utils/logger.js';
import { normalizeUrl } from '../utils/url-validator.js';
import * as secureStorage from '../utils/secure-storage.js';
import { getApiKey } from './key-installer.js';

const MODULE_NAME = 'GSB-API';

/**
 * Check if a URL is safe using Google Safe Browsing API
 * @param {string} url - URL to check
 * @returns {Promise<{ isSafe: boolean, threatType: string|null, statusCode: number }>} - Result object
 */
export const checkUrl = async (url) => {
  logger.info(MODULE_NAME, `Checking URL: ${url}`);
  
  const normalizedUrl = normalizeUrl(url);
  if (!normalizedUrl) {
    logger.error(MODULE_NAME, 'URL is invalid or could not be normalized');
    return { isSafe: false, threatType: null, statusCode: 400, error: 'Invalid URL' };
  }

  const requestBody = constructRequestBody(normalizedUrl);
  
  try {
    const apiUrl = new URL(SAFE_BROWSING_API_URL);
    
    // Get API key from secure storage
    let apiKey = await getApiKey();
    
    // Fall back to config if not found in secure storage
    if (!apiKey) {
      logger.warn(MODULE_NAME, 'Using fallback API key from config');
      apiKey = GSB_CONFIG.apiKey;
    }
    
    // Append API key as query parameter
    apiUrl.searchParams.append('key', apiKey);
    
    logger.debug(MODULE_NAME, 'Making GSB API request', {
      url: apiUrl.toString().replace(apiKey, '***API_KEY_REDACTED***'),
      method: 'POST',
      bodyLength: JSON.stringify(requestBody).length
    });
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    logger.debug(MODULE_NAME, `GSB API response status: ${response.status}`);
    
    if (!response.ok) {
      const errorText = await response.text();
      logger.error(MODULE_NAME, `GSB API error: ${response.status}`, errorText);
      return { 
        isSafe: false, 
        threatType: null, 
        statusCode: response.status, 
        error: `API error: ${response.status}` 
      };
    }
    
    const data = await response.json();
    logger.debug(MODULE_NAME, 'GSB API response data', data);
    
    if (data.matches && data.matches.length > 0) {
      // URL matches a threat
      const threatType = data.matches[0].threatType;
      logger.warn(MODULE_NAME, `URL is unsafe. Threat type: ${threatType}`, {
        url: normalizedUrl,
        threatType: threatType
      });
      
      return {
        isSafe: false,
        threatType: threatType,
        statusCode: 200,
        details: data.matches
      };
    }
    
    // No matches means the URL is safe
    logger.info(MODULE_NAME, 'URL is safe', { url: normalizedUrl });
    return {
      isSafe: true,
      threatType: null,
      statusCode: 200
    };
    
  } catch (error) {
    logger.error(MODULE_NAME, 'Error in GSB API request', error);
    return {
      isSafe: false,
      threatType: null,
      statusCode: 500,
      error: error.message
    };
  }
};

/**
 * Construct the request body for Google Safe Browsing API
 * @param {string} url - URL to check
 * @returns {Object} - Request body for the API
 */
function constructRequestBody(url) {
  return {
    client: {
      clientId: GSB_CONFIG.clientId,
      clientVersion: GSB_CONFIG.clientVersion
    },
    threatInfo: {
      threatTypes: THREAT_TYPES,
      platformTypes: PLATFORM_TYPES,
      threatEntryTypes: ['URL'],
      threatEntries: [
        { url: url }
      ]
    }
  };
}