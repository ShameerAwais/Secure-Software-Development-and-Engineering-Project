// Configuration for the extension

/**
 * Google Safe Browsing API configuration
 * The API key is not hardcoded here for security reasons.
 * It is fetched from secure storage at runtime.
 */
export const GSB_CONFIG = {
  apiKey: 'KEY_PLACEHOLDER', // Will be securely replaced during the build process
  clientId: 'anti-phishing-extension', // Separated from the API key with proper syntax
  clientVersion: '1.0.0'
};

/**
 * Extension settings with default values
 */
export const DEFAULT_SETTINGS = {
  consentEnabled: true,      // Default consent is enabled
  checkFrequency: 'manual',  // 'manual' or 'auto'
  blockMode: 'strict'        // 'strict' or 'warn'
};

/**
 * Development mode configuration 
 * Set to true during development to enable additional logging
 */
export const DEV_MODE = true; // Changed to true for debugging