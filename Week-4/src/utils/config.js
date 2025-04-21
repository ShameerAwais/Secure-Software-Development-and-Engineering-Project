// Configuration for the extension
// IMPORTANT: Replace 'YOUR_API_KEY_HERE' with your actual Google Safe Browsing API Key
// Get one from: https://developers.google.com/safe-browsing/v4/get-started

/**
 * Google Safe Browsing API configuration
 */
export const GSB_CONFIG = {
  apiKey: 'AIzaSyD-ar66lj3OxdGOOOVjSB2RlJpot7cpVy4',
  clientId: 'anti-phishing-extension',
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