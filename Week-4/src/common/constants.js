// Constants used throughout the extension
export const CONSENT_KEY = 'userConsentEnabled';
export const TAB_STATUS_PREFIX = 'tabStatus_';
export const SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

// Status types
export const STATUS_TYPES = {
  IDLE: 'idle',
  CHECKING: 'checking',
  SAFE: 'safe',
  UNSAFE: 'unsafe',
  ERROR: 'error',
  DISABLED: 'disabled'
};

// Status messages
export const STATUS_MESSAGES = {
  READY: 'Ready to scan',
  CHECKING: 'Checking...',
  SAFE: 'Safe',
  UNSAFE: 'Unsafe - Threat Detected',
  ERROR: 'Error during check',
  DISABLED: 'Disabled (Consent Required)',
  BLOCKED: 'Blocked - Threat Detected'
};

// Time constants (in milliseconds)
export const STATUS_EXPIRY_TIME = 300000; // 5 minutes

// Threat types for Google Safe Browsing API
export const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING', // Phishing
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION'
];

// Platform types for Google Safe Browsing API
export const PLATFORM_TYPES = [
  'WINDOWS',
  'LINUX',
  'ANDROID',
  'OSX',
  'IOS',
  'ANY_PLATFORM',
  'ALL_PLATFORMS',
  'CHROME'
];