/**
 * Integrity Checker
 * Validates the integrity of the extension to detect tampering
 */

import * as logger from './logger.js';
import * as secureStorage from './secure-storage.js';

const MODULE_NAME = 'IntegrityChecker';
const INTEGRITY_KEY = 'extension_integrity_hash';
const CRITICAL_FILES = [
  'background/background.js',
  'background/gsb-api.js',
  'content/content.js',
  'utils/secure-storage.js'
];

/**
 * Calculate a hash for a string using SHA-256
 * @param {string} content - Content to hash
 * @returns {Promise<string>} - Hex string hash
 */
async function calculateHash(content) {
  try {
    // Convert the string to an ArrayBuffer
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    
    // Calculate hash using subtle crypto
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    
    // Convert to hex string
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  } catch (error) {
    logger.error(MODULE_NAME, 'Error calculating hash', error);
    throw error;
  }
}

/**
 * Get the content of a file from the extension
 * @param {string} filePath - Path to the file relative to extension root
 * @returns {Promise<string>} - File content
 */
async function getFileContent(filePath) {
  try {
    const response = await fetch(chrome.runtime.getURL(`src/${filePath}`));
    if (!response.ok) {
      throw new Error(`Failed to load file: ${filePath}`);
    }
    return await response.text();
  } catch (error) {
    logger.error(MODULE_NAME, `Error loading file: ${filePath}`, error);
    return '';
  }
}

/**
 * Generate integrity hash for critical extension files
 * @returns {Promise<Object>} - Object with file hashes
 */
async function generateIntegrityHash() {
  logger.debug(MODULE_NAME, 'Generating integrity hash for critical files');
  
  const hashes = {};
  for (const file of CRITICAL_FILES) {
    const content = await getFileContent(file);
    if (content) {
      hashes[file] = await calculateHash(content);
    }
  }
  
  // Also include the extension ID as an additional check
  hashes.extensionId = chrome.runtime.id;
  
  // Calculate a master hash from all the individual hashes
  const masterHashInput = Object.values(hashes).join('|');
  hashes.masterHash = await calculateHash(masterHashInput);
  
  logger.debug(MODULE_NAME, 'Integrity hash generated', hashes);
  return hashes;
}

/**
 * Store the current integrity state of the extension
 * Should be called on installation or update
 * @returns {Promise<void>}
 */
export async function storeIntegrityState() {
  try {
    const hashes = await generateIntegrityHash();
    await secureStorage.secureSet(INTEGRITY_KEY, hashes);
    logger.info(MODULE_NAME, 'Integrity state stored successfully');
  } catch (error) {
    logger.error(MODULE_NAME, 'Error storing integrity state', error);
  }
}

/**
 * Verify the integrity of the extension
 * @returns {Promise<{isValid: boolean, issues: string[]}>} - Integrity check result
 */
export async function verifyIntegrity() {
  logger.debug(MODULE_NAME, 'Verifying extension integrity');
  
  try {
    // Retrieve stored hashes
    const storedHashes = await secureStorage.secureGet(INTEGRITY_KEY);
    if (!storedHashes) {
      logger.warn(MODULE_NAME, 'No integrity hash found, generating new one');
      await storeIntegrityState();
      return { isValid: true, issues: [] };
    }
    
    // Generate current hashes
    const currentHashes = await generateIntegrityHash();
    
    // Check extension ID
    const issues = [];
    if (storedHashes.extensionId !== currentHashes.extensionId) {
      issues.push('Extension ID mismatch');
    }
    
    // Check file hashes
    for (const file of CRITICAL_FILES) {
      if (storedHashes[file] && currentHashes[file] && 
          storedHashes[file] !== currentHashes[file]) {
        issues.push(`File modified: ${file}`);
      }
    }
    
    // Check master hash as a final verification
    if (storedHashes.masterHash !== currentHashes.masterHash) {
      issues.push('Extension files have been modified');
    }
    
    const isValid = issues.length === 0;
    
    if (isValid) {
      logger.info(MODULE_NAME, 'Extension integrity verified successfully');
    } else {
      logger.warn(MODULE_NAME, 'Extension integrity check failed', { issues });
    }
    
    return { isValid, issues };
  } catch (error) {
    logger.error(MODULE_NAME, 'Error verifying integrity', error);
    return { 
      isValid: false, 
      issues: ['Error during integrity verification: ' + error.message] 
    };
  }
}

/**
 * Reset the integrity state (useful after updates)
 * @returns {Promise<void>}
 */
export async function resetIntegrityState() {
  try {
    await secureStorage.secureRemove(INTEGRITY_KEY);
    await storeIntegrityState();
    logger.info(MODULE_NAME, 'Integrity state reset successfully');
  } catch (error) {
    logger.error(MODULE_NAME, 'Error resetting integrity state', error);
  }
}