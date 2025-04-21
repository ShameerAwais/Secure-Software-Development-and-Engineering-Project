/**
 * Secure Storage Utility
 * Provides encryption/decryption for sensitive data stored in chrome.storage
 */

import * as logger from './logger.js';

const MODULE_NAME = 'SecureStorage';
const ENCRYPTION_KEY = generateEncryptionKey();

/**
 * Generate a random encryption key or retrieve the existing one
 * @returns {string} The encryption key
 */
async function generateEncryptionKey() {
  // Try to get existing key
  const data = await chrome.storage.local.get('secureStorageKey');
  
  if (data.secureStorageKey) {
    logger.debug(MODULE_NAME, 'Using existing encryption key');
    return data.secureStorageKey;
  }
  
  // Generate a new random key if none exists
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const key = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  
  // Store the key securely
  await chrome.storage.local.set({ secureStorageKey: key });
  logger.debug(MODULE_NAME, 'Generated new encryption key');
  
  return key;
}

/**
 * Encrypt data before storing
 * @param {any} data - Data to encrypt
 * @returns {string} - Encrypted data as string
 */
async function encrypt(data) {
  try {
    const key = await ENCRYPTION_KEY;
    const stringData = JSON.stringify(data);
    
    // Simple XOR encryption with the key (for demonstration)
    // In a production environment, use a stronger encryption algorithm
    const encrypted = stringData.split('')
      .map((char, i) => {
        const keyChar = key.charCodeAt(i % key.length);
        return String.fromCharCode(char.charCodeAt(0) ^ keyChar);
      })
      .join('');
    
    return btoa(encrypted); // Base64 encode the encrypted string
  } catch (error) {
    logger.error(MODULE_NAME, 'Encryption error', error);
    throw error;
  }
}

/**
 * Decrypt stored data
 * @param {string} encryptedData - Encrypted data to decrypt
 * @returns {any} - Decrypted data
 */
async function decrypt(encryptedData) {
  try {
    if (!encryptedData) {
      return null;
    }
    
    const key = await ENCRYPTION_KEY;
    const decoded = atob(encryptedData); // Base64 decode
    
    // XOR decryption
    const decrypted = decoded.split('')
      .map((char, i) => {
        const keyChar = key.charCodeAt(i % key.length);
        return String.fromCharCode(char.charCodeAt(0) ^ keyChar);
      })
      .join('');
    
    return JSON.parse(decrypted);
  } catch (error) {
    logger.error(MODULE_NAME, 'Decryption error', error);
    return null;
  }
}

/**
 * Securely store data with encryption
 * @param {string} key - Storage key
 * @param {any} data - Data to store securely
 * @returns {Promise<void>}
 */
export async function secureSet(key, data) {
  try {
    const encryptedData = await encrypt(data);
    const storageObj = {};
    storageObj[key] = encryptedData;
    await chrome.storage.local.set(storageObj);
    
    logger.debug(MODULE_NAME, `Data securely stored for key: ${key}`);
  } catch (error) {
    logger.error(MODULE_NAME, `Error storing encrypted data for key: ${key}`, error);
    throw error;
  }
}

/**
 * Securely retrieve and decrypt stored data
 * @param {string} key - Storage key to retrieve
 * @returns {Promise<any>} - Decrypted data
 */
export async function secureGet(key) {
  try {
    const data = await chrome.storage.local.get(key);
    if (!data[key]) {
      return null;
    }
    
    const decryptedData = await decrypt(data[key]);
    logger.debug(MODULE_NAME, `Data securely retrieved for key: ${key}`);
    
    return decryptedData;
  } catch (error) {
    logger.error(MODULE_NAME, `Error retrieving encrypted data for key: ${key}`, error);
    return null;
  }
}

/**
 * Securely remove stored data
 * @param {string} key - Storage key to remove
 * @returns {Promise<void>}
 */
export async function secureRemove(key) {
  try {
    await chrome.storage.local.remove(key);
    logger.debug(MODULE_NAME, `Data securely removed for key: ${key}`);
  } catch (error) {
    logger.error(MODULE_NAME, `Error removing data for key: ${key}`, error);
    throw error;
  }
}

/**
 * Clear all securely stored data
 * @returns {Promise<void>}
 */
export async function secureClear() {
  try {
    // Keep the encryption key when clearing storage
    const key = await ENCRYPTION_KEY;
    await chrome.storage.local.clear();
    await chrome.storage.local.set({ secureStorageKey: key });
    
    logger.debug(MODULE_NAME, 'All secure data cleared');
  } catch (error) {
    logger.error(MODULE_NAME, 'Error clearing secure storage', error);
    throw error;
  }
}