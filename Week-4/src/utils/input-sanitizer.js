/**
 * Input Sanitizer Utility
 * Provides functions to sanitize user inputs and prevent injection attacks
 */

import * as logger from './logger.js';

const MODULE_NAME = 'InputSanitizer';

/**
 * Sanitize a string to prevent XSS attacks
 * @param {string} input - The string to sanitize
 * @returns {string} - Sanitized string
 */
export function sanitizeString(input) {
  if (!input || typeof input !== 'string') {
    return '';
  }
  
  try {
    // Replace HTML entities and dangerous characters
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
      .replace(/\\/g, '&#x5C;')
      .replace(/`/g, '&#96;');
  } catch (error) {
    logger.error(MODULE_NAME, 'Error sanitizing string', error);
    return '';
  }
}

/**
 * Sanitize a URL to prevent potential security issues
 * @param {string} url - URL to sanitize
 * @returns {string|null} - Sanitized URL or null if invalid
 */
export function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') {
    return null;
  }
  
  try {
    // Try to create a URL object to validate
    const urlObject = new URL(url);
    
    // Only allow http and https protocols
    if (urlObject.protocol !== 'http:' && urlObject.protocol !== 'https:') {
      logger.warn(MODULE_NAME, `Blocked potentially dangerous URL protocol: ${urlObject.protocol}`);
      return null;
    }
    
    // Check for common injection patterns in URL components
    const dangerousPatterns = [
      'javascript:',
      'data:',
      'vbscript:',
      '<script',
      'onload=',
      'onerror='
    ];
    
    const urlLower = url.toLowerCase();
    for (const pattern of dangerousPatterns) {
      if (urlLower.includes(pattern)) {
        logger.warn(MODULE_NAME, `Blocked URL with dangerous pattern: ${pattern}`);
        return null;
      }
    }
    
    // Return the sanitized URL
    return urlObject.toString();
  } catch (error) {
    logger.error(MODULE_NAME, 'Error sanitizing URL', error);
    return null;
  }
}

/**
 * Sanitize an object by checking all string properties
 * @param {Object} obj - The object to sanitize
 * @param {Array<string>} urlFields - Fields that should be treated as URLs
 * @returns {Object} - Sanitized object
 */
export function sanitizeObject(obj, urlFields = []) {
  if (!obj || typeof obj !== 'object' || obj === null) {
    return {};
  }
  
  try {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        if (urlFields.includes(key)) {
          sanitized[key] = sanitizeUrl(value);
        } else {
          sanitized[key] = sanitizeString(value);
        }
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = sanitizeObject(value, urlFields);
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  } catch (error) {
    logger.error(MODULE_NAME, 'Error sanitizing object', error);
    return {};
  }
}

/**
 * Validate that an object has required fields of expected types
 * @param {Object} obj - Object to validate
 * @param {Object} schema - Schema defining required fields and their types
 * @returns {boolean} - Whether the object is valid according to the schema
 */
export function validateObject(obj, schema) {
  if (!obj || typeof obj !== 'object' || obj === null) {
    logger.warn(MODULE_NAME, 'Invalid object provided for validation');
    return false;
  }
  
  if (!schema || typeof schema !== 'object' || schema === null) {
    logger.warn(MODULE_NAME, 'Invalid schema provided for validation');
    return false;
  }
  
  try {
    for (const [field, requirements] of Object.entries(schema)) {
      // Check required fields
      if (requirements.required && (obj[field] === undefined || obj[field] === null)) {
        logger.warn(MODULE_NAME, `Required field missing: ${field}`);
        return false;
      }
      
      // If field exists, check type
      if (obj[field] !== undefined && obj[field] !== null) {
        const actualType = Array.isArray(obj[field]) ? 'array' : typeof obj[field];
        if (requirements.type && actualType !== requirements.type) {
          logger.warn(MODULE_NAME, `Field type mismatch for ${field}: expected ${requirements.type}, got ${actualType}`);
          return false;
        }
        
        // Check array item types if specified
        if (requirements.type === 'array' && requirements.itemType && Array.isArray(obj[field])) {
          for (const item of obj[field]) {
            const itemType = Array.isArray(item) ? 'array' : typeof item;
            if (itemType !== requirements.itemType) {
              logger.warn(MODULE_NAME, `Array item type mismatch for ${field}: expected ${requirements.itemType}, got ${itemType}`);
              return false;
            }
          }
        }
      }
    }
    
    return true;
  } catch (error) {
    logger.error(MODULE_NAME, 'Error validating object', error);
    return false;
  }
}