// Logger utility for consistent logging throughout the extension
import { DEV_MODE } from './config.js';

/**
 * Log levels
 */
const LOG_LEVELS = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3
};

/**
 * Current log level - Only logs at this level or higher will be displayed
 * In production mode, we only show INFO and above
 */
const CURRENT_LOG_LEVEL = DEV_MODE ? LOG_LEVELS.DEBUG : LOG_LEVELS.INFO;

/**
 * Format the log message with module name and timestamp
 * @param {string} level - Log level
 * @param {string} module - Module name
 * @param {string} message - Log message
 * @param {any} data - Additional data to log
 * @returns {string} - Formatted log message
 */
const formatLog = (level, module, message, data) => {
  const timestamp = new Date().toISOString();
  return `[${timestamp}] [${level}] [${module}] ${message}`;
};

/**
 * Log a debug message
 * @param {string} module - Module name
 * @param {string} message - Log message
 * @param {any} data - Additional data to log
 */
export const debug = (module, message, data = null) => {
  if (CURRENT_LOG_LEVEL <= LOG_LEVELS.DEBUG) {
    console.debug(formatLog('DEBUG', module, message), data || '');
  }
};

/**
 * Log an info message
 * @param {string} module - Module name
 * @param {string} message - Log message
 * @param {any} data - Additional data to log
 */
export const info = (module, message, data = null) => {
  if (CURRENT_LOG_LEVEL <= LOG_LEVELS.INFO) {
    console.info(formatLog('INFO', module, message), data || '');
  }
};

/**
 * Log a warning message
 * @param {string} module - Module name
 * @param {string} message - Log message
 * @param {any} data - Additional data to log
 */
export const warn = (module, message, data = null) => {
  if (CURRENT_LOG_LEVEL <= LOG_LEVELS.WARN) {
    console.warn(formatLog('WARN', module, message), data || '');
  }
};

/**
 * Log an error message
 * @param {string} module - Module name
 * @param {string} message - Log message
 * @param {any} error - Error object or additional data
 */
export const error = (module, message, error = null) => {
  if (CURRENT_LOG_LEVEL <= LOG_LEVELS.ERROR) {
    console.error(formatLog('ERROR', module, message), error || '');
  }
};