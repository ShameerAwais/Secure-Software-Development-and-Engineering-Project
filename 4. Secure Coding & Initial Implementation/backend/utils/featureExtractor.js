/**
 * Feature Extractor for Phishing Detection
 * 
 * This module extracts features from URLs and page content
 * for use in the Random Forest machine learning model.
 */

const { JSDOM } = require('jsdom');
const { URL } = require('url');

/**
 * Extract features from URL and page content for machine learning model
 * @param {string} url - The URL to extract features from
 * @param {Object} pageContent - Content object extracted from the web page
 * @returns {Object} Extracted features with normalized values (0-1 range)
 */
function extractFeatures(url, pageContent) {
  try {
    const features = {};
    const urlFeatures = extractUrlFeatures(url);
    
    // Combine URL features
    Object.assign(features, urlFeatures);
    
    // If we have page content, extract content features
    if (pageContent && !pageContent.error) {
      const contentFeatures = extractContentFeatures(pageContent, url);
      Object.assign(features, contentFeatures);
    }
    
    return features;
  } catch (error) {
    console.error(`[Feature Extractor] Error extracting features: ${error.message}`);
    return {};
  }
}

/**
 * Extract features from a URL
 * @param {string} urlStr - URL string to analyze
 * @returns {Object} URL features
 */
function extractUrlFeatures(urlStr) {
  try {
    const url = new URL(urlStr);
    const domain = url.hostname;
    
    // URL Length Features
    const urlLength = urlStr.length;
    const domainLength = domain.length;
    
    // Domain Features
    const subdomainCount = domain.split('.').length - 1;
    const hasHyphen = domain.includes('-') ? 1 : 0;
    
    // URL Path Features
    const pathLength = url.pathname.length;
    const pathSegments = url.pathname.split('/').filter(Boolean).length;
    
    // Special Character Features
    const specialChars = urlStr.match(/[^a-zA-Z0-9./-]/g) || [];
    const specialCharCount = specialChars.length;
    
    // HTTPS Feature
    const hasHttps = url.protocol === 'https:' ? 1 : 0;
    
    // Query Parameter Features
    const hasQueryParams = url.search.length > 0 ? 1 : 0;
    const queryParamCount = url.search.startsWith('?') ? 
      url.search.substring(1).split('&').length : 0;
    
    // Number Features (normalize to 0-1 range)
    return {
      url_length: normalizeValue(urlLength, 10, 200), // Most URLs are 10-200 chars
      domain_length: normalizeValue(domainLength, 3, 50),
      subdomain_count: normalizeValue(subdomainCount, 0, 5),
      has_hyphen_in_domain: hasHyphen,
      path_length: normalizeValue(pathLength, 0, 100),
      path_segment_count: normalizeValue(pathSegments, 0, 10),
      special_char_count: normalizeValue(specialCharCount, 0, 20),
      has_https: hasHttps,
      has_query_params: hasQueryParams,
      query_param_count: normalizeValue(queryParamCount, 0, 10)
    };
  } catch (error) {
    console.error(`[URL Feature Extractor] Error: ${error.message}`);
    return {};
  }
}

/**
 * Extract features from page content
 * @param {Object} pageContent - Content from webpage
 * @param {string} urlStr - Current URL string
 * @returns {Object} Content features
 */
function extractContentFeatures(pageContent, urlStr) {
  try {
    const url = new URL(urlStr);
    const currentDomain = url.hostname;
    
    // Form Features
    const formCount = pageContent.forms ? pageContent.forms.length : 0;
    const loginFormCount = pageContent.forms ? 
      pageContent.forms.filter(form => form.isLoginForm).length : 0;
    
    // Password Field Features
    let passwordFieldCount = 0;
    let externalFormAction = 0;
    
    if (pageContent.forms && pageContent.forms.length > 0) {
      for (const form of pageContent.forms) {
        // Count password fields
        passwordFieldCount += form.inputs ? 
          form.inputs.filter(input => input.type === 'password').length : 0;
        
        // Check if form submits to external domain
        if (form.action) {
          try {
            const formActionDomain = new URL(form.action).hostname;
            if (formActionDomain !== currentDomain) {
              externalFormAction = 1;
            }
          } catch (e) {
            // Invalid URL in form action
          }
        }
      }
    }
    
    // Link Features
    const linkCount = pageContent.links ? pageContent.links.length : 0;
    let externalLinkCount = 0;
    
    if (pageContent.links && pageContent.links.length > 0) {
      externalLinkCount = pageContent.links.filter(link => link.isExternal).length;
    }
    
    const externalLinkRatio = linkCount > 0 ? externalLinkCount / linkCount : 0;
    
    // Text Features
    const hasSecurityClaims = pageContent.claimsSecureOrVerified ? 1 : 0;
    const hasUrgentLanguage = pageContent.hasUrgencyLanguage ? 1 : 0;
    
    // Security Features
    const hasHttps = pageContent.hasHttps ? 1 : 0;
    
    return {
      form_count: normalizeValue(formCount, 0, 10),
      login_form_count: normalizeValue(loginFormCount, 0, 5),
      password_field_count: normalizeValue(passwordFieldCount, 0, 5),
      external_form_action: externalFormAction,
      link_count: normalizeValue(linkCount, 0, 100),
      external_link_ratio: externalLinkRatio,
      has_security_claims: hasSecurityClaims,
      has_urgent_language: hasUrgentLanguage,
      content_has_https: hasHttps,
      login_form_without_https: hasHttps === 0 && loginFormCount > 0 ? 1 : 0
    };
  } catch (error) {
    console.error(`[Content Feature Extractor] Error: ${error.message}`);
    return {};
  }
}

/**
 * Normalize a value to 0-1 range
 * @param {number} value - Value to normalize
 * @param {number} min - Minimum expected value
 * @param {number} max - Maximum expected value
 * @returns {number} Normalized value between 0 and 1
 */
function normalizeValue(value, min, max) {
  if (value < min) return 0;
  if (value > max) return 1;
  return (value - min) / (max - min);
}

/**
 * Convert features object to array in consistent order for model input
 * @param {Object} features - Features object with named properties
 * @returns {Array} Array of feature values in consistent order
 */
function featuresToArray(features) {
  // Define the expected order of features for the model
  const featureOrder = [
    'url_length', 'domain_length', 'subdomain_count', 'has_hyphen_in_domain',
    'path_length', 'path_segment_count', 'special_char_count', 'has_https',
    'has_query_params', 'query_param_count', 'form_count', 'login_form_count',
    'password_field_count', 'external_form_action', 'link_count',
    'external_link_ratio', 'has_security_claims', 'has_urgent_language',
    'content_has_https', 'login_form_without_https'
  ];
  
  // Create array with features in the right order, defaulting to 0 if missing
  return featureOrder.map(feature => {
    return features[feature] !== undefined ? features[feature] : 0;
  });
}

module.exports = {
  extractFeatures,
  featuresToArray
};