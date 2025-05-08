/**
 * Train Random Forest Model Script
 * 
 * This script trains the Random Forest phishing detection model
 * using data from text files containing phishing and legitimate URLs.
 */

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const phishingClassifier = require('./randomForestClassifier');
const { extractFeatures, featuresToArray } = require('./featureExtractor');

// Data file paths
const PHISHING_URLS_FILE = path.join(__dirname, '../data/phishing_urls.txt');
const LEGITIMATE_URLS_FILE = path.join(__dirname, '../data/legitimate_urls.txt');

/**
 * Read URLs from a file
 * @param {string} filePath - Path to the file
 * @returns {Array} Array of URLs
 */
function readUrlsFromFile(filePath) {
  try {
    // Read file content
    const fileContent = fs.readFileSync(filePath, 'utf8');
    
    // Split by newline and filter out empty lines
    const urls = fileContent
      .split('\n')
      .map(url => url.trim())
      .filter(url => url.length > 0);
    
    return urls;
  } catch (error) {
    console.error(`Error reading URLs from ${filePath}: ${error.message}`);
    return [];
  }
}

/**
 * Mock page content for a phishing site
 * @returns {Object} Simulated phishing page content
 */
function mockPhishingPageContent() {
  return {
    forms: [
      {
        action: 'https://secure-form-processing.com/submit',
        method: 'post',
        isLoginForm: true,
        inputs: [
          { type: 'text', name: 'username', placeholder: 'Email or username' },
          { type: 'password', name: 'password', placeholder: 'Password' }
        ]
      }
    ],
    title: 'Login to your account - Secure verification',
    links: [
      { href: 'https://legitimate-bank.com', text: 'Home', isExternal: true },
      { href: 'https://www.google.com', text: 'Privacy Policy', isExternal: true },
      { href: 'https://phishing-site.com/terms', text: 'Terms', isExternal: false }
    ],
    hasHttps: Math.random() > 0.5, // 50% chance of HTTPS
    claimsSecureOrVerified: true,
    hasUrgencyLanguage: true
  };
}

/**
 * Mock page content for a legitimate site
 * @returns {Object} Simulated legitimate page content
 */
function mockLegitimatePageContent() {
  return {
    forms: [
      {
        action: '/submit-login',
        method: 'post',
        isLoginForm: true,
        inputs: [
          { type: 'text', name: 'username', placeholder: 'Email or username' },
          { type: 'password', name: 'password', placeholder: 'Password' }
        ]
      }
    ],
    title: 'Sign in to your account',
    links: [
      { href: '/', text: 'Home', isExternal: false },
      { href: '/privacy', text: 'Privacy Policy', isExternal: false },
      { href: '/terms', text: 'Terms', isExternal: false }
    ],
    hasHttps: true,
    claimsSecureOrVerified: false,
    hasUrgencyLanguage: false
  };
}

/**
 * Train the model with data from files
 */
async function trainModelWithFileData() {
  try {
    console.log('Starting model training with file data...');
    
    // Read URLs from files
    const phishingUrls = readUrlsFromFile(PHISHING_URLS_FILE);
    const legitimateUrls = readUrlsFromFile(LEGITIMATE_URLS_FILE);
    
    console.log(`Read ${phishingUrls.length} phishing URLs and ${legitimateUrls.length} legitimate URLs from files`);
    
    if (phishingUrls.length === 0 || legitimateUrls.length === 0) {
      console.error('Error: Not enough URLs to train the model');
      return;
    }
    
    const features = [];
    const labels = [];
    
    // Process phishing URLs
    console.log(`Processing ${phishingUrls.length} phishing URLs...`);
    for (const url of phishingUrls) {
      try {
        const pageContent = mockPhishingPageContent();
        const extractedFeatures = extractFeatures(url, pageContent);
        
        if (Object.keys(extractedFeatures).length > 0) {
          features.push(featuresToArray(extractedFeatures));
          labels.push(1); // 1 = Phishing
        }
      } catch (error) {
        console.warn(`Error processing phishing URL (${url}): ${error.message}`);
      }
    }
    
    // Process legitimate URLs
    console.log(`Processing ${legitimateUrls.length} legitimate URLs...`);
    for (const url of legitimateUrls) {
      try {
        const pageContent = mockLegitimatePageContent();
        const extractedFeatures = extractFeatures(url, pageContent);
        
        if (Object.keys(extractedFeatures).length > 0) {
          features.push(featuresToArray(extractedFeatures));
          labels.push(0); // 0 = Legitimate
        }
      } catch (error) {
        console.warn(`Error processing legitimate URL (${url}): ${error.message}`);
      }
    }
    
    console.log(`Total training samples: ${features.length}`);
    
    if (features.length === 0) {
      console.error('Error: No valid features extracted for training');
      return;
    }
    
    // Train the model
    const success = await phishingClassifier.train(features, labels);
    
    if (success) {
      console.log('Model training completed successfully!');
    } else {
      console.error('Model training failed.');
    }
  } catch (error) {
    console.error('Error training model:', error);
  }
}

// Execute training with file data
trainModelWithFileData();

// Export for use in other scripts
module.exports = {
  trainModelWithFileData
};