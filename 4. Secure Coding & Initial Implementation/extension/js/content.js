/**
 * Content Script
 * 
 * This script runs in the context of web pages and analyzes content
 * for phishing indicators using advanced detection techniques:
 * 1. NLP Content Analysis - text patterns, urgency language, brand impersonation
 * 2. JavaScript Behavior Analysis - form hijacking, keylogging, redirects
 * 3. User Interaction Analysis - forced flows, deceptive UI elements
 */

// Import dependencies via variables that will be set by the scripts loaded before this one
// The background script will load behaviorAnalyzer.js and userInteractionAnalyzer.js first
const behaviorAnalyzer = window.behaviorAnalyzer || new BehaviorAnalyzer();
const userInteractionAnalyzer = window.userInteractionAnalyzer || new UserInteractionAnalyzer();

// Current tab URL
const currentUrl = window.location.href;
const currentDomain = window.location.hostname;

// Analysis results
let nlpResults = null;
let contentFeatures = null;
let analysisCompleted = false;

// Initialize analysis on page load
document.addEventListener('DOMContentLoaded', initializeAnalysis);

// In case DOMContentLoaded already fired
if (document.readyState === 'interactive' || document.readyState === 'complete') {
  initializeAnalysis();
}

/**
 * Initialize all analysis components
 */
function initializeAnalysis() {
  console.log('[PhishGuard] Initializing content analysis');
  
  // Extract page content features
  extractPageFeatures()
    .then(features => {
      contentFeatures = features;
      
      // Send content data for NLP analysis to backend
      analyzePageContent(features);
      
      // Start behavior monitoring (JS activity analysis)
      behaviorAnalyzer.startMonitoring();
      
      // Start user interaction analysis
      userInteractionAnalyzer.startMonitoring();
    });
    
  // Set up listener for messages from background script
  chrome.runtime.onMessage.addListener(handleMessages);
}

/**
 * Extract features from the current page
 * @returns {Promise<Object>} Page features
 */
async function extractPageFeatures() {
  // Extract basic page properties
  const pageTitle = document.title;
  const metaTags = extractMetaTags();
  const forms = extractFormDetails();
  const links = extractLinks();
  const textSample = extractTextSample();
  const hasLoginForm = forms.some(form => form.isLoginForm);
  const hasPasswordField = forms.some(form => 
    form.inputs && form.inputs.some(input => input.type === 'password')
  );
  
  // Security indicators
  const hasHttps = window.location.protocol === 'https:';
  const contentHasHttps = textSample.includes('https');
  const claimsSecureOrVerified = 
    textSample.includes('secure') || 
    textSample.includes('verified') || 
    textSample.includes('official');
  const hasUrgencyLanguage = 
    textSample.includes('urgent') || 
    textSample.includes('immediately') || 
    textSample.includes('warning') ||
    textSample.includes('limited time');
  
  // Collect features
  return {
    url: currentUrl,
    domain: currentDomain,
    title: pageTitle,
    metaDescription: metaTags.description,
    metaKeywords: metaTags.keywords,
    forms: forms,
    links: links,
    textSample: textSample,
    hasLoginForm: hasLoginForm,
    hasPasswordField: hasPasswordField,
    hasHttps: hasHttps,
    contentHasHttps: contentHasHttps,
    claimsSecureOrVerified: claimsSecureOrVerified,
    hasUrgencyLanguage: hasUrgencyLanguage,
    externalLinkCount: links.filter(link => link.isExternal).length,
    totalLinkCount: links.length
  };
}

/**
 * Extract meta tags information
 * @returns {Object} Meta tags content
 */
function extractMetaTags() {
  const metaTags = {
    description: '',
    keywords: ''
  };

  // Get meta description
  const descriptionTag = document.querySelector('meta[name="description"]');
  if (descriptionTag) {
    metaTags.description = descriptionTag.getAttribute('content') || '';
  }

  // Get meta keywords
  const keywordsTag = document.querySelector('meta[name="keywords"]');
  if (keywordsTag) {
    metaTags.keywords = keywordsTag.getAttribute('content') || '';
  }

  return metaTags;
}

/**
 * Extract details about forms on the page
 * @returns {Array} Forms details
 */
function extractFormDetails() {
  const forms = Array.from(document.querySelectorAll('form'));
  
  return forms.map(form => {
    // Get form inputs
    const inputs = Array.from(form.querySelectorAll('input, select, textarea'));
    
    // Process inputs
    const inputDetails = inputs.map(input => ({
      type: input.type || '',
      name: input.name || '',
      id: input.id || '',
      placeholder: input.placeholder || ''
    }));
    
    // Check if this is a login form
    const isLoginForm = inputDetails.some(input => input.type === 'password') ||
                        (form.action && form.action.toLowerCase().includes('login')) ||
                        (form.id && form.id.toLowerCase().includes('login')) ||
                        (form.className && form.className.toLowerCase().includes('login'));
    
    // External action check
    let isExternalAction = false;
    try {
      if (form.action) {
        const actionDomain = new URL(form.action, window.location.href).hostname;
        isExternalAction = actionDomain !== currentDomain;
      }
    } catch (e) {
      // URL parsing error
    }
    
    return {
      action: form.action || '',
      method: form.method || 'get',
      id: form.id || '',
      className: form.className || '',
      inputs: inputDetails,
      isLoginForm: isLoginForm,
      isExternalAction: isExternalAction
    };
  });
}

/**
 * Extract links from the page
 * @returns {Array} Links details
 */
function extractLinks() {
  const links = Array.from(document.querySelectorAll('a[href]'));
  
  return links.map(link => {
    // Check if external link
    let isExternal = false;
    let href = link.href || '';
    
    try {
      if (href) {
        const linkDomain = new URL(href).hostname;
        isExternal = linkDomain !== currentDomain;
      }
    } catch (e) {
      // URL parsing error
    }
    
    return {
      href: href,
      text: link.textContent.trim(),
      isExternal: isExternal
    };
  });
}

/**
 * Extract representative text sample from the page
 * @returns {string} Text sample
 */
function extractTextSample() {
  // Get text from important elements
  let textSample = '';
  
  // Add page title
  textSample += document.title + ' ';
  
  // Add main content text (prioritize visible text)
  const contentSelectors = [
    'main', 'article', '.content', '#content', 
    '.main', '#main', 'section', '.body', '#body'
  ];
  
  // Try each selector to find main content
  for (const selector of contentSelectors) {
    const element = document.querySelector(selector);
    if (element) {
      textSample += element.innerText + ' ';
      break;
    }
  }
  
  // If no main content found, get text from body
  if (textSample.length < 100) {
    // Extract visible text while avoiding scripts, styles, etc.
    const visibleTextNodes = [];
    const walk = document.createTreeWalker(
      document.body, 
      NodeFilter.SHOW_TEXT, 
      { 
        acceptNode: function(node) { 
          // Filter out script, style, and other non-content nodes
          if (!node.parentElement || 
              ['SCRIPT', 'STYLE', 'NOSCRIPT', 'IFRAME', 'TEMPLATE'].includes(node.parentElement.tagName)) {
            return NodeFilter.FILTER_REJECT;
          }
          // Only include visible text
          if (node.textContent.trim().length > 0) {
            return NodeFilter.FILTER_ACCEPT;
          }
          return NodeFilter.FILTER_SKIP;
        } 
      }
    );
    
    // Collect visible text nodes
    while (walk.nextNode()) {
      visibleTextNodes.push(walk.currentNode);
    }
    
    // Add visible text to the sample (limit to first 50 nodes)
    const sampleNodes = visibleTextNodes.slice(0, 50);
    for (const node of sampleNodes) {
      const text = node.textContent.trim();
      if (text) {
        textSample += text + ' ';
      }
    }
  }
  
  // Limit to reasonable size (first 5000 chars)
  return textSample.slice(0, 5000).trim().toLowerCase();
}

/**
 * Send page content to backend for NLP analysis
 * @param {Object} features - Page content features
 */
function analyzePageContent(features) {
  chrome.runtime.sendMessage({
    action: 'analyzePageContent',
    data: {
      url: features.url,
      domain: features.domain,
      title: features.title,
      metaDescription: features.metaDescription,
      textSample: features.textSample,
      forms: features.forms,
      links: features.links
    }
  }, response => {
    if (response && response.nlpResults) {
      nlpResults = response.nlpResults;
      
      // Once we have NLP results, complete the analysis
      completeAnalysis();
    }
  });
}

/**
 * Complete the analysis by combining all signals
 */
function completeAnalysis() {
  if (analysisCompleted) return;
  
  // Get behavior analysis
  const behaviorResults = behaviorAnalyzer.getBehaviorAnalysis();
  
  // Get user interaction analysis
  const interactionResults = userInteractionAnalyzer.getAnalysisResults();
  
  // Combine all signals for comprehensive analysis
  const combinedAnalysis = {
    url: currentUrl,
    domain: currentDomain,
    nlp: nlpResults || { nlpScore: 0, indicators: [], confidence: 0 },
    behavior: behaviorResults,
    interaction: interactionResults,
    timestamp: Date.now()
  };
  
  // Calculate combined phishing probability
  const nlpWeight = nlpResults ? 0.4 : 0;
  const behaviorWeight = 0.35;
  const interactionWeight = 0.25;
  
  const combinedScore = Math.round(
    (nlpResults ? (nlpResults.nlpScore * nlpWeight) : 0) +
    (behaviorResults.behaviorScore * behaviorWeight) +
    (interactionResults.interactionScore * interactionWeight)
  );
  
  combinedAnalysis.combinedScore = combinedScore;
  combinedAnalysis.isLikelyPhishing = combinedScore >= 70;
  
  // Mark analysis as complete
  analysisCompleted = true;
  
  // Send combined results to background script
  chrome.runtime.sendMessage({
    action: 'reportCombinedAnalysis',
    data: combinedAnalysis
  });
  
  console.log('[PhishGuard] Analysis completed:', combinedAnalysis);
}

/**
 * Handle messages from background script
 * @param {Object} message - Message data
 * @param {Object} sender - Message sender
 * @param {Function} sendResponse - Response function
 */
function handleMessages(message, sender, sendResponse) {
  if (message.action === 'getPageFeatures') {
    sendResponse({ features: contentFeatures });
  }
  else if (message.action === 'nlpResultsReady') {
    nlpResults = message.data;
    completeAnalysis();
  }
}

// Report recurring analyses periodically
setInterval(() => {
  // Only run if analysis was already completed once
  if (analysisCompleted) {
    // Get updated behavior analysis
    const behaviorResults = behaviorAnalyzer.getBehaviorAnalysis();
    
    // Get updated user interaction analysis
    const interactionResults = userInteractionAnalyzer.getAnalysisResults();
    
    // Send updates if significant changes detected
    if (behaviorResults.behaviorScore > 50 || interactionResults.interactionScore > 50) {
      chrome.runtime.sendMessage({
        action: 'reportAnalysisUpdate',
        data: {
          behavior: behaviorResults,
          interaction: interactionResults,
          timestamp: Date.now()
        }
      });
    }
  }
}, 15000); // Check every 15 seconds
