/**
 * Phishing Detection Engine
 * 
 * This module now only analyzes page content for phishing indicators.
 * URL scanning is handled exclusively by Google Safe Browsing API.
 */

const axios = require('axios');
const { parse } = require('url');
const dns = require('dns');
const util = require('util');

// Promisify DNS functions
const dnsLookup = util.promisify(dns.lookup);
const dnsReverse = util.promisify(dns.reverse);

// Constants for scoring
const PHISHING_THRESHOLD = 70; // Score above which a URL is considered phishing
const MAX_SCORE = 100;

/**
 * Main function to analyze a URL for phishing indicators
 * Now only analyzes page content, not URL structure
 * @param {string} url - The URL to analyze
 * @param {Object} safeBrowsingResult - Result from Google Safe Browsing API
 * @param {Object} pageContent - Optional page content from browser for analysis
 * @returns {Object} Analysis results including phishing score and indicators
 */
async function analyzeUrl(url, safeBrowsingResult = null, pageContent = null) {
  try {
    console.log(`[Phishing Engine] Analyzing content from: ${url}`);
    
    const parsedUrl = new URL(url);
    const indicators = [];
    let totalScore = 0;
    
    // Only use Google Safe Browsing result for URL safety
    // Don't perform our own URL analysis
    
    // Google Safe Browsing integration - this is the only URL-based check we'll use
    const safeBrowsingScore = integrateSafeBrowsingResult(safeBrowsingResult);
    totalScore += safeBrowsingScore.score;
    indicators.push(...safeBrowsingScore.indicators);
    
    // Page content analysis (if available)
    let contentResult = { score: 0, indicators: [] };
    if (pageContent && !pageContent.error) {
      contentResult = analyzePageContent(pageContent, parsedUrl.hostname);
      totalScore += contentResult.score;
      indicators.push(...contentResult.indicators);
    }
    
    // Normalize score to 0-100 range
    totalScore = Math.min(Math.round(totalScore), MAX_SCORE);
    
    // Final verdict - now based only on Google Safe Browsing and content analysis
    // If Safe Browsing says it's unsafe, it's unsafe regardless of content score
    const isPhishing = (safeBrowsingResult && !safeBrowsingResult.isSafe) || 
                       (contentResult.score >= PHISHING_THRESHOLD);
    
    return {
      url,
      phishingScore: totalScore,
      isPhishing,
      phishingIndicators: indicators,
      contentAnalysis: pageContent ? {
        hasLoginForm: contentResult.hasLoginForm || false,
        contentScore: contentResult.score || 0,
        brandMismatch: contentResult.brandMismatch || false
      } : null,
      safeBrowsingVerdict: safeBrowsingResult ? !safeBrowsingResult.isSafe : null
    };
  } catch (error) {
    console.error(`[Phishing Engine] Error analyzing URL: ${error.message}`);
    return {
      url,
      phishingScore: 0,
      isPhishing: safeBrowsingResult ? !safeBrowsingResult.isSafe : false,
      phishingIndicators: [`Error during analysis: ${error.message}`],
      error: true
    };
  }
}

/**
 * Integrate Google Safe Browsing API results into phishing score
 * @param {Object} safeBrowsingResult - Result from Google Safe Browsing API
 * @returns {Object} Safe Browsing analysis integration
 */
function integrateSafeBrowsingResult(safeBrowsingResult) {
  const indicators = [];
  let score = 0;
  
  if (!safeBrowsingResult) {
    return { score: 0, indicators: [] };
  }
  
  // If Google Safe Browsing explicitly flags as unsafe
  if (safeBrowsingResult.isSafe === false) {
    const threatType = safeBrowsingResult.threatType || "Unknown threat";
    indicators.push(`Google Safe Browsing detection: ${threatType}`);
    score += 100; // Max score for confirmed threats
  }
  
  return {
    score,
    indicators
  };
}

/**
 * Analyze page content for phishing indicators
 * @param {Object} pageContent - Content object extracted from the web page
 * @param {string} currentDomain - The domain of the URL being analyzed
 * @returns {Object} Content analysis results
 */
function analyzePageContent(pageContent, currentDomain) {
  const indicators = [];
  let score = 0;
  let hasLoginForm = false;
  let brandMismatch = false;
  
  try {
    console.log("[Content Analysis] Analyzing page content for phishing indicators");
    
    // 1. Check for login forms and their security
    if (pageContent.forms && pageContent.forms.length > 0) {
      // Look for login forms
      const loginForms = pageContent.forms.filter(form => form.isLoginForm);
      
      if (loginForms.length > 0) {
        hasLoginForm = true;
        console.log(`[Content Analysis] Found ${loginForms.length} login forms`);
        
        // Check login form security
        for (const form of loginForms) {
          try {
            // Check if form submits via HTTP instead of HTTPS
            if (form.action && form.action.startsWith('http:')) {
              indicators.push('Login form submits credentials via unencrypted connection');
              score += 30;
            }
            
            // Check if form submits to external domain
            if (form.action) {
              try {
                const formActionDomain = new URL(form.action).hostname;
                
                if (formActionDomain !== currentDomain) {
                  indicators.push(`Login form submits data to external domain (${formActionDomain})`);
                  score += 30;
                }
              } catch (e) {
                console.error("[Content Analysis] Error parsing form action URL:", e.message);
              }
            }
          } catch (e) {
            console.error("[Content Analysis] Error analyzing form:", e.message);
          }
        }
      }
    }
    
    // 2. Check for page with login form but no HTTPS
    if (hasLoginForm && !pageContent.hasHttps) {
      indicators.push('Login form on page without HTTPS encryption');
      score += 30;
    }
    
    // 3. Check for brand impersonation based on page title and content
    if (pageContent.title) {
      const popularBrands = {
        'paypal': ['paypal.com'],
        'apple': ['apple.com', 'icloud.com'],
        'microsoft': ['microsoft.com', 'live.com', 'office365.com'],
        'google': ['google.com', 'gmail.com'],
        'amazon': ['amazon.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'instagram': ['instagram.com'],
        'netflix': ['netflix.com'],
        'wellsfargo': ['wellsfargo.com'],
        'chase': ['chase.com'],
        'bankofamerica': ['bankofamerica.com'],
        'amex': ['americanexpress.com']
      };
      
      const title = pageContent.title.toLowerCase();
      
      // Check each brand for potential impersonation
      for (const [brand, domains] of Object.entries(popularBrands)) {
        if (title.includes(brand)) {
          // Title includes a brand name - check if domain matches expected domain
          const isDomainMatch = domains.some(domain => currentDomain.includes(domain));
          
          if (!isDomainMatch) {
            indicators.push(`Page claims to be ${brand} but is hosted on ${currentDomain}`);
            score += 30;
            brandMismatch = true;
          }
        }
      }
    }
    
    // 4. Look for urgent language (common in phishing)
    if (pageContent.hasUrgencyLanguage) {
      indicators.push('Page contains urgent or alarming language typical of phishing attempts');
      score += 15;
    }
    
    // 5. Check for excessive security claims on suspicious sites
    if (pageContent.claimsSecureOrVerified && (score > 20 || brandMismatch)) {
      indicators.push('Page makes excessive security or verification claims');
      score += 10;
    }
    
    // 6. Analyze links on the page
    if (pageContent.links && pageContent.links.length > 0) {
      let externalLinks = 0;
      
      for (const link of pageContent.links) {
        if (link.isExternal) {
          externalLinks++;
        }
      }
      
      // Check for high ratio of external links
      const externalRatio = externalLinks / pageContent.links.length;
      if (externalRatio > 0.7 && pageContent.links.length > 5) {
        indicators.push(`High ratio of external links (${Math.round(externalRatio * 100)}%)`);
        score += 15;
      }
    }
    
    // 7. Check for password fields with suspicious attributes
    if (pageContent.forms && pageContent.forms.length > 0) {
      for (const form of pageContent.forms) {
        // Look for hidden password fields or other suspicious input patterns
        const passwordFields = form.inputs.filter(input => input.type === 'password');
        
        if (passwordFields.length > 1) {
          indicators.push('Multiple password fields in a single form (unusual behavior)');
          score += 15;
        }
      }
    }
    
    return {
      score,
      indicators,
      hasLoginForm,
      brandMismatch
    };
  } catch (error) {
    console.error(`[Content Analysis] Error: ${error.message}`);
    return {
      score: 0,
      indicators: [`Error analyzing page content: ${error.message}`],
      error: true
    };
  }
}

module.exports = {
  analyzeUrl,
  PHISHING_THRESHOLD
};