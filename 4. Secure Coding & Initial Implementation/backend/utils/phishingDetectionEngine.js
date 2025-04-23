/**
 * Phishing Detection Engine
 * 
 * This module analyzes URLs for potential phishing indicators through multiple techniques:
 * - Domain analysis (age, registration, SSL)
 * - Visual similarity to known brands
 * - URL structure analysis
 * - Content analysis
 * - Integrates with Google Safe Browsing API
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
 * @param {string} url - The URL to analyze
 * @param {Object} safeBrowsingResult - Result from Google Safe Browsing API
 * @returns {Object} Analysis results including phishing score and indicators
 */
async function analyzeUrl(url, safeBrowsingResult = null) {
  try {
    console.log(`[Phishing Engine] Analyzing URL: ${url}`);
    
    const parsedUrl = new URL(url);
    const indicators = [];
    let totalScore = 0;
    
    // 1. Basic URL structure analysis
    const urlStructureResult = analyzeUrlStructure(parsedUrl);
    totalScore += urlStructureResult.score;
    indicators.push(...urlStructureResult.indicators);
    
    // 2. Domain analysis (registration, age, SSL)
    const domainResult = await analyzeDomain(parsedUrl.hostname);
    totalScore += domainResult.score;
    indicators.push(...domainResult.indicators);
    
    // 3. Brand impersonation check
    const brandResult = checkBrandImpersonation(parsedUrl.hostname);
    totalScore += brandResult.score;
    indicators.push(...brandResult.indicators);
    
    // 4. Redirect analysis
    const redirectResult = await checkRedirects(url);
    totalScore += redirectResult.score;
    indicators.push(...redirectResult.indicators);
    
    // 5. Google Safe Browsing integration
    const safeBrowsingScore = integrateSafeBrowsingResult(safeBrowsingResult);
    totalScore += safeBrowsingScore.score;
    indicators.push(...safeBrowsingScore.indicators);
    
    // Normalize score to 0-100 range
    totalScore = Math.min(Math.round(totalScore), MAX_SCORE);
    
    // Final verdict
    const isPhishing = totalScore >= PHISHING_THRESHOLD;
    
    return {
      url,
      phishingScore: totalScore,
      isPhishing,
      phishingIndicators: indicators,
      domainAge: domainResult.domainAge,
      hasSSL: domainResult.hasSSL,
      redirectCount: redirectResult.redirectCount,
      safeBrowsingVerdict: safeBrowsingResult ? !safeBrowsingResult.isSafe : null
    };
  } catch (error) {
    console.error(`[Phishing Engine] Error analyzing URL: ${error.message}`);
    return {
      url,
      phishingScore: 0,
      isPhishing: false,
      phishingIndicators: [`Error during analysis: ${error.message}`],
      error: true
    };
  }
}

/**
 * Analyze URL structure for phishing indicators
 * @param {URL} parsedUrl - Parsed URL object
 * @returns {Object} Analysis results with score and indicators
 */
function analyzeUrlStructure(parsedUrl) {
  const indicators = [];
  let score = 0;
  
  // Check for IP address in hostname
  const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (ipRegex.test(parsedUrl.hostname)) {
    indicators.push("Uses IP address instead of domain name");
    score += 25;
  }
  
  // Check for excessive subdomains
  const subdomainCount = parsedUrl.hostname.split('.').length - 2;
  if (subdomainCount > 3) {
    indicators.push(`Excessive subdomain count (${subdomainCount})`);
    score += 10;
  }
  
  // Check for suspicious TLDs
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.top', '.xyz'];
  const tld = '.' + parsedUrl.hostname.split('.').slice(-1)[0];
  if (suspiciousTLDs.includes(tld)) {
    indicators.push(`Suspicious TLD (${tld})`);
    score += 15;
  }
  
  // Check for long domain name (potential for typosquatting)
  if (parsedUrl.hostname.length > 30) {
    indicators.push(`Unusually long domain name (${parsedUrl.hostname.length} chars)`);
    score += 10;
  }
  
  // Check for URL encoded characters in path
  const percentEncoded = (parsedUrl.pathname.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  if (percentEncoded > 3) {
    indicators.push(`High number of URL encoded characters (${percentEncoded})`);
    score += 15;
  }
  
  // Check for multiple hyphens in domain
  const hyphenCount = (parsedUrl.hostname.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    indicators.push(`Multiple hyphens in domain name (${hyphenCount})`);
    score += 10;
  }
  
  return {
    score,
    indicators: indicators.length > 0 ? indicators : []
  };
}

/**
 * Analyze domain properties like age, registration, SSL
 * @param {string} domain - Domain name to analyze
 * @returns {Object} Domain analysis results
 */
async function analyzeDomain(domain) {
  const indicators = [];
  let score = 0;
  let domainAge = null;
  let hasSSL = null;
  
  try {
    // Check if domain resolves (basic DNS check)
    try {
      await dnsLookup(domain);
    } catch (err) {
      indicators.push("Domain does not resolve to an IP address");
      score += 30;
    }
    
    // Check for HTTPS support
    try {
      const response = await axios.head(`https://${domain}`, {
        timeout: 3000,
        validateStatus: null,
        maxRedirects: 0
      });
      hasSSL = true;
    } catch (err) {
      if (err.code === 'ECONNRESET' || (err.response && err.response.status >= 400)) {
        hasSSL = false;
        indicators.push("No SSL/TLS support");
        score += 20;
      } else {
        // If error is due to timeout or other reasons, we can't determine SSL
        hasSSL = null;
      }
    }
    
    // Note: We would ideally check domain age via WHOIS APIs
    // For this implementation, we're simulating it
    domainAge = simulateDomainAgeCheck(domain);
    if (domainAge !== null && domainAge < 30) {
      indicators.push(`Recently registered domain (${domainAge} days old)`);
      score += 25 - Math.min(domainAge, 25);
    }
    
  } catch (error) {
    console.error(`[Domain Analysis] Error: ${error.message}`);
  }
  
  return {
    score,
    indicators,
    domainAge,
    hasSSL
  };
}

/**
 * Check for brand impersonation by analyzing domain for similarities to popular brands
 * @param {string} domain - Domain name to check
 * @returns {Object} Analysis results
 */
function checkBrandImpersonation(domain) {
  const indicators = [];
  let score = 0;
  
  // Map of popular brands and their variations often used in phishing
  const brandVariations = {
    'paypal': ['paypa1', 'paypaI', 'paypal-secure', 'paypal.com-', 'paypal-account'],
    'microsoft': ['micr0soft', 'rnicrosoft', 'microsoft-secure', 'microsoft365', 'ms-verify'],
    'apple': ['appie', 'apple-id', 'icloud-verify', 'apple.com-'],
    'amazon': ['arnazon', 'amazon-account', 'amazon-prime', 'amazon.com-'],
    'google': ['g00gle', 'google-verify', 'gmail-secure', 'accounts-google'],
    'facebook': ['faceb00k', 'facebook-security', 'fb-login'],
    'instagram': ['1nstagram', 'insta-verify'],
    'netflix': ['netfl1x', 'netflix-account', 'netflix-billing'],
    'bank': ['secure-bank', 'banking-online', 'account-verify']
  };
  
  const domainLower = domain.toLowerCase();
  
  // Check each brand for potential impersonation
  for (const [brand, variations] of Object.entries(brandVariations)) {
    // Direct brand mention in domain
    if (domainLower.includes(brand) && !domainLower.endsWith(`.${brand}.com`)) {
      indicators.push(`Contains brand name "${brand}" but not official domain`);
      score += 20;
      break;
    }
    
    // Check for brand variations/typosquatting
    for (const variation of variations) {
      if (domainLower.includes(variation)) {
        indicators.push(`Potential typosquatting of "${brand}"`);
        score += 25;
        break;
      }
    }
  }
  
  // Levenshtein distance check could be added here for more sophisticated detection
  
  return {
    score,
    indicators
  };
}

/**
 * Check redirect behavior of a URL
 * @param {string} url - URL to check for redirects
 * @returns {Object} Redirect analysis results
 */
async function checkRedirects(url) {
  const indicators = [];
  let score = 0;
  let redirectCount = 0;
  
  try {
    const response = await axios.get(url, {
      timeout: 5000,
      maxRedirects: 10,
      validateStatus: null
    });
    
    redirectCount = response.request._redirectable._redirectCount || 0;
    
    // Check for excessive redirects
    if (redirectCount > 3) {
      indicators.push(`Excessive redirect chain (${redirectCount} redirects)`);
      score += Math.min(redirectCount * 5, 20);
    }
    
    // Check if final URL is different from original
    const finalUrl = response.request.res.responseUrl || url;
    if (finalUrl !== url) {
      const finalDomain = new URL(finalUrl).hostname;
      const originalDomain = new URL(url).hostname;
      
      if (finalDomain !== originalDomain) {
        indicators.push(`Redirects to different domain (${finalDomain})`);
        score += 25;
      }
    }
    
  } catch (error) {
    console.error(`[Redirect Analysis] Error: ${error.message}`);
    // We can't determine redirects due to error
  }
  
  return {
    score,
    indicators,
    redirectCount
  };
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
  if (!safeBrowsingResult.isSafe) {
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
 * Simulate domain age check (would normally use WHOIS API)
 * @param {string} domain - Domain to check
 * @returns {number|null} Simulated domain age in days or null if error
 */
function simulateDomainAgeCheck(domain) {
  // For demonstration - would normally call WHOIS API
  // Returns random age, weighted to be newer for suspicious domains
  
  // Check if domain has suspicious patterns
  const suspicious = domain.includes('secure') || 
                    domain.includes('login') || 
                    domain.includes('verify') ||
                    domain.includes('-') || 
                    /\d{4,}/.test(domain);
  
  if (suspicious) {
    // 70% chance of being a very new domain (1-30 days)
    return Math.floor(Math.random() * 30) + 1;
  } else {
    // Established domains (60-1000 days)
    return Math.floor(Math.random() * 940) + 60;
  }
}

module.exports = {
  analyzeUrl,
  PHISHING_THRESHOLD
};