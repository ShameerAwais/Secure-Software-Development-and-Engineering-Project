/**
 * NLP Content Analyzer for Phishing Detection
 * 
 * This module uses natural language processing techniques to analyze 
 * page content for phishing indicators such as urgency language, 
 * threatening content, and brand impersonation.
 */

/**
 * Analyzes text content for phishing indicators using NLP techniques
 * @param {Object} pageContent - Content extracted from the webpage
 * @param {string} currentDomain - The domain of the current webpage
 * @returns {Object} Analysis results with indicators and confidence scores
 */
function analyzePageContent(pageContent, currentDomain) {
  // Results object to be returned
  const results = {
    nlpScore: 0,
    indicators: [],
    detectedLanguagePatterns: [],
    brandMentions: [],
    isBrandMismatch: false,
    confidence: 0.5,
  };

  try {
    if (!pageContent || !pageContent.textSample) {
      return results;
    }

    // Extract combined text from various page elements for analysis
    const combinedText = extractTextForAnalysis(pageContent);
    
    // Analyze urgency and threat language
    const urgencyAnalysis = analyzeUrgencyLanguage(combinedText);
    results.detectedLanguagePatterns.push(...urgencyAnalysis.patterns);
    
    if (urgencyAnalysis.hasUrgencyLanguage) {
      results.indicators.push('Urgent or threatening language detected');
      results.nlpScore += 25;
    }
    
    // Analyze security claims
    const securityAnalysis = analyzeSecurityClaims(combinedText);
    results.detectedLanguagePatterns.push(...securityAnalysis.patterns);
    
    if (securityAnalysis.hasExcessiveClaims) {
      results.indicators.push('Excessive security or verification claims');
      results.nlpScore += 15;
    }
    
    // Detect brand mentions and potential impersonation
    const brandAnalysis = detectBrandMentions(combinedText, pageContent.title, currentDomain);
    results.brandMentions = brandAnalysis.detectedBrands;
    results.isBrandMismatch = brandAnalysis.isBrandMismatch;
    
    if (brandAnalysis.isBrandMismatch) {
      results.indicators.push(`Brand impersonation detected: ${brandAnalysis.mismatchDetails}`);
      results.nlpScore += 30;
    }
    
    // Detect inconsistent language or poor grammar (often indicates phishing)
    const languageQuality = assessLanguageQuality(combinedText);
    
    if (languageQuality.hasPoorQuality) {
      results.indicators.push('Poor language quality or inconsistent terminology');
      results.nlpScore += 15;
      results.detectedLanguagePatterns.push(...languageQuality.examples);
    }
    
    // Calculate confidence based on volume and diversity of signals
    results.confidence = calculateConfidence(
      results.nlpScore, 
      results.indicators.length,
      combinedText.length
    );
    
    // Cap the score at 100
    results.nlpScore = Math.min(results.nlpScore, 100);
    
    return results;
  } catch (error) {
    console.error(`[NLP Analyzer] Error analyzing content: ${error.message}`);
    return results;
  }
}

/**
 * Extracts text from various page elements for comprehensive analysis
 * @param {Object} pageContent - Content object from the page
 * @returns {string} Combined text for analysis
 */
function extractTextForAnalysis(pageContent) {
  const textElements = [];
  
  // Add page text sample
  if (pageContent.textSample) {
    textElements.push(pageContent.textSample);
  }
  
  // Add page title
  if (pageContent.title) {
    textElements.push(pageContent.title);
  }
  
  // Add meta description
  if (pageContent.metaDescription) {
    textElements.push(pageContent.metaDescription);
  }
  
  // Add link texts
  if (pageContent.links && pageContent.links.length) {
    const linkTexts = pageContent.links
      .filter(link => link.text && link.text.trim().length > 0)
      .map(link => link.text.trim())
      .join(' ');
      
    if (linkTexts) {
      textElements.push(linkTexts);
    }
  }
  
  // Add form labels and placeholders
  if (pageContent.forms && pageContent.forms.length) {
    const formTexts = [];
    
    pageContent.forms.forEach(form => {
      if (form.inputs && form.inputs.length) {
        form.inputs.forEach(input => {
          if (input.placeholder) formTexts.push(input.placeholder);
          if (input.name) formTexts.push(input.name);
          if (input.id) formTexts.push(input.id);
        });
      }
    });
    
    if (formTexts.length) {
      textElements.push(formTexts.join(' '));
    }
  }
  
  // Combine all text elements
  return textElements.join(' ').toLowerCase();
}

/**
 * Analyze text for urgency and threatening language
 * @param {string} text - Combined text from the page
 * @returns {Object} Analysis results for urgency language
 */
function analyzeUrgencyLanguage(text) {
  const urgencyPatterns = [
    'urgent', 'immediately', 'right now', 'as soon as possible',
    'warning', 'alert', 'attention', 'important notice',
    'account suspended', 'account blocked', 'account limited',
    'suspicious activity', 'unauthorized access', 'security breach',
    'verification required', 'confirm your details', 'update your information',
    'failure to', 'will result in', 'consequences',
    'limited time', 'expires soon', 'deadline', 
    '24 hours', '48 hours', 'temporary hold'
  ];
  
  const detectedPatterns = [];
  
  // Check for each urgency pattern
  for (const pattern of urgencyPatterns) {
    if (text.includes(pattern)) {
      detectedPatterns.push(pattern);
    }
  }
  
  return {
    hasUrgencyLanguage: detectedPatterns.length >= 2, // Require multiple patterns for higher confidence
    patterns: detectedPatterns
  };
}

/**
 * Analyze text for excessive security claims
 * @param {string} text - Combined text from the page
 * @returns {Object} Analysis results for security claims
 */
function analyzeSecurityClaims(text) {
  const securityPatterns = [
    'secure', 'verified', 'protected', 'encrypted',
    'safe', 'trusted', 'official', 'authentic',
    'guaranteed', 'certified', 'legitimate', 'genuine',
    'security measure', 'for your protection', 'for your safety'
  ];
  
  const detectedPatterns = [];
  
  // Check for each security pattern
  for (const pattern of securityPatterns) {
    if (text.includes(pattern)) {
      detectedPatterns.push(pattern);
    }
  }
  
  return {
    hasExcessiveClaims: detectedPatterns.length >= 3, // Multiple claims may indicate overcompensation
    patterns: detectedPatterns
  };
}

/**
 * Detect brand mentions and check for domain/brand mismatches
 * @param {string} text - Combined text from the page
 * @param {string} pageTitle - Title of the webpage
 * @param {string} currentDomain - Current domain of the webpage
 * @returns {Object} Analysis of brand mentions and potential impersonation
 */
function detectBrandMentions(text, pageTitle, currentDomain) {
  // Popular brands and their legitimate domains
  const popularBrands = {
    'paypal': ['paypal.com'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office365.com', 'outlook.com'],
    'google': ['google.com', 'gmail.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.ca'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'netflix': ['netflix.com'],
    'wellsfargo': ['wellsfargo.com'],
    'chase': ['chase.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'amex': ['americanexpress.com', 'amex.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'dropbox': ['dropbox.com'],
    'yahoo': ['yahoo.com'],
    'reddit': ['reddit.com'],
    'walmart': ['walmart.com'],
    'ebay': ['ebay.com'],
    'spotify': ['spotify.com'],
    'snapchat': ['snapchat.com'],
    'venmo': ['venmo.com'],
    'cashapp': ['cash.app', 'squareup.com'],
    'zelle': ['zellepay.com'],
  };
  
  const results = {
    detectedBrands: [],
    isBrandMismatch: false,
    mismatchDetails: ''
  };
  
  // Check text for brand mentions
  for (const [brand, domains] of Object.entries(popularBrands)) {
    // Check if brand name appears in the text or title
    const inText = text.includes(brand);
    const inTitle = pageTitle && pageTitle.toLowerCase().includes(brand);
    
    if (inText || inTitle) {
      results.detectedBrands.push(brand);
      
      // Check if this is a potential domain mismatch (brand impersonation)
      const isDomainMatch = domains.some(domain => 
        currentDomain.includes(domain) || domain.includes(currentDomain)
      );
      
      if (!isDomainMatch && (inTitle || countOccurrences(text, brand) >= 2)) {
        results.isBrandMismatch = true;
        results.mismatchDetails = `${brand} mentioned but hosted on ${currentDomain}`;
      }
    }
  }
  
  return results;
}

/**
 * Assess the quality of language used on the page
 * @param {string} text - Combined text from the page
 * @returns {Object} Assessment of language quality
 */
function assessLanguageQuality(text) {
  // Common grammar errors or awkward phrasing found in phishing
  const grammarPatterns = [
    { pattern: 'please to', score: 0.7 },
    { pattern: 'kindly to', score: 0.7 },
    { pattern: 'verify you', score: 0.6 },
    { pattern: 'confirm you', score: 0.6 },
    { pattern: 'dear valued', score: 0.8 },
    { pattern: 'dear customer', score: 0.5 },
    { pattern: 'dear user', score: 0.5 },
    { pattern: 'company team', score: 0.6 },
    { pattern: 'will expired', score: 0.9 },
    { pattern: 'will suspended', score: 0.9 },
    { pattern: 'account will locked', score: 0.9 },
    { pattern: 'verify you account', score: 0.9 },
    { pattern: 'do the needful', score: 0.8 },
    { pattern: 'kindly revert', score: 0.7 }
  ];
  
  let qualityScore = 0;
  const detectedIssues = [];
  
  // Check for grammar patterns indicative of phishing
  for (const item of grammarPatterns) {
    if (text.includes(item.pattern)) {
      qualityScore += item.score;
      detectedIssues.push(item.pattern);
    }
  }
  
  // Simple readability analysis (extremely short or long sentences can be suspicious)
  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  const avgSentenceLength = sentences.reduce((sum, s) => sum + s.trim().length, 0) / 
                           (sentences.length || 1);
  
  // Extremely short average sentence length often indicates poorly written content
  if (avgSentenceLength < 10 && sentences.length > 3) {
    qualityScore += 0.5;
    detectedIssues.push('unusually short sentences');
  }
  
  // Very poor sentence structure can indicate machine translation
  if (sentences.some(s => s.trim().split(' ').length > 25)) {
    qualityScore += 0.4;
    detectedIssues.push('overly complex sentences');
  }
  
  return {
    hasPoorQuality: qualityScore >= 1.0,
    qualityScore,
    examples: detectedIssues.slice(0, 3) // Return top 3 examples at most
  };
}

/**
 * Calculate NLP confidence based on signals
 * @param {number} score - The calculated NLP score
 * @param {number} indicatorCount - Number of detected indicators
 * @param {number} textLength - Length of analyzed text
 * @returns {number} Confidence score between 0 and 1
 */
function calculateConfidence(score, indicatorCount, textLength) {
  // Base confidence from score
  let confidence = score / 100;
  
  // Adjust based on indicator diversity
  confidence *= (0.7 + (Math.min(indicatorCount, 5) / 10));
  
  // Adjust based on text volume (more text = higher potential confidence)
  const textFactor = Math.min(textLength / 500, 1);
  confidence *= (0.8 + (textFactor * 0.2));
  
  // Cap at 0.95 and ensure minimum of 0.1
  return Math.min(Math.max(confidence, 0.1), 0.95);
}

/**
 * Count occurrences of a substring in text
 * @param {string} text - Text to search within
 * @param {string} subString - Substring to count
 * @returns {number} Number of occurrences
 */
function countOccurrences(text, subString) {
  let count = 0;
  let position = text.indexOf(subString);
  
  while (position !== -1) {
    count++;
    position = text.indexOf(subString, position + 1);
  }
  
  return count;
}

module.exports = {
  analyzePageContent,
  extractTextForAnalysis,
  analyzeUrgencyLanguage,
  detectBrandMentions
};