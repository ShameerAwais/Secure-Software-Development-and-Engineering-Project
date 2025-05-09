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
  
  // Enhanced security checks based on improved form detection
  const hasSuspiciousForm = forms.some(form => form.isSuspiciousForm);
  const hasExternalFormAction = forms.some(form => form.isExternalAction && form.isLoginForm);
  const hasUnsecuredLoginForm = forms.some(form => 
    form.isLoginForm && form.action && form.action.startsWith('http:')
  );
  
  // Check for Brazilian document forms (CPF phishing)
  const hasCpfForm = forms.some(form => form.hasCpfField);
  const hasConsultaText = forms.some(form => form.hasConsultaText);
  const hasDocumentVerificationForm = forms.some(form => form.isDocumentVerificationForm);
  
  // Detect CPF input fields outside forms (common in simple phishing pages)
  const hasCpfInputsOutsideForms = document.querySelectorAll('input[name*="cpf"], input[placeholder*="cpf"], input[id*="cpf"]').length > 0;
  
  // Security indicators
  const hasHttps = window.location.protocol === 'https:';
  const isHttp = window.location.protocol === 'http:';
  const contentHasHttps = textSample.includes('https');
  const claimsSecureOrVerified = 
    textSample.includes('secure') || 
    textSample.includes('verified') || 
    textSample.includes('official');
  const hasUrgencyLanguage = 
    textSample.includes('urgent') || 
    textSample.includes('immediately') || 
    textSample.includes('warning') ||
    textSample.includes('limited time') ||
    textSample.includes('alert') ||
    textSample.includes('attention required') ||
    textSample.includes('action needed');
  
  // Brand impersonation check
  const commonBrands = [
    'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix', 
    'instagram', 'xfinity', 'comcast', 'chase', 'bankofamerica', 'wellsfargo', 
    'linkedin', 'twitter', 'gmail', 'outlook', 'yahoo', 'dropbox', 'icloud', 
    'hotmail', 'office365', 'citibank', 'capitalone', 'amex', 'americanexpress',
    'discord', 'spotify', 'walmart', 'target', 'usps', 'fedex', 'ups', 'dhl',
    'ebay', 'venmo', 'zelle', 'coinbase', 'binance', 'myetherwallet', 'blockchain',
    // Adding health insurance and payment providers
    'notredame', 'intermedica', 'unimed', 'amil', 'bradesco', 'itau', 'santander',
    'banco', 'caixa', 'bank', 'bbva', 'scotiabank', 'hsbc',
    // Adding Brazilian financial services often phished
    'nubank', 'inter', 'c6bank', 'next', 'picpay', 'neon', 'digio'
  ];

  // Check title and content for brand mentions
  const brandMentions = commonBrands.filter(brand => 
    pageTitle.toLowerCase().includes(brand) || 
    textSample.toLowerCase().includes(brand)
  );
  
  // Check for Nubank specifically (common Brazilian phishing target)
  const mentionsNubank = brandMentions.includes('nubank') || 
                         pageTitle.toLowerCase().includes('nu') || 
                         textSample.toLowerCase().includes('nu ') ||
                         document.documentElement.innerHTML.toLowerCase().includes('nubank');
  
  // Check URL for brand mentions but not matching hostname
  const brandInContentButNotDomain = brandMentions.some(brand => 
    !currentDomain.includes(brand) && 
    (pageTitle.toLowerCase().includes(brand) || textSample.toLowerCase().includes(brand))
  );
  
  // Check for numbers in domain - common pattern in phishing
  const hasNumbersInDomain = /\d+/.test(currentDomain);
  
  // Check for specific phishing patterns - domains with brand + numbers
  const hasBrandWithNumbers = commonBrands.some(brand => {
    const pattern = new RegExp(`${brand}\\d+`, 'i');
    return pattern.test(currentDomain);
  });
  
  // Check for suspicious free hosting patterns
  const freeHostingServices = [
    'weebly.com', 'wix.com', 'blogspot.com', 'wordpress.com', 'site123.com',
    'webnode.com', 'glitch.me', 'netlify.app', 'pages.dev', 'github.io',
    'vercel.app', 'herokuapp.com', 'repl.co', '000webhostapp.com', 'webs.com',
    'yolasite.com', 'strikingly.com', 'carrd.co', 'squarespace.com', 'azurewebsites.net',
    'firebaseapp.com', 'web.app', 'surge.sh', 'gitlab.io', 'bitbucket.io', 
    'neocities.org', 'tumblr.com', 'hubspot.com', 'shutterfly.com', 'godaddysites.com'
  ];
  
  const isOnFreeHosting = freeHostingServices.some(service => currentDomain.endsWith(service));
  
  // Brand on free hosting (high-risk indicator)
  const brandOnFreeHosting = isOnFreeHosting && brandMentions.length > 0;
  
  // Check for deceptive domain patterns
  const deceptiveDomainPatterns = [
    /secure.*login/i,
    /verify.*account/i,
    /confirm.*identity/i,
    /update.*billing/i,
    /authenticate.*user/i
  ];
  
  const hasDeceptiveDomainPattern = deceptiveDomainPatterns.some(pattern => 
    pattern.test(currentDomain)
  );
  
  // Check for excessive subdomain use (common in phishing)
  const subdomainCount = currentDomain.split('.').length - 1;
  const hasExcessiveSubdomains = subdomainCount > 3;
  
  // Suspicious security indicators
  const hasLockIconInContent = document.documentElement.innerHTML.includes('🔒') || 
                               document.documentElement.innerHTML.includes('lock') ||
                               document.documentElement.innerHTML.includes('secure');
  
  // Phishy URL/content mismatch
  const hasMismatchedContent = links.some(link => {
    // Check for links that claim to go somewhere but actually go elsewhere
    if (!link.text || !link.href) return false;
    
    for (const brand of commonBrands) {
      if (link.text.toLowerCase().includes(brand) && 
          link.href && !link.href.includes(brand)) {
        return true;
      }
    }
    return false;
  });
  
  // Payment portal phishing detection - Check for specific payment-related content
  const paymentRelatedTerms = [
    'boleto', 'segunda via', '2via', 'emitir', 'factura', 'fatura', 'pagar', 
    'pagamento', 'payment', 'bill', 'invoice', 'portal', 'cliente', 'customer'
  ];
  
  const containsPaymentTerms = paymentRelatedTerms.some(term => 
    textSample.toLowerCase().includes(term.toLowerCase()) || 
    pageTitle.toLowerCase().includes(term.toLowerCase())
  );
  
  // Check for button text that suggests payment actions
  const paymentButtonsCount = Array.from(document.querySelectorAll('button, a.button, .btn, input[type="button"], input[type="submit"]'))
    .filter(el => {
      const text = el.textContent.toLowerCase() || el.value?.toLowerCase() || '';
      return paymentRelatedTerms.some(term => text.includes(term.toLowerCase()));
    }).length;
  
  // Detect if page looks like a payment portal but isn't on a legitimate domain
  const isLegitimatePortal = 
    currentDomain.endsWith('bb.com.br') || 
    currentDomain.endsWith('caixa.gov.br') || 
    currentDomain.endsWith('bradesco.com.br') ||
    currentDomain.endsWith('santander.com.br') ||
    currentDomain.endsWith('itau.com.br') ||
    currentDomain.endsWith('notredameintermedica.com.br') ||
    currentDomain.endsWith('amil.com.br') ||
    currentDomain.endsWith('unimed.com.br') ||
    currentDomain.endsWith('paypal.com') ||
    currentDomain.endsWith('stripe.com') ||
    currentDomain.endsWith('nubank.com.br');
  
  // Looks like payment portal but isn't legitimate domain
  const looksLikePaymentPortal = containsPaymentTerms && !isLegitimatePortal;
  
  // Check for bank logos on non-bank domains (common in phishing)
  const hasBankLogos = document.documentElement.innerHTML.toLowerCase().includes('bank logo') ||
                       document.documentElement.innerHTML.toLowerCase().includes('logo banco') ||
                       document.documentElement.innerHTML.toLowerCase().includes('bradesco') ||
                       document.documentElement.innerHTML.toLowerCase().includes('santander') ||
                       document.documentElement.innerHTML.toLowerCase().includes('notredame') ||
                       document.documentElement.innerHTML.toLowerCase().includes('intermedica');
  
  // Payment impersonation on unofficial domain
  const hasPaymentImpersonation = (hasBankLogos || looksLikePaymentPortal) && !isLegitimatePortal;
  
  // Check for Boleto/Invoice words in HTML
  const boletoRelatedWords = ['boleto', 'invoice', 'fatura', 'payment', 'emitir', 'segunda via', '2via'];
  const hasBoletoContent = boletoRelatedWords.some(word => 
    document.documentElement.innerHTML.toLowerCase().includes(word.toLowerCase())
  );
  
  // Common misspellings that indicate phishing (especially in Portuguese)
  const hasMisspelledSupport = currentDomain.includes('suport') && !currentDomain.includes('support');
  
  // Specific Brazilian document verification phishing checks
  const brazilianDocumentTerms = [
    'cpf', 'consulta', 'consulte', 'verificar', 'consultar',
    'indenização', 'indenizacao', 'restituição', 'restituicao',
    'beneficio', 'benefício', 'auxilio', 'auxílio'
  ];
  
  const containsBrazilianDocTerms = brazilianDocumentTerms.some(term => 
    textSample.toLowerCase().includes(term) || 
    pageTitle.toLowerCase().includes(term) ||
    document.documentElement.innerHTML.toLowerCase().includes(term)
  );
  
  // Check for simplified phishing page layout (common in Brazilian phishing)
  const hasSimplifiedLayout = 
    document.querySelectorAll('form, input, button').length > 0 && 
    document.querySelectorAll('a').length < 5 && 
    document.querySelectorAll('img').length < 3;
  
  // Check if this is clearly a Nubank phishing page
  const isNubankPhishingPage = 
    mentionsNubank && 
    (hasCpfForm || hasCpfInputsOutsideForms || containsBrazilianDocTerms) && 
    !currentDomain.endsWith('nubank.com.br');
  
  // Log security issues for debugging
  console.log('[PhishGuard] Security check:', {
    url: currentUrl,
    isHttp,
    hasHttps,
    hasLoginForm,
    hasPasswordField,
    hasSuspiciousForm,
    hasExternalFormAction,
    hasUnsecuredLoginForm,
    brandMentions,
    brandInContentButNotDomain,
    hasNumbersInDomain,
    hasBrandWithNumbers,
    isOnFreeHosting,
    brandOnFreeHosting,
    hasDeceptiveDomainPattern,
    hasExcessiveSubdomains,
    hasMismatchedContent,
    looksLikePaymentPortal,
    hasBankLogos,
    hasPaymentImpersonation,
    hasBoletoContent,
    hasMisspelledSupport,
    hasCpfForm,
    hasConsultaText,
    isNubankPhishingPage
  });
  
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
    hasSuspiciousForm: hasSuspiciousForm,
    hasExternalFormAction: hasExternalFormAction,
    hasUnsecuredLoginForm: hasUnsecuredLoginForm,
    hasHttps: hasHttps,
    isHttp: isHttp,
    contentHasHttps: contentHasHttps,
    claimsSecureOrVerified: claimsSecureOrVerified,
    hasUrgencyLanguage: hasUrgencyLanguage,
    externalLinkCount: links.filter(link => link.isExternal).length,
    totalLinkCount: links.length,
    // New phishing indicators
    brandMentions: brandMentions,
    brandInContentButNotDomain: brandInContentButNotDomain,
    hasNumbersInDomain: hasNumbersInDomain,
    hasBrandWithNumbers: hasBrandWithNumbers,
    isOnFreeHosting: isOnFreeHosting,
    brandOnFreeHosting: brandOnFreeHosting,
    hasDeceptiveDomainPattern: hasDeceptiveDomainPattern,
    hasExcessiveSubdomains: hasExcessiveSubdomains,
    hasLockIconInContent: hasLockIconInContent,
    hasMismatchedContent: hasMismatchedContent,
    // Payment portal phishing indicators
    looksLikePaymentPortal: looksLikePaymentPortal,
    hasBankLogos: hasBankLogos,
    hasPaymentImpersonation: hasPaymentImpersonation,
    hasBoletoContent: hasBoletoContent,
    hasMisspelledSupport: hasMisspelledSupport,
    containsPaymentTerms: containsPaymentTerms,
    paymentButtonsCount: paymentButtonsCount,
    // Brazilian document phishing indicators
    hasCpfForm: hasCpfForm,
    hasConsultaText: hasConsultaText,
    hasDocumentVerificationForm: hasDocumentVerificationForm,
    hasCpfInputsOutsideForms: hasCpfInputsOutsideForms,
    containsBrazilianDocTerms: containsBrazilianDocTerms,
    hasSimplifiedLayout: hasSimplifiedLayout,
    mentionsNubank: mentionsNubank,
    isNubankPhishingPage: isNubankPhishingPage
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
 * Extract forms from the page with enhanced detection for CPF inputs and Brazilian-style phishing forms
 * @returns {Array} Forms details
 */
function extractFormDetails() {
  const forms = Array.from(document.querySelectorAll('form'));
  
  // Also look for form-like div structures (common in phishing that doesn't use actual forms)
  const formLikeStructures = Array.from(document.querySelectorAll('div:has(input), div:has(button)'))
    .filter(div => {
      const inputs = div.querySelectorAll('input');
      const buttons = div.querySelectorAll('button, a.button, .btn, input[type="button"], input[type="submit"]');
      return inputs.length > 0 && buttons.length > 0;
    });
  
  // Check for CPF input fields across the entire page (not just in forms)
  const hasCpfInputsOutsideForms = document.querySelectorAll('input[name*="cpf"], input[placeholder*="cpf"], input[id*="cpf"]').length > 0;
  
  // Combine all form-like structures
  const allFormStructures = [...forms, ...formLikeStructures];
  
  return allFormStructures.map(form => {
    // Get form inputs
    const inputs = Array.from(form.querySelectorAll('input, select, textarea'));
    
    // Process inputs
    const inputDetails = inputs.map(input => ({
      type: input.type || '',
      name: input.name || '',
      id: input.id || '',
      placeholder: input.placeholder || ''
    }));
    
    // Check for Brazilian-specific inputs (CPF, etc.)
    const hasCpfField = inputDetails.some(input => 
      input.name?.toLowerCase().includes('cpf') || 
      input.id?.toLowerCase().includes('cpf') || 
      input.placeholder?.toLowerCase().includes('cpf')
    );
    
    // Check for verification/consultation language specific to Brazilian phishing
    const hasConsultaText = form.innerText.toLowerCase().includes('consulta') || 
                           form.innerText.toLowerCase().includes('verificar') ||
                           form.innerText.toLowerCase().includes('indenização') ||
                           form.innerText.toLowerCase().includes('indenizacao');
    
    // Enhanced login form detection
    // Check for login-related keywords in various attributes
    const formText = [
      form.id || '',
      form.className || '',
      form.action || '',
      ...inputDetails.map(i => i.name),
      ...inputDetails.map(i => i.id),
      ...inputDetails.map(i => i.placeholder)
    ].join(' ').toLowerCase();
    
    // Look for login-related terms
    const loginKeywords = ['login', 'signin', 'sign in', 'log in', 'authenticate', 'credentials', 'username', 'email', 'account'];
    const containsLoginTerms = loginKeywords.some(term => formText.includes(term));
    
    // Check for any password field
    const hasPasswordField = inputDetails.some(input => input.type === 'password');
    
    // Check for credential-related input patterns
    const hasEmailField = inputDetails.some(input => 
      input.type === 'email' || 
      input.name?.includes('email') || 
      input.id?.includes('email') || 
      input.placeholder?.includes('email')
    );
    
    const hasUsernameField = inputDetails.some(input => 
      input.name?.includes('user') || 
      input.id?.includes('user') || 
      input.placeholder?.includes('user') ||
      input.name?.includes('name') || 
      input.id?.includes('name') || 
      input.placeholder?.includes('name')
    );
    
    // Determine if this is a login form
    const isLoginForm = hasPasswordField || 
                        (form.action && form.action.toLowerCase().includes('login')) ||
                        (form.id && form.id.toLowerCase().includes('login')) ||
                        (form.className && form.className.toLowerCase().includes('login')) ||
                        (containsLoginTerms && (hasEmailField || hasUsernameField));
    
    // Check for external form action (possible data theft)
    let isExternalAction = false;
    let actionUrl = '';
    try {
      if (form.action) {
        actionUrl = form.action;
        const actionDomain = new URL(form.action, window.location.href).hostname;
        isExternalAction = actionDomain !== currentDomain;
      }
    } catch (e) {
      // URL parsing error
    }
    
    // Check for suspicious form attributes
    const isSuspiciousForm = 
      // No action (could be hijacked by JS)
      !form.action || 
      // Sends data to a different domain
      isExternalAction ||
      // Non-HTTPS form with password field  
      (hasPasswordField && actionUrl && actionUrl.startsWith('http:')) ||
      // Hidden form with credentials
      (isLoginForm && getComputedStyle(form).display === 'none') ||
      // Brazilian identity document phishing
      (hasCpfField && !form.action?.includes('gov.br')) ||
      // Consultation forms on non-government/bank sites
      (hasConsultaText && !currentDomain.includes('gov.br') && !currentDomain.includes('nubank.com.br'));
    
    return {
      action: form.action || '',
      method: form.method || 'get',
      id: form.id || '',
      className: form.className || '',
      inputs: inputDetails,
      isLoginForm: isLoginForm,
      isExternalAction: isExternalAction,
      isSuspiciousForm: isSuspiciousForm,
      hasPasswordField: hasPasswordField,
      hasEmailField: hasEmailField,
      hasCpfField: hasCpfField,
      hasConsultaText: hasConsultaText,
      isDocumentVerificationForm: hasCpfField || hasConsultaText
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
 * Extract text sample from the page
 * @returns {string} Text sample
 */
function extractTextSample() {
  // Get text from important elements
  let textSample = '';
  
  // Add page title
  textSample += document.title + ' ';
  
  // Add content from h1, h2, h3 elements (often contain revealing text in phishing sites)
  const headerElements = document.querySelectorAll('h1, h2, h3, h4');
  headerElements.forEach(element => {
    textSample += element.innerText + ' ';
  });
  
  // Add meta description content (often contains revealing text in phishing)
  const metaDesc = document.querySelector('meta[name="description"]');
  if (metaDesc) {
    textSample += metaDesc.getAttribute('content') + ' ';
  }
  
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
      links: features.links,
      hasLoginForm: features.hasLoginForm,
      hasPasswordField: features.hasPasswordField,
      hasSuspiciousForm: features.hasSuspiciousForm,
      hasExternalFormAction: features.hasExternalFormAction,
      hasUnsecuredLoginForm: features.hasUnsecuredLoginForm,
      hasHttps: features.hasHttps,
      isHttp: features.isHttp,
      claimsSecureOrVerified: features.claimsSecureOrVerified,
      hasUrgencyLanguage: features.hasUrgencyLanguage
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
  
  // Additional phishing score based on our enhanced indicators
  let additionalScore = 0;
  const additionalIndicators = [];
  
  // Add scores for different phishing indicators
  if (contentFeatures.isHttp) {
    additionalScore += 30; // HTTP is a major security issue
    additionalIndicators.push('Non-secure HTTP connection');
  }
  
  if (contentFeatures.brandOnFreeHosting) {
    additionalScore += 40; // Very strong phishing signal
    additionalIndicators.push('Brand impersonation on free hosting service');
  }
  
  if (contentFeatures.hasBrandWithNumbers) {
    additionalScore += 35; // Strong phishing signal
    additionalIndicators.push('Brand name with numeric pattern in domain');
  }
  
  if (contentFeatures.brandInContentButNotDomain) {
    additionalScore += 25;
    additionalIndicators.push('Content impersonates brand not in domain');
  }
  
  if (contentFeatures.hasDeceptiveDomainPattern) {
    additionalScore += 20;
    additionalIndicators.push('Deceptive domain pattern');
  }
  
  if (contentFeatures.hasExcessiveSubdomains) {
    additionalScore += 15;
    additionalIndicators.push('Excessive subdomains');
  }
  
  if (contentFeatures.hasMismatchedContent) {
    additionalScore += 20;
    additionalIndicators.push('Mismatched link destinations');
  }
  
  if (contentFeatures.hasUrgencyLanguage) {
    additionalScore += 15;
    additionalIndicators.push('Urgent or threatening language');
  }
  
  if (contentFeatures.hasSuspiciousForm) {
    additionalScore += 25;
    additionalIndicators.push('Suspicious form detected');
  }
  
  if (contentFeatures.hasExternalFormAction) {
    additionalScore += 30;
    additionalIndicators.push('Form submits to external domain');
  }
  
  if (contentFeatures.hasUnsecuredLoginForm) {
    additionalScore += 35;
    additionalIndicators.push('Unsecured login form');
  }
  
  // Payment portal phishing indicators
  if (contentFeatures.hasPaymentImpersonation) {
    additionalScore += 50; // Very strong signal for payment fraud
    additionalIndicators.push('Payment portal impersonation');
  }
  
  if (contentFeatures.looksLikePaymentPortal) {
    additionalScore += 40;
    additionalIndicators.push('Looks like payment portal on unofficial domain');
  }
  
  if (contentFeatures.hasBankLogos) {
    additionalScore += 35;
    additionalIndicators.push('Bank logos on unofficial site');
  }
  
  if (contentFeatures.hasBoletoContent && 
      !contentFeatures.domain.includes('bradesco') && 
      !contentFeatures.domain.includes('bb.com.br') && 
      !contentFeatures.domain.includes('santander')) {
    additionalScore += 30;
    additionalIndicators.push('Payment content on unofficial domain');
  }
  
  if (contentFeatures.hasMisspelledSupport) {
    additionalScore += 25;
    additionalIndicators.push('Misspelled support term in domain');
  }
  
  // Special case for NotreDame insurance impersonation
  if ((contentFeatures.textSample.includes('notredame') || 
       contentFeatures.textSample.includes('intermedica') || 
       contentFeatures.textSample.includes('intermédica')) && 
      !contentFeatures.domain.includes('notredameintermedica')) {
    additionalScore += 45;
    additionalIndicators.push('NotreDame Intermédica impersonation');
  }
  
  // Portuguese payment terms with payment buttons is very suspicious
  if ((contentFeatures.textSample.includes('boleto') || 
       contentFeatures.textSample.includes('segunda via') || 
       contentFeatures.textSample.includes('emitir')) && 
      contentFeatures.paymentButtonsCount > 0) {
    additionalScore += 40;
    additionalIndicators.push('Fake payment portal for bill payments');
  }
  
  // Brazilian document phishing detection - very high score as these are almost certainly phishing
  if (contentFeatures.hasCpfForm || contentFeatures.hasCpfInputsOutsideForms) {
    additionalScore += 60; // Extremely high score - these are almost always phishing
    additionalIndicators.push('Site requests CPF (Brazilian tax ID) on non-official domain');
  }
  
  if (contentFeatures.isNubankPhishingPage) {
    additionalScore += 75; // Maximum suspicion for Nubank phishing pages
    additionalIndicators.push('Site impersonates Nubank banking services');
  }
  
  if (contentFeatures.hasConsultaText && !contentFeatures.domain.includes('gov.br')) {
    additionalScore += 45;
    additionalIndicators.push('Page contains document consultation terminology on non-official domain');
  }
  
  // Check for suspicious URL domain patterns specifically for Nubank
  if (contentFeatures.domain.includes('hj-nu') || 
      contentFeatures.domain.includes('-nu.') ||
      contentFeatures.domain.includes('nu-') ||
      (contentFeatures.domain.includes('nu') && !contentFeatures.domain.includes('nubank.com.br'))) {
    additionalScore += 55; // Very high score for Nubank domain impersonation
    additionalIndicators.push('Domain uses suspicious pattern to impersonate Nubank');
  }
  
  // If we have login forms and any suspicious indicators, increase risk
  if (contentFeatures.hasLoginForm) {
    // If there's a login form and any suspicious indicator, mark as unsafe
    if (contentFeatures.isOnFreeHosting || 
       contentFeatures.hasNumbersInDomain || 
       contentFeatures.brandMentions.length > 0) {
      additionalScore += 20;
      additionalIndicators.push('Login form on suspicious domain');
    }
  }
  
  // "idealsuport.com" pattern - misspelled support and mentions major brands
  if (contentFeatures.domain.includes('suport') && 
      !contentFeatures.domain.includes('support') &&
      contentFeatures.brandMentions.length > 0) {
    additionalScore += 40;
    additionalIndicators.push('Misspelled support domain with brand mentions');
  }
  
  // Cap the additional score at 100
  additionalScore = Math.min(additionalScore, 100);
  
  // Format our additional indicators for the combined report
  const contentSecurityIndicators = {
    score: additionalScore,
    details: additionalIndicators
  };
  
  // Combine all signals for comprehensive analysis
  const combinedAnalysis = {
    url: currentUrl,
    domain: currentDomain,
    nlp: nlpResults || { nlpScore: 0, indicators: [], confidence: 0 },
    behavior: behaviorResults,
    interaction: interactionResults,
    contentSecurity: contentSecurityIndicators,
    timestamp: Date.now()
  };
  
  // Calculate combined phishing probability - now including our enhanced content security
  const nlpWeight = nlpResults ? 0.25 : 0;
  const behaviorWeight = 0.2;
  const interactionWeight = 0.15;
  const contentSecurityWeight = 0.4; // Give higher weight to our enhanced content checks
  
  const combinedScore = Math.round(
    (nlpResults ? (nlpResults.nlpScore * nlpWeight) : 0) +
    (behaviorResults.behaviorScore * behaviorWeight) +
    (interactionResults.interactionScore * interactionWeight) +
    (additionalScore * contentSecurityWeight)
  );
  
  combinedAnalysis.combinedScore = combinedScore;
  
  // More aggressive phishing detection - lower the threshold
  combinedAnalysis.isLikelyPhishing = combinedScore >= 55; // Lowered from 60
  
  // If we have strong phishing signals, immediately mark as phishing regardless of score
  if (contentFeatures.brandOnFreeHosting || 
      contentFeatures.isHttp || 
      contentFeatures.hasUnsecuredLoginForm ||
      contentFeatures.hasPaymentImpersonation ||
      contentFeatures.looksLikePaymentPortal ||
      contentFeatures.hasCpfForm ||
      contentFeatures.hasCpfInputsOutsideForms ||
      contentFeatures.isNubankPhishingPage ||
      (contentFeatures.domain.includes('hj-nu') || contentFeatures.domain.includes('nu-')) ||
      (contentFeatures.hasBrandWithNumbers && contentFeatures.hasLoginForm) ||
      (contentFeatures.hasMisspelledSupport && contentFeatures.brandMentions.length > 0)) {
    combinedAnalysis.isLikelyPhishing = true;
    // Ensure the score reflects this
    combinedAnalysis.combinedScore = Math.max(combinedAnalysis.combinedScore, 85);
  }
  
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
  else if (message.action === 'checkCurrentPage') {
    // If the page is using HTTP, immediately flag it as insecure
    if (window.location.protocol === 'http:') {
      sendResponse({
        result: {
          isSafe: false,
          threatType: 'Insecure connection',
          details: {
            threatIndicators: ['Non-secure HTTP connection (not using HTTPS)'],
            isHttp: true
          }
        }
      });
      return true;
    }
    
    // Special check for common Brazilian banking phishing structures
    if (currentDomain.includes('hj-nu') || 
        (currentDomain.includes('nu') && !currentDomain.includes('nubank.com.br')) ||
        (currentDomain.includes('hj-') && document.body.innerText.toLowerCase().includes('cpf')) ||
        (document.body.innerText.toLowerCase().includes('nubank') && document.body.innerText.toLowerCase().includes('cpf'))) {
      
      sendResponse({
        result: {
          isSafe: false,
          threatType: 'Phishing site detected',
          details: {
            threatIndicators: ['Site appears to be impersonating Nubank banking services']
          }
        }
      });
      return true;
    }
    
    // Check for CPF input outside of legitimate domains - immediate flag
    const hasCpfInput = document.querySelectorAll('input[name*="cpf"], input[placeholder*="cpf"], input[id*="cpf"]').length > 0;
    const isFinancialDomain = currentDomain.includes('.gov.br') || 
                              currentDomain.includes('nubank.com.br') || 
                              currentDomain.includes('caixa.gov.br') || 
                              currentDomain.includes('banco.bradesco');
                              
    if (hasCpfInput && !isFinancialDomain) {
      sendResponse({
        result: {
          isSafe: false,
          threatType: 'Document phishing detected',
          details: {
            threatIndicators: ['Site requesting CPF (Brazilian taxpayer ID) on non-official domain']
          }
        }
      });
      return true;
    }
    
    // If we already have features, check for suspicious indicators
    if (contentFeatures) {
      // Check for obvious phishing indicators
      const indicators = [];
      
      // Always flag HTTP as unsafe
      if (contentFeatures.isHttp) {
        indicators.push('Non-secure HTTP connection (not using HTTPS)');
      }
      
      // Check for suspicious forms
      if (contentFeatures.hasSuspiciousForm) {
        indicators.push('Suspicious form detected on page');
      }
      
      if (contentFeatures.hasExternalFormAction) {
        indicators.push('Login form submits data to external domain');
      }
      
      if (contentFeatures.hasUnsecuredLoginForm) {
        indicators.push('Login form uses insecure HTTP submission');
      }
      
      // Check for brand impersonation
      if (contentFeatures.brandOnFreeHosting) {
        indicators.push('Brand name detected on free hosting service (high-risk phishing indicator)');
      }
      
      if (contentFeatures.hasBrandWithNumbers) {
        indicators.push('Domain contains brand name with numeric pattern (common phishing technique)');
      }
      
      if (contentFeatures.brandInContentButNotDomain) {
        indicators.push('Page content impersonates a brand not in the domain name');
      }
      
      // Check for suspicious domain patterns
      if (contentFeatures.hasDeceptiveDomainPattern) {
        indicators.push('Domain contains deceptive security-related terms');
      }
      
      if (contentFeatures.hasExcessiveSubdomains) {
        indicators.push('Domain has excessive number of subdomains');
      }
      
      // Check for content-related phishing indicators
      if (contentFeatures.hasMismatchedContent) {
        indicators.push('Page contains links that disguise their actual destination');
      }
      
      if (contentFeatures.hasUrgencyLanguage) {
        indicators.push('Page contains urgent or threatening language');
      }
      
      // Check for payment portal phishing
      if (contentFeatures.hasPaymentImpersonation) {
        indicators.push('Page appears to impersonate a payment portal');
      }
      
      if (contentFeatures.looksLikePaymentPortal) {
        indicators.push('Page contains payment-related content but is not on a legitimate payment site');
      }
      
      if (contentFeatures.hasBankLogos) {
        indicators.push('Page contains bank/financial logos on an unofficial domain');
      }
      
      if (contentFeatures.hasBoletoContent && !contentFeatures.domain.includes('bradesco') && 
          !contentFeatures.domain.includes('bb.com.br') && !contentFeatures.domain.includes('santander')) {
        indicators.push('Page contains payment/invoice terminology on unofficial domain');
      }
      
      if (contentFeatures.hasMisspelledSupport) {
        indicators.push('Domain contains misspelled support term (common in phishing)');
      }
      
      // Special case for payment sites with NotreDame brand
      if ((contentFeatures.textSample.includes('notredame') || 
           contentFeatures.textSample.includes('intermedica') || 
           contentFeatures.textSample.includes('intermédica')) && 
          !contentFeatures.domain.includes('notredameintermedica')) {
        indicators.push('Page impersonates NotreDame Intermédica health insurance');
      }
      
      // Detecting Portuguese payment portal features
      if ((contentFeatures.textSample.includes('boleto') || 
           contentFeatures.textSample.includes('segunda via') || 
           contentFeatures.textSample.includes('emitir')) && 
          contentFeatures.paymentButtonsCount > 0) {
        indicators.push('Page appears to be a fake payment portal for bill payments');
      }
      
      // Brazilian document phishing detection
      if (contentFeatures.hasCpfForm || contentFeatures.hasCpfInputsOutsideForms) {
        indicators.push('Page requests CPF (Brazilian tax ID) on non-official domain');
      }
      
      if (contentFeatures.isNubankPhishingPage) {
        indicators.push('Page appears to be impersonating Nubank banking services');
      }
      
      if (contentFeatures.hasConsultaText && !contentFeatures.domain.includes('gov.br')) {
        indicators.push('Page contains Brazilian document verification terminology on non-official domain');
      }
      
      if (contentFeatures.hasDocumentVerificationForm && !contentFeatures.domain.includes('gov.br')) {
        indicators.push('Page contains document verification form on non-official domain');
      }
      
      // Check for suspicious URL domain patterns
      if (contentFeatures.domain.includes('hj-nu') || 
          contentFeatures.domain.includes('-nu.') ||
          contentFeatures.domain.includes('nu-') ||
          contentFeatures.domain.includes('nu.shop')) {
        indicators.push('Domain uses suspicious pattern to impersonate Nubank');
      }
      
      // For login forms, be more strict
      if (contentFeatures.hasLoginForm) {
        // If there's a login form and ANY other suspicious indicator, mark as unsafe
        if (contentFeatures.isOnFreeHosting || 
            contentFeatures.hasNumbersInDomain || 
            contentFeatures.brandMentions.length > 0) {
          indicators.push('Login form on suspicious domain');
        }
      }
      
      // Send response with suspicious content indicators
      if (indicators.length > 0) {
        // If we have indicators, site is unsafe
        sendResponse({
          result: {
            isSafe: false,
            threatType: indicators.length > 2 ? 'Multiple phishing indicators detected' : 'Suspicious page content',
            details: {
              threatIndicators: indicators
            }
          }
        });
      } else if (contentFeatures.brandMentions.length > 0 && 
                !contentFeatures.brandMentions.some(brand => currentDomain.includes(brand))) {
        // If page mentions brands that aren't in the domain, be cautious
        sendResponse({
          result: {
            isSafe: false,
            threatType: 'Potential brand impersonation',
            details: {
              threatIndicators: [`Page mentions ${contentFeatures.brandMentions.join(', ')} but domain doesn't match`]
            }
          }
        });
      } else if (contentFeatures.containsPaymentTerms && 
                contentFeatures.domain !== 'paypal.com' && 
                !contentFeatures.domain.includes('bank') && 
                !contentFeatures.domain.includes('banco')) {
        // Extra check for payment sites that slipped through other checks
        sendResponse({
          result: {
            isSafe: false,
            threatType: 'Suspicious payment site',
            details: {
              threatIndicators: ['Page contains payment terminology on unofficial domain']
            }
          }
        });
      } else if (contentFeatures.containsBrazilianDocTerms && 
                 !contentFeatures.domain.includes('gov.br') &&
                 !contentFeatures.domain.includes('nubank.com.br')) {
        // Extra check for Brazilian document verification sites
        sendResponse({
          result: {
            isSafe: false,
            threatType: 'Document phishing site',
            details: {
              threatIndicators: ['Page contains Brazilian document terminology on unofficial domain']
            }
          }
        });
      } else {
        // Send the features for further analysis
        sendResponse({ features: contentFeatures });
      }
    } else {
      // If features not yet extracted, do a quick check for HTTP
      if (window.location.protocol === 'http:') {
        sendResponse({
          result: {
            isSafe: false,
            threatType: 'Insecure connection',
            details: {
              threatIndicators: ['Non-secure HTTP connection (not using HTTPS)'],
              isHttp: true
            }
          }
        });
      } else {
        // Wait for features to be extracted
        sendResponse({ status: 'analyzing' });
      }
    }
    return true;
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
