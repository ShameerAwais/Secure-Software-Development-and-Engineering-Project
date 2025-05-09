/**
 * Background Script
 * 
 * This script runs in the extension's background and coordinates the
 * phishing detection system:
 * 1. Receives data from content scripts monitoring web pages
 * 2. Communicates with the backend API for NLP analysis
 * 3. Makes final phishing determinations combining all signals
 * 4. Manages user notifications and protection responses
 */

// Configuration
const API_CONFIG = {
  baseUrl: 'http://localhost:5001/api/v1',
  endpoints: {
    analyzeContent: '/urls/user-check',
    checkUrl: '/urls/check',
    reportPhishing: '/urls/user-action',
    login: '/auth/login',
    register: '/auth/register',
    logout: '/auth/logout',
    profile: '/auth/profile',
    lists: '/auth/lists'
  },
  headers: {
    'Content-Type': 'application/json'
  }
};

// Track analysis results across tabs
const tabAnalysisData = {};
const phishingAlerts = {};
const safeUrls = new Set();
const suspiciousUrls = new Set();
const confirmedPhishingUrls = new Set();

// Initialize common phishing patterns seen in PhishTank and Kaggle datasets
const phishingPatterns = {
  // Common phishing keywords in URL
  suspiciousKeywords: [
    'secure', 'login', 'signin', 'verify', 'account', 'update', 'confirm', 
    'banking', 'security', 'authenticate', 'wallet', 'official', 'support',
    'password', 'credential', 'verification', 'authenticate', 'billing',
    'recover', 'unlock', 'restore', 'access', 'protect', 'limited', 'restrict',
    // Adding more payment-related and service keywords
    'boleto', 'invoice', 'payment', 'bill', 'pay', 'portal', 'suport', 'support',
    'cliente', 'customer', 'service', 'atendimento', 'conta', 'emitir', 'segunda',
    'via', '2via', 'ideal', 'banco', 'bank', 'health', 'insurance', 'plano',
    // Adding Brazilian financial terms
    'consulta', 'saldo', 'indenização', 'indenizacao', 'restituicao', 'restituição',
    'beneficio', 'benefício', 'auxilio', 'auxílio', 'resgate', 'cadastro', 'cpf',
    // Adding darknet market related terms
    'market', 'darknet', 'dark', 'deep', 'onion', 'silk', 'russia', 'russiaa', 'russiaan',
    'captcha', 'anonymous', 'hidden', 'escrow', 'bitcoin', 'btc', 'crypto', 'monero',
    'xmr', 'pgp', 'verify', 'tor', 'privacy'
  ],
  
  // Common brand targets in phishing
  targetedBrands: [
    'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix', 
    'instagram', 'xfinity', 'comcast', 'chase', 'bankofamerica', 'wellsfargo', 
    'linkedin', 'twitter', 'gmail', 'outlook', 'yahoo', 'dropbox', 'icloud', 
    'hotmail', 'office365', 'citibank', 'capitalone', 'amex', 'americanexpress',
    'discord', 'spotify', 'walmart', 'target', 'usps', 'fedex', 'ups', 'dhl',
    'ebay', 'venmo', 'zelle', 'coinbase', 'binance', 'myetherwallet', 'blockchain',
    // Adding healthcare/insurance providers and banks commonly targeted
    'notredame', 'intermédica', 'unimed', 'amil', 'bradesco', 'itau', 'santander',
    'caixa', 'banco', 'saude', 'health', 'seguro', 'insurance', 'visa', 'mastercard',
    // Adding Brazilian financial institutions commonly targeted
    'nubank', 'inter', 'c6bank', 'bancopan', 'picpay', 'original', 'mercadopago',
    'next', 'neon', 'digio', 'bs2', 'bmg', 'pagseguro', 'banrisul', 'crefisa',
    // Adding darknet market names commonly impersonated 
    'hydra', 'russian', 'russiaa', 'russiaan', 'darkmarket', 'empire', 'alphabay', 'versus',
    'world', 'torrez', 'dark0de', 'cannazon', 'whitehouse', 'monopoly', 'darkfox'
  ],
  
  // Common free hosting services used in phishing
  freeHostingServices: [
    'weebly.com', 'wix.com', 'blogspot.com', 'wordpress.com', 'site123.com',
    'webnode.com', 'glitch.me', 'netlify.app', 'pages.dev', 'github.io',
    'vercel.app', 'herokuapp.com', 'repl.co', '000webhostapp.com', 'webs.com',
    'yolasite.com', 'strikingly.com', 'carrd.co', 'squarespace.com', 'azurewebsites.net',
    'firebaseapp.com', 'web.app', 'surge.sh', 'gitlab.io', 'bitbucket.io', 
    'neocities.org', 'tumblr.com', 'hubspot.com', 'shutterfly.com', 'godaddysites.com'
  ],
  
  // Common suspicious TLDs 
  suspiciousTLDs: [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.online', 
    '.site', '.club', '.info', '.biz', '.live', '.services', '.buzz',
    '.shop', '.store', '.uno', '.pw', '.fun', '.casa', '.icu', '.today',
    // Darknet market commonly used TLDs
    '.to', '.st', '.lc', '.ws', '.cc', '.io', '.is', '.ly', '.me', '.su',
    '.rs', '.gs', '.sh'
  ],
  
  // Known phishing URL patterns (regex patterns)
  phishingRegexPatterns: [
    /secure.*login.*verify/i,
    /login.*verify.*account/i,
    /sign.*in.*secure/i,
    /confirm.*account.*details/i,
    /verify.*identity.*now/i,
    /(payment|billing).*update.*required/i,
    /account.*suspended/i,
    /unusual.*activity/i,
    /limited.*access/i,
    /security.*alert/i,
    /password.*expired/i,
    /action.*required/i,
    // Adding patterns for payment-related phishing
    /emitir.*segunda.*via/i,
    /boleto.*online/i,
    /portal.*cliente/i,
    /payment.*portal/i,
    // Adding Brazilian fraud patterns
    /consulta.*indenizacao/i,
    /consulte.*saldo/i,
    /resgate.*beneficio/i,
    /verificar.*conta/i,
    /cpf.*verificar/i,
    // Adding darknet market patterns
    /russiaanmarket/i,
    /russia+n+market/i,
    /market.*captcha/i,
    /login.*captcha/i,
    /forgot.*password.*contacts/i
  ],
  
  // Hard-coded samples from PhishTank and Kaggle
  // These are intentionally modified slightly to avoid accidental blocking of legitimate sites
  knownBadDomains: [
    'appleid-appls.com', 
    'secure-paypal.net',
    'login-microsoft-verify.com',
    'account-verify-amazon.co',
    'netflix-billing-update.com',
    'secure-bankofamerica-login.com',
    'verification-wellsfargo.com',
    'google-docs-share.xyz',
    'dropbox-secure-files.com',
    'instagram-verify-account.co',
    'facebook-security-login.com',
    'chase-secure-bank.com',
    'office365-login-verify.com',
    'apple-icloud-signin.co',
    'account-update-paypal.com',
    'signin-chase-verify.com',
    // Specifically adding the xfinity8765748.weebly.com pattern and variations
    'xfinity87', 
    'xfinity8', 
    'xfinity9',
    'xfinity1',
    'xfinity-login',
    'xfinity-account',
    'xfinity-security',
    'xfinity-update',
    'xfinity-verify',
    'xfinity.weebly',
    // Adding patterns for common misspelled support domains
    'idealsuport',
    'suport',
    'cliente-portal',
    'portal-cliente',
    'emitir-segunda',
    'emitir-boleto',
    'boleto-online',
    'segunda-via',
    'pagamento-online',
    // Adding Nubank phishing patterns
    'hj-nu',
    'nu-shop',
    'nu-',
    '-nu',
    'nubank-',
    '-nubank',
    'nu.shop',
    'nu.site',
    'nu.online',
    'nubank.online',
    'nubank.site',
    'nubank.info',
    'nubank.top',
    // Adding darknet market phishing patterns
    'russiaanmarket',
    'russiaamarket',
    'russianmarket',
    'russian-market',
    'russia-market',
    'darkmarket',
    'darkweb',
    'darknet',
    'hydramarket',
    'alphabay',
    'empire-market',
    'versus-market',
    'torrez-market'
  ],
  
  // URL patterns that contain both a brand name and suspicious term
  brandWithSuspicious: [],
  
  // Specific patterns for numeric phishing domains (common in phishing URLs)
  numericPatterns: [
    /[a-z]+\d{4,}/i,  // word followed by 4+ digits
    /\d{4,}[a-z]+/i   // 4+ digits followed by word
  ],
  
  // Common misspellings used in phishing domains
  commonMisspellings: [
    {correct: 'support', misspelled: ['suport', 'supprt', 'supporte', 'suporte']},
    {correct: 'account', misspelled: ['acount', 'acct', 'accnt', 'acouunt']},
    {correct: 'secure', misspelled: ['secur', 'sequre', 'securre', 'seguro']},
    {correct: 'banking', misspelled: ['bancking', 'bankin', 'bancking', 'banc']},
    {correct: 'login', misspelled: ['logon', 'loging', 'logn', 'entrar']},
    {correct: 'official', misspelled: ['oficial', 'ofisial', 'offical', 'officiel']},
    {correct: 'service', misspelled: ['servic', 'servico', 'servis', 'servizio']},
    {correct: 'customer', misspelled: ['custmer', 'client', 'cliente', 'costumer']},
    {correct: 'russian', misspelled: ['russias', 'russin', 'russiaan', 'russiaan', 'russiaa']}
  ],
  
  // Payment and banking terms in multiple languages (common in global phishing)
  paymentTerms: [
    'payment', 'pago', 'pagamento', 'boleto', 'fatura', 'bill',
    'invoice', 'factura', 'segunda via', '2via', 'emitir', 'emissão',
    'bank', 'banco', 'banca', 'conta', 'account', 'portal', 'área cliente'
  ],
  
  // URL shortening or fragment patterns (common in recent phishing campaigns)
  suspiciousUrlPatterns: [
    // Short domains with brand fragments
    /hj-[a-z]{2,5}\.[a-z]{2,5}/i,
    /[a-z]{2,4}-[a-z]{2,5}\.[a-z]{2,5}/i,
    // Random subdirectories (common in phishing)
    /\/[a-z]{3,5}\/$/i,
    /\/[a-z]{2,4}-[a-z]{2,4}\/$/i,
    // Fragment-based brand impersonation
    /-nu\./i,
    /nu-/i,
    /nu\./i,
    // Brazilian document request patterns
    /\/(cpf|consulta|verificar|cadastro)\//i,
    // Darknet market patterns
    /russia+n+market\./i,
    /darkmarket\./i,
    /market\.(to|cc|st|me)/i
  ],
  
  // Brazilian financial terminology and document patterns
  brazilianFinancialTerms: [
    'cpf', 'consulta', 'saldo', 'beneficio', 'benefício', 'indenização', 'indenizacao',
    'restituição', 'restituicao', 'consultar', 'verificar', 'acesso', 'digite', 
    'auxílio', 'auxilio', 'cadastro', 'conta', 'login', 'entrar', 'acessar'
  ],
  
  // Darknet marketplace terminology
  darknetMarketTerms: [
    'captcha', 'market', 'escrow', 'pgp', 'btc', 'xmr', 'crypto', 'bitcoin', 'monero',
    'wallet', 'vendor', 'anonymous', 'hidden', 'mirror', 'verify', 'verification',
    'account', 'password', 'forgot', 'contacts', 'register', 'login',
    'россия', 'russian', 'russiaan', 'russiaa', 'россиян', 'рынок', 'даркнет'
  ],
  
  // Suspicious captcha implementations (common in phishing)
  suspiciousCaptchaPatterns: [
    // Sites with multiple captchas on login/register pages
    // Sites with fake captchas that don't actually validate
    // Sites that use captchas but have poor security otherwise
    /captcha.*password/i,
    /password.*captcha/i,
    /forgot.*password.*contacts/i,
    /captcha.*login/i,
    /captcha.*create.*account/i
  ],
  
  // List of legitimate banking domains for comparison
  legitimateBankingDomains: [
    'nubank.com.br', 'banco.bradesco', 'bb.com.br', 'santander.com.br', 'caixa.gov.br',
    'itau.com.br', 'inter.co', 'bancopan.com.br', 'c6bank.com.br', 'original.com.br',
    'mercadopago.com.br', 'picpay.com', 'neon.com.br', 'next.me', 'bs2.com', 'bmg.com.br',
    'pagseguro.uol.com.br', 'banrisul.com.br', 'crefisa.com.br', 'digio.com.br',
    'paypal.com', 'stripe.com', 'wise.com'
  ],
  
  // Legitimate darknet markets (for research purposes only)
  legitimateDarknetDomains: [
    'torproject.org', 'deepdotweb.com', 'darknetlive.com', 'darknetstats.com'
  ]
};

// Generate combinations of brand + suspicious term patterns
for (const brand of phishingPatterns.targetedBrands) {
  for (const term of ['verify', 'secure', 'login', 'signin', 'account', 'update', 'confirm', 'payment', 'portal', 'bill', 'boleto', 'via', 'cpf', 'consulta', 'market', 'captcha']) {
    phishingPatterns.brandWithSuspicious.push(`${brand}-${term}`);
    phishingPatterns.brandWithSuspicious.push(`${term}-${brand}`);
    phishingPatterns.brandWithSuspicious.push(`${brand}.${term}`);
    phishingPatterns.brandWithSuspicious.push(`${term}.${brand}`);
    phishingPatterns.brandWithSuspicious.push(`${brand}${term}`);
    phishingPatterns.brandWithSuspicious.push(`${term}${brand}`);
    
    // Add numeric variations for xfinity specifically
    if (brand === 'xfinity' || brand === 'comcast') {
      for (let i = 1; i <= 9; i++) {
        phishingPatterns.brandWithSuspicious.push(`${brand}${i}`);
        phishingPatterns.brandWithSuspicious.push(`${brand}${i}${term}`);
        phishingPatterns.brandWithSuspicious.push(`${brand}${term}${i}`);
      }
    }
    
    // Add special patterns for Nubank and other Brazilian banks
    if (brand === 'nubank' || brand === 'bradesco' || brand === 'itau' || brand === 'santander') {
      phishingPatterns.brandWithSuspicious.push(`${brand.substring(0, 2)}-`);
      phishingPatterns.brandWithSuspicious.push(`-${brand.substring(0, 2)}`);
      phishingPatterns.brandWithSuspicious.push(`${brand.substring(0, 2)}.`);
      phishingPatterns.brandWithSuspicious.push(`hj-${brand.substring(0, 2)}`);
    }
    
    // Add special patterns for darknet markets
    if (brand === 'russian' || brand === 'hydra' || brand === 'empire' || brand === 'alphabay') {
      // Add misspelled variations
      if (brand === 'russian') {
        phishingPatterns.brandWithSuspicious.push(`russiaan${term}`);
        phishingPatterns.brandWithSuspicious.push(`russiaa${term}`);
        phishingPatterns.brandWithSuspicious.push(`russiamarket`);
        phishingPatterns.brandWithSuspicious.push(`russiaanmarket`);
      }
      
      // Add market patterns
      phishingPatterns.brandWithSuspicious.push(`${brand}market`);
      phishingPatterns.brandWithSuspicious.push(`${brand}-market`);
    }
  }
}

// Initialize extension
chrome.runtime.onInstalled.addListener(initializeExtension);
setupListeners();

/**
 * Initialize the extension
 */
function initializeExtension() {
  console.log('[PhishGuard] Extension initialized');
  
  // Reset extension state
  resetExtensionState();
  
  // Set default badge color
  chrome.action.setBadgeBackgroundColor({ color: '#5D87E8' });
}

/**
 * Set up all message and event listeners
 */
function setupListeners() {
  // Listen for messages from content scripts
  chrome.runtime.onMessage.addListener(handleMessages);
  
  // Listen for tab updates to reset data and start scans
  chrome.tabs.onUpdated.addListener(handleTabUpdated);
  
  // Listen for tab removal to clean up data
  chrome.tabs.onRemoved.addListener(handleTabRemoved);
}

/**
 * Handle messages from content scripts
 * @param {Object} message - Message data
 * @param {Object} sender - Message sender
 * @param {Function} sendResponse - Response function
 * @returns {boolean} Whether response will be async
 */
function handleMessages(message, sender, sendResponse) {
  // Handle messages from popup and content scripts
  if (message.action === 'getAuthStatus') {
    // Get auth state from storage
    chrome.storage.local.get(['isAuthenticated', 'user'], (result) => {
      sendResponse({
        success: true,
        isAuthenticated: result.isAuthenticated || false,
        user: result.user || null
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'login') {
    // Make login request to backend
    fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.login, {
      method: 'POST',
      headers: API_CONFIG.headers,
      body: JSON.stringify(message.credentials),
      credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Save auth state to storage
        chrome.storage.local.set({
          isAuthenticated: true,
          user: data.user,
          token: data.token,
          refreshToken: data.refreshToken,
          tokenExpiry: data.tokenExpiry
        });
      }
      sendResponse(data);
    })
    .catch(error => {
      console.error('Login error:', error);
      sendResponse({
        success: false,
        message: 'Error connecting to authentication service'
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'register') {
    // Make register request to backend
    fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.register, {
      method: 'POST',
      headers: API_CONFIG.headers,
      body: JSON.stringify(message.userData),
      credentials: 'include'
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      if (data.success) {
        // Save auth state to storage
        chrome.storage.local.set({
          isAuthenticated: true,
          user: data.user,
          token: data.token,
          refreshToken: data.refreshToken,
          tokenExpiry: data.tokenExpiry
        });
      }
      sendResponse(data);
    })
    .catch(error => {
      console.error('Registration error:', error);
      sendResponse({
        success: false,
        message: `Error creating account: ${error.message}`
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'refreshProfile') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const url = API_CONFIG.baseUrl + API_CONFIG.endpoints.profile;
      console.log('Fetching profile from:', url);
      
      // Make profile request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Update stored user data
          chrome.storage.local.set({
            user: data.user
          });
          sendResponse({
            success: true,
            user: data.user
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to refresh profile'
          });
        }
      })
      .catch(error => {
        console.error('Profile refresh error:', error);
        sendResponse({
          success: false,
          message: `Error refreshing profile data: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'getProfile') {
    // Get stored token
    chrome.storage.local.get(['token', 'user'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      // First check if we have a cached user profile and it's recent
      if (result.user && result.user.lastFetched && 
          (Date.now() - result.user.lastFetched < 300000)) { // 5 minutes cache
        console.log('Using cached profile data');
        sendResponse({
          success: true,
          user: result.user
        });
        return;
      }

      const url = API_CONFIG.baseUrl + API_CONFIG.endpoints.profile;
      console.log('Fetching fresh profile from:', url);
      
      // Make profile request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Add timestamp to user data
          const userData = {
            ...data.user,
            lastFetched: Date.now()
          };
          
          // Update stored user data
          chrome.storage.local.set({
            user: userData
          });
          
          sendResponse({
            success: true,
            user: userData
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to get profile data'
          });
        }
      })
      .catch(error => {
        console.error('Profile fetch error:', error);
        
        // If we have cached data, return it as fallback
        if (result.user) {
          sendResponse({
            success: true,
            user: result.user,
            message: 'Using cached profile data (fetch failed)'
          });
        } else {
          sendResponse({
            success: false,
            message: `Error getting profile data: ${error.message}`
          });
        }
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'getLists') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const url = API_CONFIG.baseUrl + API_CONFIG.endpoints.lists;
      console.log('Fetching lists from:', url);
      
      // Make lists request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Store lists data
          chrome.storage.local.set({
            allowList: data.allowList || [],
            blockList: data.blockList || []
          });
          sendResponse({
            success: true,
            allowList: data.allowList || [],
            blockList: data.blockList || []
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to load lists'
          });
        }
      })
      .catch(error => {
        console.error('Lists loading error:', error);
        sendResponse({
          success: false,
          message: `Error loading lists: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'updateLists') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const url = `${API_CONFIG.baseUrl}/lists/${message.listType}`;
      console.log(`${message.listAction} to ${message.listType}:`, url, message.url);
      
      // Determine HTTP method based on action
      const method = message.listAction === 'add' ? 'POST' : 'DELETE';
      
      // Make request to backend
      fetch(url, {
        method: method,
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        body: JSON.stringify({ url: message.url }),
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          // Update stored lists
          chrome.storage.local.get([message.listType], (listResult) => {
            const currentList = listResult[message.listType] || [];
            let updatedList = [...currentList];
            
            if (message.listAction === 'add' && !currentList.includes(message.url)) {
              updatedList.push(message.url);
            } else if (message.listAction === 'remove') {
              updatedList = currentList.filter(item => item !== message.url);
            }
            
            const updateObj = {};
            updateObj[message.listType] = updatedList;
            chrome.storage.local.set(updateObj);
          });
          
          sendResponse({
            success: true,
            message: `${message.url} ${message.listAction === 'add' ? 'added to' : 'removed from'} ${message.listType}`
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || `Failed to ${message.listAction} to ${message.listType}`
          });
        }
      })
      .catch(error => {
        console.error(`Error updating ${message.listType}:`, error);
        sendResponse({
          success: false,
          message: `Error updating ${message.listType}: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'logout') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      const token = result.token;
      
      // Clear auth state first (even if API call fails)
      chrome.storage.local.remove(['isAuthenticated', 'user', 'token', 'refreshToken', 'tokenExpiry', 'allowList', 'blockList'], () => {
        console.log('Cleared auth state from storage');
      });
      
      // If we have a token, try to properly logout on server
      if (token) {
        fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.logout, {
          method: 'POST',
          headers: {
            ...API_CONFIG.headers,
            'Authorization': `Bearer ${token}`
          },
          credentials: 'include'
        })
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
          }
          return response.json();
        })
        .then(data => {
          sendResponse({
            success: true,
            message: 'Logged out successfully'
          });
        })
        .catch(error => {
          console.error('Logout API error:', error);
          // Still consider logout successful even if API call fails
          sendResponse({
            success: true,
            message: 'Logged out locally'
          });
        });
      } else {
        // No token means we're not logged in anyway
        sendResponse({
          success: true,
          message: 'Not logged in'
        });
      }
    });
    return true; // Indicate async response
  }

  if (message.action === 'checkServerAvailability') {
    // Check if server is available by making a request to the health endpoint
    // Add cache-busting query parameter to prevent 304 responses
    const timestamp = new Date().getTime();
    fetch(`http://localhost:5001/health?_=${timestamp}`)
      .then(response => {
        if (response.ok) {
          sendResponse({
            success: true,
            isAvailable: true
          });
        } else {
          sendResponse({
            success: true,
            isAvailable: false
          });
        }
      })
      .catch(error => {
        console.error('Server availability check failed:', error);
        sendResponse({
          success: true,
          isAvailable: false
        });
      });
    return true; // Indicate async response
  }

  if (message.action === 'checkUrl') {
    const url = message.url;
    try {
      // Parse the URL to get the domain
      const parsedUrl = new URL(url);
      const domain = parsedUrl.hostname;
      
      console.log('Checking URL:', url, 'Domain:', domain);
      
      // Check for HTTP protocol (always unsafe)
      if (url.startsWith('http:') && !url.startsWith('https:')) {
        sendResponse({
          success: true,
          data: {
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
      
      // First check if it's in our known lists
      if (confirmedPhishingUrls.has(url) || confirmedPhishingUrls.has(domain)) {
        sendResponse({
          success: true,
          data: {
            isSafe: false,
            threatType: 'Known phishing site',
            details: {
              threatIndicators: ['URL matches known phishing pattern']
            }
          }
        });
        return true;
      }
      
      // Check for domain in our phishing patterns
      for (const badDomain of phishingPatterns.knownBadDomains) {
        if (domain.includes(badDomain)) {
          // Add to confirmed list for future checks
          confirmedPhishingUrls.add(domain);
          
          sendResponse({
            success: true,
            data: {
              isSafe: false,
              threatType: 'Known phishing pattern',
              details: {
                threatIndicators: ['Domain matches known phishing pattern']
              }
            }
          });
          return true;
        }
      }
      
      // Check against targeted brands combined with free hosting
      for (const brand of phishingPatterns.targetedBrands) {
        if (domain.includes(brand)) {
          // Check if it's on a free hosting service
          for (const freeHost of phishingPatterns.freeHostingServices) {
            if (domain.endsWith(freeHost)) {
              // Add to confirmed list for future checks
              confirmedPhishingUrls.add(domain);
              
              sendResponse({
                success: true,
                data: {
                  isSafe: false,
                  threatType: 'Brand impersonation',
                  details: {
                    threatIndicators: ['Brand name on free hosting service (high risk phishing indicator)']
                  }
                }
              });
              return true;
            }
          }
        }
      }
      
      // If we have a strong reason to believe it's a safe site, return that
      if (safeUrls.has(url) || safeUrls.has(domain)) {
        sendResponse({
          success: true,
          data: {
            isSafe: true,
            threatType: null,
            details: {}
          }
        });
        return true;
      }
      
      // Perform basic client-side checks
      const basicCheckResult = performBasicUrlCheck(url, domain);
      
      // If our basic check found issues, immediately report as suspicious
      if (!basicCheckResult.isSafe && basicCheckResult.indicators.length > 0) {
        // Add to suspicious URLs set
        suspiciousUrls.add(url);
        suspiciousUrls.add(domain);
        
        sendResponse({
          success: true,
          data: {
            isSafe: false,
            threatType: 'Suspicious URL pattern',
            details: {
              threatIndicators: basicCheckResult.indicators
            }
          }
        });
        return true;
      }
      
      // Check authentication for full scan
      chrome.storage.local.get(['isAuthenticated', 'token'], (result) => {
        if (!result.isAuthenticated || !result.token) {
          // Not authenticated, return limited scan
          sendResponse({
            success: true,
            requiresAuth: true,
            fallback: false,
            data: {
              isSafe: basicCheckResult.isSafe,
              threatType: basicCheckResult.isSafe ? null : 'Suspicious URL pattern',
              details: {
                threatIndicators: basicCheckResult.indicators
              }
            }
          });
          return;
        }
        
        // Check if server is available then proceed with API check
        checkServerAndMakeApiRequest();
        
        // Function to handle server check and API request flow
        function checkServerAndMakeApiRequest() {
          const timestamp = new Date().getTime();
          
          // Step 1: Check server availability
          fetch(`http://localhost:5001/health?_=${timestamp}`)
            .then(response => {
              if (!response.ok) {
                throw new Error('Health check failed');
              }
              return true;
            })
            .then(serverAvailable => {
              // Step 2: Make API request since server is available
              return fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.checkUrl, {
                method: 'POST',
                headers: {
                  ...API_CONFIG.headers,
                  'Authorization': `Bearer ${result.token}`
                },
                body: JSON.stringify({
                  url: url,
                  domain: domain
                }),
                credentials: 'include'
              });
            })
            .then(response => {
              // Step 3: Handle API response
              if (response.status === 404) {
                throw new Error('API endpoint not found');
              }
              if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
              }
              return response.json();
            })
            .then(data => {
              // Step 4: Process API data
              if (data.success) {
                // Check for Safe Browsing data
                const safeBrowsingResult = data.data?.details?.safeBrowsing;
                const isSafeBrowsingSource = data.data?.details?.source === "Google Safe Browsing API";
                
                // If Google Safe Browsing detected a threat, it's authoritative
                if ((safeBrowsingResult && !safeBrowsingResult.isSafe) || 
                    (isSafeBrowsingSource && !data.data.isSafe)) {
                  console.log('Google Safe Browsing detected unsafe URL');
                  
                  // Save to confirmed phishing URLs
                  confirmedPhishingUrls.add(url);
                  confirmedPhishingUrls.add(domain);
                }
                
                // Build response
                sendResponse({
                  success: true,
                  data: data.data || {
                    isSafe: data.isSafe,
                    threatType: data.isSafe ? null : data.threatType,
                    details: data.details || {}
                  }
                });
                
                // Save results to our caches
                if (data.data?.isSafe) {
                  safeUrls.add(url);
                  safeUrls.add(domain);
                } else if (data.data?.isPhishing || !data.data?.isSafe) {
                  confirmedPhishingUrls.add(url);
                  confirmedPhishingUrls.add(domain);
                }
              } else {
                // API responded but indicated an error
                sendResponse({
                  success: false,
                  error: data.message || 'Server returned an error',
                  fallback: true,
                  data: {
                    isSafe: basicCheckResult.isSafe,
                    threatType: basicCheckResult.isSafe ? null : 'Suspicious URL pattern',
                    details: {
                      threatIndicators: basicCheckResult.indicators
                    }
                  }
                });
              }
            })
            .catch(error => {
              // Handle any errors in the promise chain
              console.error('URL check error:', error);
              
              // Use fallback data for response
              sendResponse({
                success: true, // Using fallback, so consider it "successful" but with fallback data
                error: `Error checking URL: ${error.message}`,
                fallback: true,
                data: {
                  isSafe: basicCheckResult.isSafe,
                  threatType: basicCheckResult.isSafe ? null : 'Suspicious URL pattern',
                  details: {
                    threatIndicators: basicCheckResult.indicators
                  }
                }
              });
            });
        }
      });
      
      return true; // Indicate async response
    } catch (error) {
      // Error parsing URL
      console.error('URL parsing error:', error);
      sendResponse({
        success: false,
        error: `Invalid URL: ${error.message}`,
        data: { isSafe: null }
      });
      return true;
    }
  }

  if (message.action === 'getUserStats') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const timeRange = message.timeRange || 'month';
      const url = `${API_CONFIG.baseUrl}/urls/user-stats?range=${timeRange}`;
      console.log('Fetching user stats from:', url);
      
      // Make stats request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          sendResponse({
            success: true,
            stats: data.data || {}
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to fetch statistics'
          });
        }
      })
      .catch(error => {
        console.error('Stats fetch error:', error);
        sendResponse({
          success: false,
          message: `Error fetching statistics: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  if (message.action === 'getUserHistory') {
    // Get stored token
    chrome.storage.local.get(['token'], (result) => {
      if (!result.token) {
        sendResponse({
          success: false,
          message: 'Not authenticated'
        });
        return;
      }

      const page = message.page || 1;
      const limit = message.limit || 10;
      const timeRange = message.timeRange || 'month';
      const url = `${API_CONFIG.baseUrl}/urls/user-history?page=${page}&limit=${limit}&range=${timeRange}`;
      console.log('Fetching user history from:', url);
      
      // Make history request to backend
      fetch(url, {
        method: 'GET',
        headers: {
          ...API_CONFIG.headers,
          'Authorization': `Bearer ${result.token}`
        },
        credentials: 'include'
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        if (data.success) {
          sendResponse({
            success: true,
            history: data.data || [],
            pagination: data.pagination || {
              page: 1,
              pages: 1,
              total: 0
            }
          });
        } else {
          sendResponse({
            success: false,
            message: data.message || 'Failed to fetch history'
          });
        }
      })
      .catch(error => {
        console.error('History fetch error:', error);
        sendResponse({
          success: false,
          message: `Error fetching history: ${error.message}`
        });
      });
    });
    return true; // Indicate async response
  }

  // Only process messages from content scripts with tab IDs
  if (!sender.tab || !sender.tab.id) return false;
  
  const tabId = sender.tab.id;
  
  switch (message.action) {
    case 'analyzePageContent':
      handleAnalyzePageContent(tabId, message.data, sendResponse);
      return true; // Indicate async response
      
    case 'reportBehaviorAnalysis':
      handleBehaviorAnalysis(tabId, message.data);
      break;
      
    case 'reportUserInteractionAnalysis':
      handleUserInteractionAnalysis(tabId, message.data);
      break;
      
    case 'reportCombinedAnalysis':
      handleCombinedAnalysis(tabId, message.data);
      break;
      
    case 'reportAnalysisUpdate':
      handleAnalysisUpdate(tabId, message.data);
      break;
  }
  
  return false;
}

/**
 * Handle tab updated event to reset data and start analysis
 * @param {number} tabId - Tab ID
 * @param {Object} changeInfo - Change info
 * @param {Object} tab - Tab data
 */
function handleTabUpdated(tabId, changeInfo, tab) {
  // Only react to URL changes and complete loads
  if (!changeInfo.url && changeInfo.status !== 'complete') return;
  
  // Skip extension pages and empty pages
  if (!tab.url || tab.url.startsWith('chrome://') || tab.url === 'about:blank') {
    return;
  }

  // Reset previous analysis for this tab
  if (changeInfo.url) {
    resetTabAnalysis(tabId);
    
    // Check if URL is already known
    const url = new URL(tab.url);
    checkKnownUrl(tabId, url.href, url.hostname);
  }
  
  // Update badge for fresh page load
  if (changeInfo.status === 'complete') {
    updateBadgeForTab(tabId, 'scanning');
  }
}

/**
 * Check if URL is already known as safe or suspicious
 * @param {number} tabId - Tab ID
 * @param {string} url - Full URL
 * @param {string} domain - Domain name
 */
function checkKnownUrl(tabId, url, domain) {
  // Check if already confirmed as phishing
  if (confirmedPhishingUrls.has(url) || confirmedPhishingUrls.has(domain)) {
    updateBadgeForTab(tabId, 'danger');
    showPhishingWarning(tabId, {
      url: url,
      domain: domain,
      reason: 'Previously confirmed phishing site'
    });
    return;
  }
  
  // Check if previously flagged as suspicious
  if (suspiciousUrls.has(url) || suspiciousUrls.has(domain)) {
    updateBadgeForTab(tabId, 'warning');
    return;
  }
  
  // Check if already confirmed as safe
  if (safeUrls.has(url) || safeUrls.has(domain)) {
    updateBadgeForTab(tabId, 'safe');
    return;
  }
  
  // Otherwise request API check
  checkUrlWithApi(tabId, url, domain);
}

/**
 * Check URL with backend API
 * @param {number} tabId - Tab ID
 * @param {string} url - Full URL
 * @param {string} domain - Domain name
 */
function checkUrlWithApi(tabId, url, domain) {
  // Make API request to check URL
  fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.checkUrl, {
    method: 'POST',
    headers: API_CONFIG.headers,
    body: JSON.stringify({
      url: url,
      domain: domain
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.isPhishing) {
      // Add to confirmed phishing list
      confirmedPhishingUrls.add(url);
      confirmedPhishingUrls.add(domain);
      
      // Update UI
      updateBadgeForTab(tabId, 'danger');
      showPhishingWarning(tabId, {
        url: url,
        domain: domain,
        reason: data.reason || 'URL matches known phishing patterns'
      });
    }
    else if (data.isSafe) {
      // Add to safe URLs
      safeUrls.add(url);
      safeUrls.add(domain);
      updateBadgeForTab(tabId, 'safe');
    }
    // Otherwise wait for content analysis results
  })
  .catch(error => {
    console.error('[PhishGuard] URL check API error:', error);
  });
}

/**
 * Handle content analysis request
 * @param {number} tabId - Tab ID
 * @param {Object} contentData - Page content data
 * @param {Function} sendResponse - Response function
 */
function handleAnalyzePageContent(tabId, contentData, sendResponse) {
  // Store content data
  if (!tabAnalysisData[tabId]) {
    tabAnalysisData[tabId] = {};
  }
  
  tabAnalysisData[tabId].contentData = contentData;
  
  // Make API request to analyze content
  fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.analyzeContent, {
    method: 'POST',
    headers: API_CONFIG.headers,
    body: JSON.stringify({
      url: contentData.url,
      domain: contentData.domain,
      title: contentData.title,
      description: contentData.metaDescription,
      textSample: contentData.textSample,
      hasLoginForm: contentData.hasLoginForm,
      forms: contentData.forms.map(form => ({
        action: form.action,
        method: form.method,
        isLoginForm: form.isLoginForm,
        isExternalAction: form.isExternalAction,
        inputCount: form.inputs ? form.inputs.length : 0,
        hasPasswordField: form.inputs ? form.inputs.some(input => input.type === 'password') : false
      }))
    })
  })
  .then(response => response.json())
  .then(data => {
    // Store NLP results
    tabAnalysisData[tabId].nlpResults = data;
    
    // Send results back to content script
    sendResponse({ nlpResults: data });
    
    // Also send to active tab in case response wasn't delivered
    chrome.tabs.sendMessage(tabId, {
      action: 'nlpResultsReady',
      data: data
    }).catch(err => {
      // Tab might be navigating or closed, ignore error
    });
  })
  .catch(error => {
    console.error('[PhishGuard] Content analysis API error:', error);
    sendResponse({ error: 'API request failed' });
  });
}

/**
 * Handle behavior analysis results
 * @param {number} tabId - Tab ID
 * @param {Object} data - Behavior analysis data
 */
function handleBehaviorAnalysis(tabId, data) {
  // Initialize tab data if needed
  if (!tabAnalysisData[tabId]) {
    tabAnalysisData[tabId] = {};
  }
  
  // Store behavior results
  tabAnalysisData[tabId].behaviorResults = data;
  
  // Check if this is high risk
  if (data.behaviorScore >= 70) {
    // Update badge immediately for high-risk behavior
    updateBadgeForTab(tabId, 'danger');
    
    // Get tab info to determine if warning needed
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError) return; // Tab closed
      
      // Show phishing warning if not already shown
      if (!phishingAlerts[tabId]) {
        showPhishingWarning(tabId, {
          url: tab.url,
          domain: new URL(tab.url).hostname,
          reason: 'Suspicious JavaScript behavior detected',
          details: data.detectedPatterns.map(p => p.details).flat().slice(0, 3),
          score: data.behaviorScore
        });
      }
    });
  }
  // Moderate risk - update badge only
  else if (data.behaviorScore >= 40) {
    updateBadgeForTab(tabId, 'warning');
  }
}

/**
 * Handle user interaction analysis results
 * @param {number} tabId - Tab ID
 * @param {Object} data - User interaction analysis data
 */
function handleUserInteractionAnalysis(tabId, data) {
  // Initialize tab data if needed
  if (!tabAnalysisData[tabId]) {
    tabAnalysisData[tabId] = {};
  }
  
  // Store interaction results
  tabAnalysisData[tabId].interactionResults = data;
  
  // Check if this is high risk
  if (data.interactionScore >= 70 && data.isLikelyPhishing) {
    // Update badge for high-risk user interaction patterns
    updateBadgeForTab(tabId, 'danger');
    
    // Get tab info to determine if warning needed
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError) return; // Tab closed
      
      // Show phishing warning if not already shown
      if (!phishingAlerts[tabId]) {
        showPhishingWarning(tabId, {
          url: tab.url,
          domain: new URL(tab.url).hostname,
          reason: 'Suspicious user interface/interaction patterns',
          details: data.details.slice(0, 3),
          score: data.interactionScore
        });
      }
    });
  }
  // Moderate risk - update badge only
  else if (data.interactionScore >= 50) {
    updateBadgeForTab(tabId, 'warning');
  }
}

/**
 * Handle combined analysis results
 * @param {number} tabId - Tab ID
 * @param {Object} data - Combined analysis data
 */
function handleCombinedAnalysis(tabId, data) {
  // Update full analysis data
  tabAnalysisData[tabId] = {
    ...tabAnalysisData[tabId],
    combinedResults: data,
    lastAnalysisTime: Date.now()
  };
  
  // Update badge based on combined risk
  if (data.isLikelyPhishing) {
    updateBadgeForTab(tabId, 'danger');
    
    // Add to suspicious URLs list
    suspiciousUrls.add(data.url);
    suspiciousUrls.add(data.domain);
    
    // Show warning if it's clearly phishing
    if (data.combinedScore >= 80 && !phishingAlerts[tabId]) {
      showPhishingWarning(tabId, {
        url: data.url,
        domain: data.domain,
        reason: 'Multiple phishing indicators detected',
        score: data.combinedScore
      });
      
      // Report to API if high confidence
      if (data.combinedScore >= 90) {
        reportPhishingToApi(data);
      }
    }
  } 
  else if (data.combinedScore >= 40) {
    updateBadgeForTab(tabId, 'warning');
    suspiciousUrls.add(data.url);
  }
  else {
    updateBadgeForTab(tabId, 'safe');
    safeUrls.add(data.url);
    safeUrls.add(data.domain);
  }
}

/**
 * Handle analysis update
 * @param {number} tabId - Tab ID
 * @param {Object} data - Analysis update data
 */
function handleAnalysisUpdate(tabId, data) {
  // Skip if we don't have previous data
  if (!tabAnalysisData[tabId] || !tabAnalysisData[tabId].combinedResults) return;
  
  // Get previous combined results
  const previous = tabAnalysisData[tabId].combinedResults;
  
  // Check if risk level increased significantly
  const behaviorIncrease = data.behavior.behaviorScore - 
                          (previous.behavior ? previous.behavior.behaviorScore : 0);
  
  const interactionIncrease = data.interaction.interactionScore -
                             (previous.interaction ? previous.interaction.interactionScore : 0);
  
  // If significant risk increase, update badge and potentially warn
  if (behaviorIncrease > 20 || interactionIncrease > 20) {
    // Recalculate combined score
    const nlpWeight = previous.nlp ? 0.4 : 0;
    const behaviorWeight = 0.35;
    const interactionWeight = 0.25;
    
    const newScore = Math.round(
      (previous.nlp ? (previous.nlp.nlpScore * nlpWeight) : 0) +
      (data.behavior.behaviorScore * behaviorWeight) +
      (data.interaction.interactionScore * interactionWeight)
    );
    
    // Update stored data
    tabAnalysisData[tabId].combinedResults.combinedScore = newScore;
    tabAnalysisData[tabId].combinedResults.isLikelyPhishing = newScore >= 70;
    tabAnalysisData[tabId].combinedResults.behavior = data.behavior;
    tabAnalysisData[tabId].combinedResults.interaction = data.interaction;
    
    // Update UI based on new score
    if (newScore >= 70) {
      updateBadgeForTab(tabId, 'danger');
      
      // Show warning if significant change and not already warned
      if (!phishingAlerts[tabId] && (behaviorIncrease > 30 || interactionIncrease > 30)) {
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError) return; // Tab closed
          
          showPhishingWarning(tabId, {
            url: tab.url,
            domain: new URL(tab.url).hostname,
            reason: 'Phishing behavior detected after page interaction',
            score: newScore
          });
        });
      }
    }
    else if (newScore >= 40) {
      updateBadgeForTab(tabId, 'warning');
    }
  }
}

/**
 * Update badge for tab
 * @param {number} tabId - Tab ID
 * @param {string} status - Status ('safe', 'warning', 'danger', 'scanning')
 */
function updateBadgeForTab(tabId, status) {
  let text = '';
  let color = '#5D87E8';
  
  switch (status) {
    case 'safe':
      text = '✓';
      color = '#4CAF50';
      break;
    case 'warning':
      text = '!';
      color = '#FF9800';
      break;
    case 'danger':
      text = '!!';
      color = '#F44336';
      break;
    case 'scanning':
      text = '...';
      color = '#5D87E8';
      break;
  }
  
  chrome.action.setBadgeText({ text: text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
}

/**
 * Show phishing warning
 * @param {number} tabId - Tab ID
 * @param {Object} data - Warning data
 */
function showPhishingWarning(tabId, data) {
  try {
    // Record that we've shown an alert for this tab
    phishingAlerts[tabId] = true;
    
    // Check if notifications API is available
    if (chrome.notifications && typeof chrome.notifications.create === 'function') {
      // Create notification
      chrome.notifications.create(`phishing-alert-${tabId}`, {
        type: 'basic',
        iconUrl: '../images/icon128.jpg',
        title: 'Phishing Warning!',
        message: `Suspicious site detected: ${data.domain}\nReason: ${data.reason}`,
        priority: 2,
        buttons: [
          { title: 'Close Tab' },
          { title: 'Ignore' }
        ]
      }, notificationId => {
        // Handle potential error in notification creation
        if (chrome.runtime.lastError) {
          console.warn('Notification creation error:', chrome.runtime.lastError);
        }
      });
      
      // Handle notification button clicks
      chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
        if (notificationId === `phishing-alert-${tabId}`) {
          if (buttonIndex === 0) {
            // Close the tab
            chrome.tabs.remove(tabId);
          } else {
            // Ignore - dismiss notification
            chrome.notifications.clear(notificationId);
          }
        }
      });
    } else {
      // Notification API not available, fallback to console warning
      console.warn('Notifications API not available. Phishing site detected:', data.domain);
      
      // Update badge as a visual indicator
      updateBadgeForTab(tabId, 'danger');
    }
    
    // Update popup with alert info (do this regardless of notification availability)
    if (tabAnalysisData[tabId]) {
      tabAnalysisData[tabId].alert = {
        timestamp: Date.now(),
        url: data.url,
        domain: data.domain,
        reason: data.reason,
        details: data.details || [],
        score: data.score || 0
      };
    }
  } catch (error) {
    // Catch any other errors to prevent the extension from crashing
    console.error('Error showing phishing warning:', error);
  }
}

/**
 * Report phishing site to API
 * @param {Object} data - Phishing data
 */
function reportPhishingToApi(data) {
  fetch(API_CONFIG.baseUrl + API_CONFIG.endpoints.reportPhishing, {
    method: 'POST',
    headers: API_CONFIG.headers,
    body: JSON.stringify({
      url: data.url,
      domain: data.domain,
      score: data.combinedScore,
      nlpScore: data.nlp.nlpScore,
      behaviorScore: data.behavior.behaviorScore,
      interactionScore: data.interaction.interactionScore,
      indicators: [
        ...(data.nlp.indicators || []),
        ...(data.behavior.detectedPatterns || []).map(p => p.type + ': ' + p.details.join(', ')),
        ...(data.interaction.details || [])
      ],
      timestamp: Date.now()
    })
  })
  .then(response => response.json())
  .then(result => {
    console.log('[PhishGuard] Phishing report submitted:', result);
    
    // If confirmed, add to confirmed list
    if (result.confirmed) {
      confirmedPhishingUrls.add(data.url);
      confirmedPhishingUrls.add(data.domain);
    }
  })
  .catch(error => {
    console.error('[PhishGuard] Error reporting phishing:', error);
  });
}

/**
 * Handle tab removed
 * @param {number} tabId - Tab ID
 */
function handleTabRemoved(tabId) {
  // Clean up data for this tab
  delete tabAnalysisData[tabId];
  delete phishingAlerts[tabId];
}

/**
 * Reset tab analysis data
 * @param {number} tabId - Tab ID
 */
function resetTabAnalysis(tabId) {
  tabAnalysisData[tabId] = {};
  phishingAlerts[tabId] = false;
}

/**
 * Reset extension state
 */
function resetExtensionState() {
  // Clear all stored data
  Object.keys(tabAnalysisData).forEach(key => delete tabAnalysisData[key]);
  Object.keys(phishingAlerts).forEach(key => delete phishingAlerts[key]);
  
  // Maintain small cache of known URLs
  if (confirmedPhishingUrls.size > 1000) {
    confirmedPhishingUrls.clear();
  }
  if (suspiciousUrls.size > 1000) {
    suspiciousUrls.clear();
  }
  if (safeUrls.size > 5000) {
    safeUrls.clear();
  }
}

/**
 * Perform basic client-side URL check
 * @param {string} url - Full URL
 * @param {string} domain - Domain name
 * @returns {Object} Check result
 */
function performBasicUrlCheck(url, domain) {
  const indicators = [];
  let isSafe = true;
  
  // Check for HTTP protocol (non-HTTPS) - ALWAYS UNSAFE
  if (url.startsWith('http:')) {
    indicators.push('Non-secure HTTP connection (not using HTTPS)');
    isSafe = false;
  }
  
  // Check for IP address instead of domain
  if (/^https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
    indicators.push('IP address used instead of domain name');
    isSafe = false;
  }
  
  // Check for suspicious TLDs
  const suspiciousTLDs = phishingPatterns.suspiciousTLDs;
  if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
    indicators.push('Domain uses suspicious TLD');
    isSafe = false;
  }
  
  // Check for too many subdomains
  const subdomainCount = domain.split('.').length - 1;
  if (subdomainCount > 3) {
    indicators.push('Excessive number of subdomains');
    isSafe = false;
  }
  
  // Check for unusual port
  const urlObj = new URL(url);
  if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
    indicators.push('Unusual port number in URL');
    isSafe = false;
  }
  
  // Check for encoded characters
  if (/%[0-9a-f]{2}/i.test(url)) {
    indicators.push('URL contains encoded characters');
    isSafe = false;
  }
  
  // Enhanced brand impersonation check - more comprehensive list of brands
  const commonBrands = phishingPatterns.targetedBrands;

  // Check for brand name in subdomain (more aggressive pattern matching)
  const domainParts = domain.split('.');
  const isSubdomain = domainParts.length > 2;
  const rootDomain = domainParts.slice(-2).join('.');
  const subdomains = domainParts.slice(0, -2).join('.');
  
  // Check for brand impersonation in subdomain
  if (isSubdomain && commonBrands.some(brand => 
    subdomains.toLowerCase().includes(brand.toLowerCase()))) {
    indicators.push('Subdomain contains major brand name (likely impersonation)');
    isSafe = false;
  }
  
  // Check for brand name but not as the main domain
  if (commonBrands.some(brand => {
    return domain.toLowerCase().includes(brand.toLowerCase()) && 
          !domain.toLowerCase().endsWith(`.${brand.toLowerCase()}.com`);
  })) {
    indicators.push('Domain contains common brand name (potential spoofing)');
    isSafe = false;
  }
  
  // Check for abbreviated brand names in domain (like "nu" for Nubank)
  for (const brand of phishingPatterns.targetedBrands) {
    // Check for 2-3 letter abbreviations
    if (brand.length > 3) {
      const prefix = brand.substring(0, 2);
      
      // Various patterns: hj-nu.shop, nu-shop.xyz, etc.
      if (domain.includes(`-${prefix}`) || 
          domain.includes(`${prefix}-`) || 
          domain.includes(`.${prefix}.`) || 
          domain.startsWith(`${prefix}.`)) {
        
        // Make sure it's not a legitimate domain
        if (!phishingPatterns.legitimateBankingDomains.includes(domain)) {
          indicators.push(`Domain contains abbreviated brand name "${prefix}" from "${brand}" (likely impersonation)`);
          isSafe = false;
          break;
        }
      }
    }
  }
  
  // Check for suspicious numeric patterns in subdomains (common in phishing)
  if (/[a-z]+\d{4,}/.test(subdomains) || /\d{4,}[a-z]+/.test(subdomains)) {
    indicators.push('Subdomain contains suspicious numeric sequence');
    isSafe = false;
  }
  
  // Check for free hosting services (common for phishing sites)
  const freeHostingServices = phishingPatterns.freeHostingServices;
  
  if (freeHostingServices.some(service => domain.toLowerCase().endsWith(service))) {
    // If it's a free hosting service AND contains a brand name, it's very suspicious
    if (commonBrands.some(brand => domain.toLowerCase().includes(brand.toLowerCase()))) {
      indicators.push('Brand impersonation on free hosting platform (high risk)');
      isSafe = false;
    } else {
      indicators.push('Site hosted on free website platform');
      // Make it suspicious but not definitively unsafe
      if (isSafe === true) isSafe = false; // Always mark free hosting as potentially unsafe
    }
  }
  
  // Check for suspicious keywords in domain
  const suspiciousKeywords = phishingPatterns.suspiciousKeywords;
  
  if (suspiciousKeywords.some(keyword => domain.toLowerCase().includes(keyword.toLowerCase()))) {
    indicators.push('Domain contains suspicious keywords (possible social engineering)');
    isSafe = false;
  }
  
  // Additional checks for known bad patterns from phishingPatterns
  // If domain is in knownBadDomains list or matches any brandWithSuspicious pattern
  if (phishingPatterns.knownBadDomains.some(badDomain => 
      domain.toLowerCase().includes(badDomain.toLowerCase()))) {
    indicators.push('Domain matches known phishing pattern');
    isSafe = false;
  }
  
  // Check for combinations of brand names and suspicious terms
  if (phishingPatterns.brandWithSuspicious.some(pattern => 
      domain.toLowerCase().includes(pattern.toLowerCase()))) {
    indicators.push('Domain contains suspicious brand pattern combination');
    isSafe = false;
  }
  
  // Check suspicious URL patterns (specifically for abbreviated brands like hj-nu.shop)
  for (const pattern of phishingPatterns.suspiciousUrlPatterns) {
    if (pattern.test(url)) {
      indicators.push('URL follows suspicious pattern common in phishing campaigns');
      isSafe = false;
      break;
    }
  }
  
  // Check for suspicious URL path patterns (like /nun/, /cpf/, /consulta/)
  const urlPath = new URL(url).pathname;
  if (/\/[a-z]{2,4}\/$/i.test(urlPath)) {
    indicators.push('URL path uses suspicious short directory pattern');
    isSafe = false;
  }
  
  // Check for CPF (Brazilian Tax ID) request patterns
  if (url.toLowerCase().includes('/cpf') || 
      url.toLowerCase().includes('consulte') || 
      url.toLowerCase().includes('indenizacao') || 
      url.toLowerCase().includes('indenização')) {
    indicators.push('URL contains Brazilian document request terminology (high-risk phishing indicator)');
    isSafe = false;
  }
  
  // Check for payment-related phishing patterns
  if (phishingPatterns.paymentTerms.some(term => domain.toLowerCase().includes(term.toLowerCase()))) {
    // If domain contains payment terms but isn't a legitimate payment provider
    const isLegitimatePaymentDomain = phishingPatterns.legitimateBankingDomains.some(
      legitimate => domain.endsWith(legitimate)
    );
    
    if (!isLegitimatePaymentDomain) {
      indicators.push('Domain contains payment-related terms but is not a legitimate payment provider');
      isSafe = false;
    }
  }
  
  // Check for common misspellings of legitimate service domains
  for (const misspellingGroup of phishingPatterns.commonMisspellings) {
    for (const misspelled of misspellingGroup.misspelled) {
      if (domain.toLowerCase().includes(misspelled.toLowerCase())) {
        indicators.push(`Domain contains commonly misspelled term "${misspelled}" (should be "${misspellingGroup.correct}")`);
        isSafe = false;
        break;
      }
    }
  }
  
  // Check for "suport" specifically (common in Brazilian phishing)
  if (domain.toLowerCase().includes('suport')) {
    indicators.push('Domain contains misspelled "support" term (missing "p")');
    isSafe = false;
  }
  
  // Check for payment portal indicators
  const paymentPortalIndicators = [
    /boleto/i, /segunda.?via/i, /2.?via/i, /emitir/i, /fatura/i, 
    /payment/i, /portal/i, /cliente/i, /factura/i, /pagar/i
  ];
  
  for (const regex of paymentPortalIndicators) {
    if (regex.test(domain)) {
      // If it's a payment-related domain that's not a known legitimate provider
      const isLegitimatePortal = phishingPatterns.legitimateBankingDomains.some(
        legitimate => domain.endsWith(legitimate)
      );
        
      if (!isLegitimatePortal) {
        indicators.push('Domain appears to be impersonating a payment portal');
        isSafe = false;
      }
      break;
    }
  }
  
  // Check for RegEx patterns (scan the full URL)
  for (const pattern of phishingPatterns.phishingRegexPatterns) {
    if (pattern.test(url)) {
      indicators.push('URL matches suspicious pattern typically used in phishing');
      isSafe = false;
      break;
    }
  }
  
  // Check for Brazilian financial terminology
  if (phishingPatterns.brazilianFinancialTerms.some(term => url.toLowerCase().includes(term.toLowerCase()))) {
    // If domain isn't a legitimate Brazilian financial institution
    const isLegitimateBrazilianBank = phishingPatterns.legitimateBankingDomains.some(
      legitimate => legitimate.includes('.br') && domain.endsWith(legitimate)
    );
    
    if (!isLegitimateBrazilianBank) {
      indicators.push('URL contains Brazilian financial terminology on unofficial domain');
      isSafe = false;
    }
  }
  
  // Check specifically for Nubank impersonation on unofficial domains
  if ((domain.includes('nu') || domain.includes('nubank')) && 
      !domain.endsWith('nubank.com.br')) {
    indicators.push('Domain appears to be impersonating Nubank');
    isSafe = false;
  }
  
  // If we found ANY indicators, the site is not safe
  if (indicators.length > 0) {
    isSafe = false;
  }
  
  console.log(`[BasicUrlCheck] URL: ${url}, Safe: ${isSafe}, Indicators: ${indicators.length}`);
  
  return {
    isSafe,
    indicators
  };
}

