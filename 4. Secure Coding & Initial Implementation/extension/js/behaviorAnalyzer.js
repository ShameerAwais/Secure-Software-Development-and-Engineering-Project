/**
 * Behavior Analyzer for Phishing Detection
 * 
 * This module monitors JavaScript behavior on webpages for suspicious
 * patterns common in phishing attacks, such as form hijacking, keystroke logging,
 * and redirect chains.
 */

class BehaviorAnalyzer {
  constructor() {
    // Patterns we're monitoring for
    this.suspiciousPatterns = {
      formHijacking: { weight: 0.8, detected: false, details: [] },
      keyLogging: { weight: 0.9, detected: false, details: [] },
      redirectChain: { weight: 0.6, detected: false, details: [] },
      cookieTheft: { weight: 0.7, detected: false, details: [] },
      invisibleIframes: { weight: 0.7, detected: false, details: [] },
      popupAbuse: { weight: 0.5, detected: false, details: [] },
      eventBlockers: { weight: 0.6, detected: false, details: [] }
    };
    
    this.originalFunctions = {};
    this.monitoringActive = false;
    this.detectedEvents = [];
    this.behaviorScore = 0;
    this.redirectCount = 0;
    this.originalDomain = window.location.hostname;
    
    // Store references to sensitive form elements
    this.sensitiveInputs = new WeakMap();
  }
  
  /**
   * Initialize behavior monitoring
   */
  startMonitoring() {
    if (this.monitoringActive) return;
    
    console.log('[BehaviorAnalyzer] Starting behavior monitoring');
    this.monitoringActive = true;
    
    this.trackForms();
    this.monitorEventListeners();
    this.interceptJavaScriptAPIs();
    this.monitorRedirects();
    this.checkIframes();
    this.monitorPopups();
    
    // Re-check after a delay to find dynamic content
    setTimeout(() => {
      this.trackForms();
      this.checkIframes();
    }, 2000);
  }
  
  /**
   * Stop monitoring and restore original functionality
   */
  stopMonitoring() {
    this.monitoringActive = false;
    // Restore original functions if needed
    for (const [name, originalFunction] of Object.entries(this.originalFunctions)) {
      try {
        const parts = name.split('.');
        if (parts.length === 2) {
          window[parts[0]][parts[1]] = originalFunction;
        } else {
          window[name] = originalFunction;
        }
      } catch (e) {
        console.error(`[BehaviorAnalyzer] Error restoring ${name}:`, e);
      }
    }
  }
  
  /**
   * Track forms and monitor for hijacking
   */
  trackForms() {
    // Find all forms
    const forms = document.querySelectorAll('form');
    
    forms.forEach((form, index) => {
      // Store original action
      const originalAction = form.action;
      
      // Check for password fields to mark sensitive forms
      const hasPasswordField = Array.from(form.elements).some(el => el.type === 'password');
      
      // Monitor form action changes
      this.observeFormAction(form, originalAction, hasPasswordField);
      
      // Monitor password fields for suspicious event listeners
      if (hasPasswordField) {
        const passwordFields = Array.from(form.elements).filter(el => el.type === 'password');
        
        passwordFields.forEach(field => {
          // Track this input as sensitive
          this.sensitiveInputs.set(field, {
            form: form,
            originalForm: form.cloneNode(true),
            events: []
          });
          
          // Monitor keydown/keyup events
          this.monitorFieldEvents(field);
        });
      }
    });
  }
  
  /**
   * Monitor for changes to form action attribute
   * @param {HTMLFormElement} form - Form to monitor
   * @param {string} originalAction - Original action URL
   * @param {boolean} isSensitive - Whether form contains sensitive data
   */
  observeFormAction(form, originalAction, isSensitive) {
    // Create MutationObserver to watch for attribute changes
    const observer = new MutationObserver(mutations => {
      for (const mutation of mutations) {
        if (mutation.type === 'attributes' && mutation.attributeName === 'action') {
          const newAction = form.action;
          
          // Check if action changed to a different domain
          try {
            const originalDomain = new URL(originalAction).hostname;
            const newDomain = new URL(newAction).hostname;
            
            if (originalDomain !== newDomain) {
              const details = `Form action changed from ${originalAction} to ${newAction}`;
              this.recordSuspiciousEvent('formHijacking', details, 0.8);
              
              // Higher score for sensitive forms
              if (isSensitive) {
                this.recordSuspiciousEvent('formHijacking', 
                  'Password form submission redirected to external domain', 0.9);
              }
            }
          } catch (e) {
            // URL parsing error, likely due to relative URLs
          }
        }
      }
    });
    
    // Start observing
    observer.observe(form, { attributes: true });
  }
  
  /**
   * Monitor keyboard events on sensitive fields
   * @param {HTMLElement} field - Input field to monitor
   */
  monitorFieldEvents(field) {
    const originalAddEventListener = field.addEventListener;
    
    // Store reference to original function
    this.originalFunctions[`${field}.addEventListener`] = originalAddEventListener;
    
    // Override addEventListener to track events on this field
    field.addEventListener = (type, handler, options) => {
      // Call original function
      originalAddEventListener.call(field, type, handler, options);
      
      // Track potentially suspicious events
      if (type === 'keydown' || type === 'keyup' || type === 'keypress' || type === 'input') {
        const fieldInfo = this.sensitiveInputs.get(field);
        
        if (fieldInfo) {
          fieldInfo.events.push({
            type,
            handler: handler.toString(),
            timestamp: Date.now()
          });
          
          // Check if this is outside a form submit event (potential keylogging)
          if (type.startsWith('key') && handler.toString().includes('send') || 
              handler.toString().includes('post') || 
              handler.toString().includes('ajax')) {
            
            this.recordSuspiciousEvent('keyLogging', 
              `Keyboard event on password field with suspicious handler`, 0.7);
          }
        }
      }
    };
  }
  
  /**
   * Intercept and monitor key JavaScript APIs used in phishing attacks
   */
  interceptJavaScriptAPIs() {
    // Monitor XMLHttpRequest
    this.interceptXHR();
    
    // Monitor fetch API
    this.interceptFetch();
    
    // Monitor cookie access
    this.interceptCookies();
    
    // Monitor navigation and history manipulation
    this.interceptHistoryAPI();
  }
  
  /**
   * Intercept XMLHttpRequest to detect data exfiltration
   */
  interceptXHR() {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    const analyzer = this;
    
    this.originalFunctions['XMLHttpRequest.prototype.open'] = originalOpen;
    
    XMLHttpRequest.prototype.open = function(method, url, ...args) {
      try {
        // Check if data is being sent to an external domain
        let externalRequest = false;
        
        try {
          const targetDomain = new URL(url, window.location.href).hostname;
          externalRequest = targetDomain !== analyzer.originalDomain;
          
          // Check if this request immediately follows sensitive input interaction
          if (externalRequest && analyzer.recentSensitiveInputActivity()) {
            analyzer.recordSuspiciousEvent('formHijacking', 
              `XHR sending data to external domain: ${targetDomain}`, 0.7);
          }
        } catch (e) {
          // URL parsing error
        }
      } catch (e) {
        // Do nothing on error
      }
      
      // Call original
      return originalOpen.apply(this, [method, url, ...args]);
    };
    
    // Monitor what's being sent
    this.originalFunctions['XMLHttpRequest.prototype.send'] = originalSend;
    
    XMLHttpRequest.prototype.send = function(data) {
      try {
        if (data && typeof data === 'string') {
          // Check for password or credential data
          if (data.includes('password') || data.includes('credential') || 
              data.includes('passwd') || data.includes('login')) {
            
            analyzer.recordSuspiciousEvent('formHijacking', 
              'XHR sending credentials', 0.6);
          }
        }
      } catch (e) {
        // Do nothing on error
      }
      
      // Call original
      return originalSend.apply(this, arguments);
    };
  }
  
  /**
   * Intercept fetch API
   */
  interceptFetch() {
    const originalFetch = window.fetch;
    const analyzer = this;
    
    this.originalFunctions['fetch'] = originalFetch;
    
    window.fetch = function(resource, options) {
      try {
        const url = typeof resource === 'string' ? resource : resource.url;
        
        // Check if data is being sent to an external domain
        try {
          const targetDomain = new URL(url, window.location.href).hostname;
          const externalRequest = targetDomain !== analyzer.originalDomain;
          
          // Check if this fetch follows sensitive input interaction
          if (externalRequest && analyzer.recentSensitiveInputActivity()) {
            analyzer.recordSuspiciousEvent('formHijacking', 
              `Fetch sending data to external domain: ${targetDomain}`, 0.7);
          }
          
          // Check if sending potentially sensitive data
          if (options && options.body && typeof options.body === 'string') {
            if (options.body.includes('password') || options.body.includes('credential')) {
              analyzer.recordSuspiciousEvent('formHijacking', 'Fetch sending credentials', 0.6);
            }
          }
        } catch (e) {
          // URL parsing error
        }
      } catch (e) {
        // Do nothing on error
      }
      
      // Call original
      return originalFetch.apply(this, arguments);
    };
  }
  
  /**
   * Intercept cookie access
   */
  interceptCookies() {
    const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    const analyzer = this;
    
    // Store original for restoration
    this.originalFunctions['cookie'] = originalCookieDescriptor;
    
    if (originalCookieDescriptor && originalCookieDescriptor.configurable) {
      Object.defineProperty(Document.prototype, 'cookie', {
        get: function() {
          return originalCookieDescriptor.get.call(this);
        },
        set: function(value) {
          try {
            // Check for session cookie theft attempts
            if (value.includes('document.cookie') || value.includes('session')) {
              analyzer.recordSuspiciousEvent('cookieTheft', 
                'Potential session cookie manipulation', 0.7);
            }
          } catch (e) {
            // Ignore errors
          }
          
          return originalCookieDescriptor.set.call(this, value);
        },
        configurable: true
      });
    }
  }
  
  /**
   * Intercept history API to detect navigation manipulation
   */
  interceptHistoryAPI() {
    ['pushState', 'replaceState'].forEach(method => {
      const original = window.history[method];
      const analyzer = this;
      
      this.originalFunctions[`history.${method}`] = original;
      
      window.history[method] = function(...args) {
        try {
          analyzer.recordSuspiciousEvent('redirectChain', 
            `History API used: ${method}`, 0.2);
            
          // Higher score if multiple history manipulations in short time
          if (analyzer.detectedEvents.filter(
              e => e.type === 'redirectChain' && 
              Date.now() - e.timestamp < 5000).length >= 2) {
            
            analyzer.recordSuspiciousEvent('redirectChain', 
              'Multiple history manipulations detected', 0.6);
          }
        } catch (e) {
          // Ignore errors
        }
        
        // Call original
        return original.apply(this, args);
      };
    });
  }
  
  /**
   * Monitor for navigation and redirect chains
   */
  monitorRedirects() {
    // Track page navigations
    let previousUrl = window.location.href;
    
    // Check for rapid redirects
    setInterval(() => {
      const currentUrl = window.location.href;
      
      if (currentUrl !== previousUrl) {
        this.redirectCount++;
        previousUrl = currentUrl;
        
        // Multiple redirects in short time are suspicious
        if (this.redirectCount >= 2) {
          this.recordSuspiciousEvent('redirectChain', 
            `Multiple redirects detected (count: ${this.redirectCount})`, 0.5);
        }
      }
    }, 1000);
  }
  
  /**
   * Check for hidden or zero-opacity iframes (common in clickjacking)
   */
  checkIframes() {
    const iframes = document.querySelectorAll('iframe');
    
    iframes.forEach(iframe => {
      // Get computed style
      const style = window.getComputedStyle(iframe);
      
      // Check if iframe is hidden or tiny
      if (style.display === 'none' || 
          style.visibility === 'hidden' || 
          style.opacity === '0' ||
          parseInt(style.width) <= 2 ||
          parseInt(style.height) <= 2) {
        
        this.recordSuspiciousEvent('invisibleIframes', 
          'Hidden iframe detected', 0.7);
      }
      
      // Check if iframe source is on a different domain
      try {
        if (iframe.src) {
          const iframeDomain = new URL(iframe.src).hostname;
          
          if (iframeDomain !== this.originalDomain) {
            this.recordSuspiciousEvent('invisibleIframes', 
              `Cross-domain iframe from ${iframeDomain}`, 0.3);
          }
        }
      } catch (e) {
        // URL parsing error
      }
    });
  }
  
  /**
   * Monitor popup creation and behavior
   */
  monitorPopups() {
    // Intercept window.open
    const originalOpen = window.open;
    const analyzer = this;
    
    this.originalFunctions['window.open'] = originalOpen;
    
    window.open = function(...args) {
      try {
        analyzer.recordSuspiciousEvent('popupAbuse', 
          'Popup created', 0.3);
          
        // Multiple popups are highly suspicious
        if (analyzer.detectedEvents.filter(
            e => e.type === 'popupAbuse' && 
            Date.now() - e.timestamp < 10000).length >= 2) {
          
          analyzer.recordSuspiciousEvent('popupAbuse', 
            'Multiple popups detected', 0.6);
        }
      } catch (e) {
        // Ignore errors
      }
      
      // Call original
      return originalOpen.apply(this, args);
    };
    
    // Monitor modal dialogs
    ['alert', 'confirm', 'prompt'].forEach(method => {
      const original = window[method];
      
      this.originalFunctions[method] = original;
      
      window[method] = function(...args) {
        try {
          analyzer.recordSuspiciousEvent('popupAbuse', 
            `Dialog used: ${method}`, 0.2);
            
          // Multiple dialogs are suspicious
          if (analyzer.detectedEvents.filter(
              e => e.type === 'popupAbuse' && 
              Date.now() - e.timestamp < 10000).length >= 2) {
            
            analyzer.recordSuspiciousEvent('popupAbuse', 
              'Multiple dialogs detected', 0.5);
          }
        } catch (e) {
          // Ignore errors
        }
        
        // Call original
        return original.apply(this, args);
      };
    });
  }
  
  /**
   * Monitor modification of event handlers for suspicious behavior
   */
  monitorEventListeners() {
    const eventTypesToMonitor = ['beforeunload', 'unload', 'blur'];
    const originalAddEventListener = window.addEventListener;
    const analyzer = this;
    
    this.originalFunctions['window.addEventListener'] = originalAddEventListener;
    
    window.addEventListener = function(type, handler, options) {
      // Monitor specific event types
      if (eventTypesToMonitor.includes(type)) {
        analyzer.recordSuspiciousEvent('eventBlockers', 
          `Added ${type} event handler`, 0.4);
          
        // Check for navigation blocking
        if (type === 'beforeunload' && handler && handler.toString().includes('return')) {
          analyzer.recordSuspiciousEvent('eventBlockers', 
            'Navigation blocking detected', 0.6);
        }
      }
      
      // Call original
      return originalAddEventListener.apply(this, arguments);
    };
  }
  
  /**
   * Check if there was recent activity on sensitive input fields
   * @returns {boolean} Whether there was recent sensitive input activity
   */
  recentSensitiveInputActivity() {
    let recentActivity = false;
    
    // Check all tracked sensitive inputs
    this.sensitiveInputs.forEach((info, field) => {
      // Look for recent events (within last 5 seconds)
      const recentEvents = info.events.filter(
        e => Date.now() - e.timestamp < 5000
      );
      
      if (recentEvents.length > 0) {
        recentActivity = true;
      }
    });
    
    return recentActivity;
  }
  
  /**
   * Record a suspicious event
   * @param {string} type - Type of suspicious pattern
   * @param {string} details - Description of the event
   * @param {number} weight - How suspicious this event is (0-1)
   */
  recordSuspiciousEvent(type, details, weight) {
    // Only record if this pattern exists in our monitoring list
    if (this.suspiciousPatterns[type]) {
      // Mark pattern as detected
      this.suspiciousPatterns[type].detected = true;
      
      // Add details if not already recorded
      if (!this.suspiciousPatterns[type].details.includes(details)) {
        this.suspiciousPatterns[type].details.push(details);
      }
      
      // Add to event log
      this.detectedEvents.push({
        type,
        details,
        weight,
        timestamp: Date.now()
      });
      
      // Update behavior score
      this.behaviorScore = this.calculateBehaviorScore();
      
      // Report event immediately if severe enough
      if (weight > 0.7) {
        this.reportBehaviorAnalysis();
      }
    }
  }
  
  /**
   * Calculate overall behavior score based on detected patterns
   * @returns {number} Behavior score between 0-100
   */
  calculateBehaviorScore() {
    let score = 0;
    let patternCount = 0;
    
    // Calculate score from detected patterns
    for (const [type, pattern] of Object.entries(this.suspiciousPatterns)) {
      if (pattern.detected) {
        // More details = higher confidence
        const detailFactor = Math.min(pattern.details.length / 2, 1);
        
        // Add weighted score for this pattern
        score += pattern.weight * (0.7 + (0.3 * detailFactor)) * 100;
        patternCount++;
      }
    }
    
    // Apply a bonus for multiple pattern types (indicates more sophisticated attack)
    if (patternCount > 1) {
      score *= (1 + (patternCount - 1) * 0.1);
    }
    
    // Cap at 100
    return Math.min(Math.round(score), 100);
  }
  
  /**
   * Get current analysis results for reporting
   * @returns {Object} Analysis results
   */
  getBehaviorAnalysis() {
    const detectedPatterns = [];
    
    for (const [type, pattern] of Object.entries(this.suspiciousPatterns)) {
      if (pattern.detected) {
        detectedPatterns.push({
          type,
          confidence: pattern.weight,
          details: pattern.details.slice(0, 3) // Limit to top 3 details
        });
      }
    }
    
    return {
      behaviorScore: this.behaviorScore,
      isPhishing: this.behaviorScore >= 70,
      detectedPatterns: detectedPatterns.sort((a, b) => b.confidence - a.confidence),
      detectedEventCount: this.detectedEvents.length,
      timestamp: Date.now()
    };
  }
  
  /**
   * Report current behavior analysis to the background script
   */
  reportBehaviorAnalysis() {
    // Only report if we have something suspicious
    if (this.behaviorScore > 0) {
      chrome.runtime.sendMessage({
        action: 'reportBehaviorAnalysis',
        data: this.getBehaviorAnalysis()
      });
    }
  }
}

// Create a global instance that content.js can use
window.behaviorAnalyzer = new BehaviorAnalyzer();

// For backward compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = window.behaviorAnalyzer;
}