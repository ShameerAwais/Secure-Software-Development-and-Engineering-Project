/**
 * User Interaction Analyzer for Phishing Detection
 * 
 * This module monitors user interactions with the webpage to detect
 * suspicious patterns often used in phishing attacks, such as:
 * - Forced user flows and restricted navigation
 * - Deceptive UI elements that manipulate user behavior
 * - Suspicious input timing patterns
 */

class UserInteractionAnalyzer {
  constructor() {
    this.interactions = [];
    this.interactionHeatmap = {}; // Track click locations
    this.pageLoadTime = Date.now();
    this.navigationAttempts = 0;
    this.monitoringActive = false;
    this.suspiciousPatterns = {
      restrictedNavigation: { detected: false, score: 0, details: [] },
      forcedInteraction: { detected: false, score: 0, details: [] },
      unusualTiming: { detected: false, score: 0, details: [] },
      deceptiveElements: { detected: false, score: 0, details: [] }
    };
    this.interactionScore = 0;
    this.lastReportTime = 0;
    
    // Tracked sensitive fields
    this.sensitiveFields = new Set();
  }
  
  /**
   * Start monitoring user interactions
   */
  startMonitoring() {
    if (this.monitoringActive) return;
    
    console.log('[UserInteractionAnalyzer] Starting user interaction monitoring');
    this.monitoringActive = true;
    this.pageLoadTime = Date.now();
    
    // Track user interactions
    this.attachEventListeners();
    
    // Track form fields
    this.identifySensitiveFields();
    
    // Analyze page for deceptive UI elements
    this.analyzePageUI();
    
    // Check again after a delay to catch dynamically added elements
    setTimeout(() => {
      this.identifySensitiveFields();
      this.analyzePageUI();
    }, 2000);
    
    // Periodically check for restricted navigation attempts
    setInterval(() => this.checkForRestrictedNavigation(), 5000);
    
    // Schedule periodic reports
    setInterval(() => this.reportInteractionAnalysis(), 10000);
  }
  
  /**
   * Stop all monitoring
   */
  stopMonitoring() {
    if (!this.monitoringActive) return;
    
    console.log('[UserInteractionAnalyzer] Stopping user interaction monitoring');
    this.monitoringActive = false;
    
    // Clean up event listeners
    document.removeEventListener('click', this.handleClick);
    document.removeEventListener('keydown', this.handleKeyDown);
    window.removeEventListener('beforeunload', this.handleBeforeUnload);
    
    // Final report
    this.reportInteractionAnalysis();
  }
  
  /**
   * Attach event listeners to track user interactions
   */
  attachEventListeners() {
    // Track mouse clicks
    this.handleClick = this.recordClick.bind(this);
    document.addEventListener('click', this.handleClick, true);
    
    // Track keyboard inputs
    this.handleKeyDown = this.recordKeyDown.bind(this);
    document.addEventListener('keydown', this.handleKeyDown, true);
    
    // Track navigation attempts
    this.handleBeforeUnload = this.recordNavigationAttempt.bind(this);
    window.addEventListener('beforeunload', this.handleBeforeUnload);
    
    // Track form submissions
    document.querySelectorAll('form').forEach(form => {
      form.addEventListener('submit', this.recordFormSubmission.bind(this), true);
    });
    
    // Track tab/window visibility changes
    document.addEventListener('visibilitychange', this.recordVisibilityChange.bind(this));
  }
  
  /**
   * Identify and track sensitive input fields
   */
  identifySensitiveFields() {
    // Find password fields
    document.querySelectorAll('input[type="password"]').forEach(input => {
      this.sensitiveFields.add(input);
      input.addEventListener('focus', () => this.recordSensitiveFieldInteraction(input, 'focus'));
      input.addEventListener('blur', () => this.recordSensitiveFieldInteraction(input, 'blur'));
    });
    
    // Find credit card fields
    document.querySelectorAll('input').forEach(input => {
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      
      // Check for credit card field indicators
      if (name.includes('card') || id.includes('card') || placeholder.includes('card') ||
          name.includes('credit') || id.includes('credit') || placeholder.includes('credit') ||
          name.includes('cc') || id.includes('cc')) {
        
        this.sensitiveFields.add(input);
        input.addEventListener('focus', () => this.recordSensitiveFieldInteraction(input, 'focus'));
        input.addEventListener('blur', () => this.recordSensitiveFieldInteraction(input, 'blur'));
      }
    });
  }
  
  /**
   * Record a mouse click
   * @param {MouseEvent} event - Click event
   */
  recordClick(event) {
    // Don't track clicks on extension UI
    if (event.target.closest('.web-safety-scanner-ui')) return;
    
    // Get click target info
    const target = event.target;
    const targetInfo = this.getElementInfo(target);
    
    // Record the interaction
    const interaction = {
      type: 'click',
      timestamp: Date.now(),
      timeSincePageLoad: Date.now() - this.pageLoadTime,
      target: targetInfo,
      position: {
        x: event.clientX,
        y: event.clientY,
        relativeX: event.clientX / window.innerWidth,
        relativeY: event.clientY / window.innerHeight
      }
    };
    
    this.interactions.push(interaction);
    
    // Update heatmap
    const heatmapKey = `${Math.floor(interaction.position.relativeX * 10)}_${Math.floor(interaction.position.relativeY * 10)}`;
    this.interactionHeatmap[heatmapKey] = (this.interactionHeatmap[heatmapKey] || 0) + 1;
    
    // Analyze click for unusual patterns
    this.analyzeClick(interaction);
  }
  
  /**
   * Get information about an element
   * @param {HTMLElement} element - The element to analyze
   * @returns {Object} Information about the element
   */
  getElementInfo(element) {
    if (!element || !element.tagName) return { type: 'unknown' };
    
    const tagName = element.tagName.toLowerCase();
    const id = element.id || '';
    const classNames = Array.from(element.classList || []).join(' ');
    const rect = element.getBoundingClientRect();
    
    // Check for links
    if (tagName === 'a') {
      const href = element.href || '';
      let targetDomain = '';
      
      try {
        targetDomain = new URL(href).hostname;
      } catch (e) {
        // Not a valid URL
      }
      
      return {
        type: 'link',
        href,
        targetDomain,
        text: element.innerText,
        id,
        classNames,
        size: {
          width: rect.width,
          height: rect.height
        }
      };
    }
    
    // Check for buttons
    if (tagName === 'button' || 
        (tagName === 'input' && (element.type === 'submit' || element.type === 'button'))) {
      return {
        type: 'button',
        text: element.innerText || element.value || '',
        id,
        classNames,
        inputType: element.type,
        size: {
          width: rect.width,
          height: rect.height
        }
      };
    }
    
    // Check for form inputs
    if (tagName === 'input' || tagName === 'textarea' || tagName === 'select') {
      return {
        type: 'input',
        inputType: element.type || '',
        id,
        name: element.name || '',
        classNames,
        isSensitive: this.sensitiveFields.has(element),
        size: {
          width: rect.width,
          height: rect.height
        }
      };
    }
    
    // For all other elements
    return {
      type: 'element',
      tagName,
      id,
      classNames,
      text: element.innerText || '',
      size: {
        width: rect.width,
        height: rect.height
      }
    };
  }
  
  /**
   * Record keyboard input
   * @param {KeyboardEvent} event - Keyboard event
   */
  recordKeyDown(event) {
    // Don't track extension UI interactions
    if (event.target.closest('.web-safety-scanner-ui')) return;
    
    // Get information about target element
    const targetInfo = this.getElementInfo(event.target);
    
    // Record the key pressed but avoid recording full input in case of sensitive fields
    const interaction = {
      type: 'keydown',
      timestamp: Date.now(),
      timeSincePageLoad: Date.now() - this.pageLoadTime,
      target: targetInfo,
      key: targetInfo.isSensitive ? 'sensitive-input' : event.key, // Don't record actual key for sensitive fields
      isSpecialKey: event.ctrlKey || event.altKey || event.metaKey
    };
    
    this.interactions.push(interaction);
    
    // Check for specific key combinations that suggest user is trying to escape
    if ((event.key === 'Escape' || 
         (event.ctrlKey && event.key === 'w') || 
         (event.altKey && event.key === 'F4'))) {
      this.recordNavigationAttempt('keyboard-escape');
    }
  }
  
  /**
   * Record an attempt to navigate away from the page
   * @param {string|Event} source - Source of the navigation attempt
   */
  recordNavigationAttempt(source) {
    this.navigationAttempts++;
    
    // Record interaction
    const interaction = {
      type: 'navigation-attempt',
      timestamp: Date.now(),
      timeSincePageLoad: Date.now() - this.pageLoadTime,
      source: typeof source === 'string' ? source : 'beforeunload'
    };
    
    this.interactions.push(interaction);
    
    // Analyze for suspicious patterns of restricted navigation
    this.analyzeNavigationAttempts();
  }
  
  /**
   * Record form submission
   * @param {Event} event - Form submission event
   */
  recordFormSubmission(event) {
    const form = event.target;
    
    // Get information about the form
    const formInfo = {
      id: form.id || '',
      action: form.action || '',
      method: form.method || '',
      fields: Array.from(form.elements).map(el => ({
        type: el.type || '',
        name: el.name || '',
        id: el.id || ''
      }))
    };
    
    // Check for sensitive fields
    const hasSensitiveFields = Array.from(form.elements).some(el => 
      this.sensitiveFields.has(el)
    );
    
    // Record the interaction
    const interaction = {
      type: 'form-submit',
      timestamp: Date.now(),
      timeSincePageLoad: Date.now() - this.pageLoadTime,
      form: formInfo,
      hasSensitiveFields
    };
    
    this.interactions.push(interaction);
    
    // Analyze timing of sensitive form submissions
    if (hasSensitiveFields) {
      this.analyzeSensitiveFormSubmission(interaction);
    }
  }
  
  /**
   * Record interaction with sensitive input field
   * @param {HTMLElement} field - The sensitive field
   * @param {string} eventType - Type of event (focus/blur)
   */
  recordSensitiveFieldInteraction(field, eventType) {
    // Record the interaction
    const interaction = {
      type: `sensitive-field-${eventType}`,
      timestamp: Date.now(),
      timeSincePageLoad: Date.now() - this.pageLoadTime,
      field: this.getElementInfo(field)
    };
    
    this.interactions.push(interaction);
    
    // If this is a blur event, check how long the field was in focus
    if (eventType === 'blur') {
      const focusEvent = this.interactions.find(i => 
        i.type === 'sensitive-field-focus' && 
        i.field.id === interaction.field.id &&
        i.timestamp < interaction.timestamp
      );
      
      if (focusEvent) {
        const interactionTime = interaction.timestamp - focusEvent.timestamp;
        
        // Analyze timing patterns for sensitive field interaction
        this.analyzeSensitiveFieldTiming(interactionTime, interaction.field);
      }
    }
  }
  
  /**
   * Record visibility change event
   * @param {Event} event - Visibility change event
   */
  recordVisibilityChange(event) {
    const isHidden = document.hidden;
    
    // Record the interaction
    const interaction = {
      type: 'visibility-change',
      timestamp: Date.now(),
      timeSincePageLoad: Date.now() - this.pageLoadTime,
      isHidden
    };
    
    this.interactions.push(interaction);
    
    // If page becomes visible again, report any findings
    if (!isHidden) {
      this.reportInteractionAnalysis();
    }
  }
  
  /**
   * Analyze a click for suspicious patterns
   * @param {Object} interaction - Click interaction data
   */
  analyzeClick(interaction) {
    // Check for clicks on extremely small or invisible elements (potential clickjacking)
    if (interaction.target.size.width < 10 || interaction.target.size.height < 10) {
      this.suspiciousPatterns.deceptiveElements.detected = true;
      this.suspiciousPatterns.deceptiveElements.score += 20;
      this.suspiciousPatterns.deceptiveElements.details.push(
        'Click detected on very small element, possible clickjacking');
    }
    
    // Check for suspicious link behavior
    if (interaction.target.type === 'link') {
      // Detect potential deceptive links (text doesn't match destination)
      if (interaction.target.text && interaction.target.targetDomain) {
        const linkText = interaction.target.text.toLowerCase();
        const domain = interaction.target.targetDomain.toLowerCase();
        
        // Check if link text contains a different domain than actual target
        const commonDomains = ['google', 'facebook', 'apple', 'microsoft', 'paypal', 
                               'amazon', 'bank', 'secure', 'login', 'signin'];
        
        for (const commonDomain of commonDomains) {
          if (linkText.includes(commonDomain) && !domain.includes(commonDomain)) {
            this.suspiciousPatterns.deceptiveElements.detected = true;
            this.suspiciousPatterns.deceptiveElements.score += 30;
            this.suspiciousPatterns.deceptiveElements.details.push(
              `Potentially misleading link: text mentions "${commonDomain}" but points to ${domain}`);
          }
        }
      }
    }
  }
  
  /**
   * Analyze navigation attempts for signs of navigation restriction
   */
  analyzeNavigationAttempts() {
    // Check for multiple navigation attempts in short time
    const recentAttempts = this.interactions.filter(i => 
      i.type === 'navigation-attempt' && 
      Date.now() - i.timestamp < 30000 // Last 30 seconds
    );
    
    if (recentAttempts.length >= 3) {
      // Multiple navigation attempts suggest user is trying to leave but can't
      this.suspiciousPatterns.restrictedNavigation.detected = true;
      this.suspiciousPatterns.restrictedNavigation.score = 
        Math.min(recentAttempts.length * 10, 80);
      
      this.suspiciousPatterns.restrictedNavigation.details.push(
        `Multiple navigation attempts detected (${recentAttempts.length} in 30 seconds)`);
    }
  }
  
  /**
   * Check for signs of restricted navigation
   */
  checkForRestrictedNavigation() {
    // Use history length as an indicator of potential navigation blocking
    const historyLength = window.history.length || 0;
    
    if (historyLength === 1 && Date.now() - this.pageLoadTime > 60000) {
      // User has been on the same page for over a minute with no history
      // This could be legitimate, but combined with other signals might indicate forced flow
      this.suspiciousPatterns.restrictedNavigation.detected = true;
      this.suspiciousPatterns.restrictedNavigation.score += 10;
      this.suspiciousPatterns.restrictedNavigation.details.push(
        'User appears to be locked on a single page for an extended period');
    }
  }
  
  /**
   * Analyze page UI for deceptive elements
   */
  analyzePageUI() {
    // Check for fake browser UI elements (common phishing technique)
    const fakeBrowserUI = this.detectFakeBrowserUI();
    if (fakeBrowserUI.detected) {
      this.suspiciousPatterns.deceptiveElements.detected = true;
      this.suspiciousPatterns.deceptiveElements.score += fakeBrowserUI.score;
      this.suspiciousPatterns.deceptiveElements.details.push(...fakeBrowserUI.details);
    }
    
    // Check for hidden or deceptive form fields
    const deceptiveFields = this.detectDeceptiveFormFields();
    if (deceptiveFields.detected) {
      this.suspiciousPatterns.deceptiveElements.detected = true;
      this.suspiciousPatterns.deceptiveElements.score += deceptiveFields.score;
      this.suspiciousPatterns.deceptiveElements.details.push(...deceptiveFields.details);
    }
    
    // Check for countdown timers or urgency indicators
    const urgencyElements = this.detectUrgencyElements();
    if (urgencyElements.detected) {
      this.suspiciousPatterns.forcedInteraction.detected = true;
      this.suspiciousPatterns.forcedInteraction.score += urgencyElements.score;
      this.suspiciousPatterns.forcedInteraction.details.push(...urgencyElements.details);
    }
    
    // Calculate overall score
    this.calculateInteractionScore();
  }
  
  /**
   * Detect fake browser UI elements like address bars, security icons
   * @returns {Object} Detection results
   */
  detectFakeBrowserUI() {
    const results = {
      detected: false,
      score: 0,
      details: []
    };
    
    // Look for elements that mimic browser UI
    const potentialFakeUI = document.querySelectorAll(
      'img[src*="browser"], img[src*="chrome"], img[src*="firefox"], img[src*="edge"], ' +
      'img[src*="safari"], img[src*="lock"], img[src*="secure"], img[src*="address"], ' +
      'img[src*="url"], img[src*="bar"], img[alt*="secure"], img[alt*="browser"], ' +
      'div[class*="browser"], div[id*="browser"], div[class*="address-bar"], div[id*="address-bar"]'
    );
    
    if (potentialFakeUI.length > 0) {
      results.detected = true;
      results.score = 40;
      results.details.push(`Detected ${potentialFakeUI.length} elements that may mimic browser UI`);
    }
    
    // Check for address bar mimicry
    const addressBarElements = document.querySelectorAll(
      'input[readonly][value*="https"], div[class*="url"], div[class*="address"]'
    );
    
    if (addressBarElements.length > 0) {
      results.detected = true;
      results.score += 30;
      results.details.push('Detected elements that may mimic browser address bar');
    }
    
    return results;
  }
  
  /**
   * Detect deceptive form fields (hidden, misleading, etc)
   * @returns {Object} Detection results
   */
  detectDeceptiveFormFields() {
    const results = {
      detected: false,
      score: 0,
      details: []
    };
    
    // Check for hidden fields that aren't typical hidden form fields
    const hiddenFields = document.querySelectorAll('input:not([type="hidden"])');
    
    hiddenFields.forEach(field => {
      const style = window.getComputedStyle(field);
      
      if ((style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') &&
          (field.type === 'text' || field.type === 'password' || field.type === 'email')) {
        
        results.detected = true;
        results.score += 30;
        results.details.push('Hidden input field detected that may be collecting data covertly');
      }
    });
    
    // Check for potentially deceptive field labels
    document.querySelectorAll('label').forEach(label => {
      const labelText = label.innerText.toLowerCase();
      const forAttribute = label.getAttribute('for');
      
      if (forAttribute) {
        const field = document.getElementById(forAttribute);
        
        if (field && field.type) {
          // Check for mismatched label/field types
          if ((labelText.includes('email') && field.type !== 'email') ||
              (labelText.includes('password') && field.type !== 'password') ||
              (labelText.includes('secure') && field.type !== 'password')) {
            
            results.detected = true;
            results.score += 20;
            results.details.push('Potentially misleading form field label detected');
          }
        }
      }
    });
    
    return results;
  }
  
  /**
   * Detect urgency elements like countdowns or threatening messages
   * @returns {Object} Detection results
   */
  detectUrgencyElements() {
    const results = {
      detected: false,
      score: 0,
      details: []
    };
    
    // Check for countdown elements
    const countdownElements = document.querySelectorAll(
      '[class*="countdown"], [id*="countdown"], ' +
      '[class*="timer"], [id*="timer"], ' +
      '[class*="clock"], [id*="clock"]'
    );
    
    if (countdownElements.length > 0) {
      results.detected = true;
      results.score += 20;
      results.details.push('Countdown timer detected, potentially creating false urgency');
    }
    
    // Check for urgency text
    const allText = document.body.innerText.toLowerCase();
    const urgencyPhrases = [
      'limited time', 'act now', 'expires', 'deadline', 'running out',
      'only today', 'last chance', 'immediate action', 'urgent'
    ];
    
    for (const phrase of urgencyPhrases) {
      if (allText.includes(phrase)) {
        results.detected = true;
        results.score += 10;
        results.details.push('Urgency language detected, potentially forcing hasty user decisions');
        break;  // Only count this once
      }
    }
    
    return results;
  }
  
  /**
   * Analyze timing patterns in sensitive field interactions
   * @param {number} interactionTime - Time spent on field in ms
   * @param {Object} fieldInfo - Information about the field
   */
  analyzeSensitiveFieldTiming(interactionTime, fieldInfo) {
    // Check for suspicious timing patterns
    
    // Extremely short interaction time with sensitive field (< 1.5 seconds)
    if (interactionTime < 1500 && fieldInfo.inputType === 'password') {
      this.suspiciousPatterns.unusualTiming.detected = true;
      this.suspiciousPatterns.unusualTiming.score += 30;
      this.suspiciousPatterns.unusualTiming.details.push(
        'Unusually brief interaction with password field, possible auto-fill by phishing page');
    }
  }
  
  /**
   * Analyze sensitive form submissions for timing anomalies
   * @param {Object} interaction - Form submission interaction data
   */
  analyzeSensitiveFormSubmission(interaction) {
    // Check if this is a very quick submission after page load
    if (interaction.timeSincePageLoad < 5000) {
      // Very quick form submission with sensitive data is suspicious
      this.suspiciousPatterns.unusualTiming.detected = true;
      this.suspiciousPatterns.unusualTiming.score += 40;
      this.suspiciousPatterns.unusualTiming.details.push(
        'Sensitive form submitted very quickly after page load, possible auto-submission');
    }
    
    // Check if there's minimal interaction before submission
    const priorInteractions = this.interactions.filter(i => 
      i.type !== 'form-submit' && 
      i.timestamp < interaction.timestamp
    );
    
    if (priorInteractions.length < 3) {
      this.suspiciousPatterns.unusualTiming.detected = true;
      this.suspiciousPatterns.unusualTiming.score += 20;
      this.suspiciousPatterns.unusualTiming.details.push(
        'Form submitted with minimal prior user interaction, unusual behavior');
    }
  }
  
  /**
   * Calculate overall interaction risk score
   */
  calculateInteractionScore() {
    let score = 0;
    
    // Sum weighted scores from all pattern categories
    if (this.suspiciousPatterns.restrictedNavigation.detected) {
      score += this.suspiciousPatterns.restrictedNavigation.score * 0.3;
    }
    
    if (this.suspiciousPatterns.forcedInteraction.detected) {
      score += this.suspiciousPatterns.forcedInteraction.score * 0.2;
    }
    
    if (this.suspiciousPatterns.unusualTiming.detected) {
      score += this.suspiciousPatterns.unusualTiming.score * 0.25;
    }
    
    if (this.suspiciousPatterns.deceptiveElements.detected) {
      score += this.suspiciousPatterns.deceptiveElements.score * 0.25;
    }
    
    // Cap at 100
    this.interactionScore = Math.min(Math.round(score), 100);
  }
  
  /**
   * Get summary of analysis results
   * @returns {Object} Analysis results summary
   */
  getAnalysisResults() {
    // Ensure score is current
    this.calculateInteractionScore();
    
    // Collect all detected details
    const allDetails = [];
    let topPatternType = null;
    let topPatternScore = 0;
    
    for (const [type, pattern] of Object.entries(this.suspiciousPatterns)) {
      if (pattern.detected) {
        // Get top 2 details for each pattern
        const patternDetails = pattern.details.slice(0, 2).map(detail => 
          `[${type}] ${detail}`
        );
        
        allDetails.push(...patternDetails);
        
        // Track pattern with highest score
        if (pattern.score > topPatternScore) {
          topPatternScore = pattern.score;
          topPatternType = type;
        }
      }
    }
    
    // Determine if this is likely phishing based on interaction score
    const isLikelyPhishing = this.interactionScore >= 70;
    
    return {
      interactionScore: this.interactionScore,
      isLikelyPhishing,
      topPattern: topPatternType,
      interactionCount: this.interactions.length,
      details: allDetails.slice(0, 5), // Limit to top 5 details
      timestamp: Date.now(),
      timeSincePageLoad: Date.now() - this.pageLoadTime
    };
  }
  
  /**
   * Report analysis results to background script
   */
  reportInteractionAnalysis() {
    // Only report if we have interactions and our score has changed
    if (this.interactions.length === 0) return;
    
    // Don't report too frequently
    if (Date.now() - this.lastReportTime < 5000) return;
    
    // Calculate updated score
    this.calculateInteractionScore();
    
    // Only report if we have a non-zero score or sufficient interactions
    if (this.interactionScore > 0 || this.interactions.length > 10) {
      const results = this.getAnalysisResults();
      
      chrome.runtime.sendMessage({
        action: 'reportUserInteractionAnalysis',
        data: results
      });
      
      this.lastReportTime = Date.now();
    }
  }
}

// Create a global instance that content.js can use
window.userInteractionAnalyzer = new UserInteractionAnalyzer();

// For backward compatibility 
if (typeof module !== 'undefined' && module.exports) {
  module.exports = window.userInteractionAnalyzer;
}