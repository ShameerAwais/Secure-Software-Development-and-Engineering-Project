// Content script that runs on web pages
// Intercepts URLs and sends them for analysis

// Function to check if the current URL is safe
function checkCurrentPageSafety() {
  const currentUrl = window.location.href;
  
  // First check if the user is authenticated
  chrome.runtime.sendMessage({ action: 'getAuthStatus' }, (authResponse) => {
    if (authResponse && authResponse.success && authResponse.isAuthenticated) {
      console.log("User is authenticated. Proceeding with page scan.");
      
      // Intercept URL and send to background script for checking
      console.log("Check URL: Intercepting URL", currentUrl);
      
      // Extract page content for analysis
      const pageContent = extractPageContent();
      console.log("Extracting page content for analysis");
      
      // Send message to background script to analyze URL and page content
      chrome.runtime.sendMessage(
        { 
          action: "checkUrl", 
          url: currentUrl,
          pageContent: pageContent 
        },
        (response) => {
          if (response && response.success) {
            const { isSafe, threatType, analysisPhase, details, phishingScore } = response.data;
            
            console.log(`URL Check Result: ${isSafe ? 'Safe' : 'Unsafe'}, Phase: ${analysisPhase}`);
            
            if (!isSafe) {
              // Show warning for unsafe page with enhanced details
              showWarningBanner(threatType, analysisPhase, details, phishingScore);
            }
          } else if (response && !response.success) {
            console.error("Error checking URL safety:", response.error);
            
            // If there's a fallback result, use it
            if (response.fallback && response.data) {
              const { isSafe, threatType } = response.data;
              console.log(`Fallback Result: ${isSafe ? 'Safe' : 'Unsafe'}`);
              
              if (!isSafe) {
                showWarningBanner(threatType || "Unknown Threat");
              }
            }
          }
        }
      );
    } else {
      console.log("User not authenticated. Authentication required to scan pages.");
      // Show an authentication required message
      showLoginRequiredBanner();
    }
  });
}

/**
 * Shows a banner prompting the user to login to use the extension
 */
function showLoginRequiredBanner() {
  const banner = document.createElement("div");
  banner.style.position = "fixed";
  banner.style.top = "0";
  banner.style.left = "0";
  banner.style.width = "100%";
  banner.style.padding = "15px";
  banner.style.backgroundColor = "#3498db"; // Blue instead of red
  banner.style.color = "white";
  banner.style.textAlign = "center";
  banner.style.fontWeight = "bold";
  banner.style.zIndex = "9999";
  banner.style.boxShadow = "0 2px 10px rgba(0,0,0,0.2)";
  banner.style.fontSize = "16px";
  
  // Create banner content
  banner.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: center; flex-direction: column;">
      <div style="display: flex; align-items: center; justify-content: center;">
        <svg style="width: 24px; height: 24px; margin-right: 10px;" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white">
          <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v5.7c0 4.83-3.4 9.19-7 10.36-3.6-1.17-7-5.53-7-10.36v-5.7l7-3.12zM11 7v4h2V7h-2zm0 6v2h2v-2h-2z"/>
        </svg>
        <span>Authentication Required</span>
      </div>
      <div style="margin-top: 5px;">Please login to the Web Safety Scanner extension to scan this page for security threats.</div>
      <button id="open-extension-button" style="padding: 5px 15px; margin-top: 10px; border: none; background-color: white; color: #3498db; font-weight: bold; border-radius: 4px; cursor: pointer;">Open Extension</button>
    </div>
  `;
  
  // Append to body
  document.body.prepend(banner);
  
  // Add event listener to open extension popup
  document.getElementById("open-extension-button").addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: 'openPopup' });
    document.body.removeChild(banner);
  });
  
  // Create close button
  const closeButton = document.createElement("button");
  closeButton.textContent = "×";
  closeButton.style.position = "absolute";
  closeButton.style.right = "10px";
  closeButton.style.top = "10px";
  closeButton.style.border = "none";
  closeButton.style.backgroundColor = "#2980b9";
  closeButton.style.color = "white";
  closeButton.style.fontWeight = "bold";
  closeButton.style.fontSize = "20px";
  closeButton.style.cursor = "pointer";
  closeButton.style.borderRadius = "50%";
  closeButton.style.width = "30px";
  closeButton.style.height = "30px";
  closeButton.style.display = "flex";
  closeButton.style.alignItems = "center";
  closeButton.style.justifyContent = "center";
  
  closeButton.addEventListener("click", () => {
    document.body.removeChild(banner);
  });
  
  banner.appendChild(closeButton);
}

/**
 * Extract relevant content from the webpage for phishing analysis
 * @returns {Object} Extracted page content features
 */
function extractPageContent() {
  try {
    console.log("Extracting page content features for advanced phishing detection");
    
    // Get all forms on the page
    const forms = document.querySelectorAll('form');
    const formData = Array.from(forms).map(form => {
      // Get input fields in the form
      const inputs = form.querySelectorAll('input');
      const formInputs = Array.from(inputs).map(input => ({
        type: input.type || 'text',
        name: input.name || '',
        id: input.id || '',
        placeholder: input.placeholder || '',
        hasPasswordField: input.type === 'password'
      }));
      
      // Check if this appears to be a login form
      const isLoginForm = formInputs.some(input => input.type === 'password') || 
                         formInputs.some(input => 
                            (input.name?.toLowerCase().includes('pass') || 
                             input.id?.toLowerCase().includes('pass') || 
                             input.placeholder?.toLowerCase().includes('pass')));
      
      return {
        action: form.action || window.location.href,
        method: form.method || 'get',
        inputs: formInputs,
        isLoginForm: isLoginForm
      };
    });
    
    // Get page title and meta description
    const title = document.title || '';
    const metaDescription = document.querySelector('meta[name="description"]')?.content || '';
    
    // Get all images on the page, focusing on logos
    const images = Array.from(document.querySelectorAll('img')).slice(0, 10).map(img => ({
      src: img.src || '',
      alt: img.alt || '',
      width: img.width || 0,
      height: img.height || 0,
      isLogo: (img.width < 300 && img.height < 200) && 
              (img.src.toLowerCase().includes('logo') || 
               img.alt.toLowerCase().includes('logo') ||
               img.className.toLowerCase().includes('logo') ||
               img.id.toLowerCase().includes('logo'))
    }));
    
    // Get all links on the page
    const links = Array.from(document.querySelectorAll('a')).slice(0, 20).map(link => ({
      href: link.href || '',
      text: link.innerText || '',
      isExternal: link.hostname !== window.location.hostname
    }));
    
    // Get security indicators
    const hasHttps = window.location.protocol === 'https:';
    
    // Look for common security signs/claims on the page
    const pageText = document.body.innerText.toLowerCase();
    const claimsSecureOrVerified = pageText.includes('secure') || 
                                  pageText.includes('verified') || 
                                  pageText.includes('official') ||
                                  pageText.includes('guarantee');
    
    // Look for urgency or pressure tactics
    const hasUrgencyLanguage = pageText.includes('urgent') || 
                              pageText.includes('immediately') || 
                              pageText.includes('alert') ||
                              pageText.includes('limited time') ||
                              pageText.includes('act now');
    
    // Return the aggregated page content data
    return {
      forms: formData,
      title: title,
      metaDescription: metaDescription,
      images: images,
      links: links,
      hasHttps: hasHttps,
      claimsSecureOrVerified: claimsSecureOrVerified,
      hasUrgencyLanguage: hasUrgencyLanguage,
      // Include only a reasonable amount of text to avoid network overhead
      textSample: pageText.substring(0, 1000)
    };
  } catch (error) {
    console.error('Error extracting page content:', error);
    return {
      error: true,
      message: error.message
    };
  }
}

// Function to show warning banner for unsafe sites with enhanced phishing information
function showWarningBanner(threatType, analysisPhase, details, phishingScore) {
  const banner = document.createElement("div");
  banner.style.position = "fixed";
  banner.style.top = "0";
  banner.style.left = "0";
  banner.style.width = "100%";
  banner.style.padding = "15px";
  banner.style.backgroundColor = "#ff4c4c";
  banner.style.color = "white";
  banner.style.textAlign = "center";
  banner.style.fontWeight = "bold";
  banner.style.zIndex = "9999";
  banner.style.boxShadow = "0 2px 10px rgba(0,0,0,0.2)";
  banner.style.fontSize = "16px";
  
  // Build warning message with enhanced details based on detection method
  let warningMessage = `⚠️ Warning: This site may be dangerous`;
  let detailsHtml = "";
  
  // Add specific threat type information
  if (threatType) {
    warningMessage += ` (${threatType})`;
  }
  
  // Add phishing score if available
  if (phishingScore !== undefined) {
    detailsHtml += `<div style="margin-top: 5px;">Phishing Score: <strong>${phishingScore}/100</strong></div>`;
  }
  
  // Add specific details about the threat
  if (details) {
    // Add top phishing indicators if available
    if (details.threatIndicators && details.threatIndicators.length > 0) {
      detailsHtml += `<div style="margin-top: 5px; font-size: 14px;">Detected issues:</div>`;
      detailsHtml += `<ul style="margin: 5px 0; padding-left: 20px; text-align: left; display: inline-block;">`;
      
      details.threatIndicators.forEach(indicator => {
        detailsHtml += `<li style="margin-bottom: 3px;">${indicator}</li>`;
      });
      
      detailsHtml += `</ul>`;
    } 
    // If specific reason from URL Analyzer
    else if (details.reason) {
      detailsHtml += `<div style="margin-top: 5px;">${details.reason}</div>`;
    }
  }
  
  // Create main warning content with icon
  banner.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: center; flex-direction: column;">
      <div style="display: flex; align-items: center; justify-content: center;">
        <svg style="width: 24px; height: 24px; margin-right: 10px;" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white">
          <path d="M12 2L1 21h22L12 2zm0 3.99L19.53 19H4.47L12 5.99zM12 16c.83 0 1.5-.67 1.5-1.5s-.67-1.5-1.5-1.5-1.5.67-1.5 1.5.67 1.5 1.5 1.5zm-1-4.5h2v-4h-2v4z"/>
        </svg>
        <span>${warningMessage}</span>
      </div>
      ${detailsHtml}
      <div style="margin-top: 5px; font-size: 14px;">Proceed with caution or go back to safety.</div>
    </div>
  `;
  
  // Create "Go Back" button
  const goBackButton = document.createElement("button");
  goBackButton.textContent = "Go Back";
  goBackButton.style.padding = "5px 15px";
  goBackButton.style.marginTop = "10px";
  goBackButton.style.border = "none";
  goBackButton.style.backgroundColor = "white";
  goBackButton.style.color = "#ff4c4c";
  goBackButton.style.fontWeight = "bold";
  goBackButton.style.borderRadius = "4px";
  goBackButton.style.cursor = "pointer";
  
  goBackButton.addEventListener("click", () => {
    window.history.back();
  });
  
  banner.querySelector('div').appendChild(goBackButton);
  
  // Create close button
  const closeButton = document.createElement("button");
  closeButton.textContent = "×";
  closeButton.style.position = "absolute";
  closeButton.style.right = "10px";
  closeButton.style.top = "10px";
  closeButton.style.border = "none";
  closeButton.style.backgroundColor = "#ff3333";
  closeButton.style.color = "white";
  closeButton.style.fontWeight = "bold";
  closeButton.style.fontSize = "20px";
  closeButton.style.cursor = "pointer";
  closeButton.style.borderRadius = "50%";
  closeButton.style.width = "30px";
  closeButton.style.height = "30px";
  closeButton.style.display = "flex";
  closeButton.style.alignItems = "center";
  closeButton.style.justifyContent = "center";
  
  closeButton.addEventListener("click", () => {
    document.body.removeChild(banner);
  });
  
  banner.appendChild(closeButton);
  document.body.prepend(banner);
}

// Listen for messages from popup or background scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkCurrentPage") {
    checkCurrentPageSafety();
    sendResponse({success: true});
  }
  return true;
});

// No automatic checking on page load or URL changes
// We'll only check when the user explicitly requests it via the popup
