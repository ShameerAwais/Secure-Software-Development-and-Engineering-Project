// Content script that runs on web pages
// Intercepts URLs and sends them for analysis

// Function to check if the current URL is safe
function checkCurrentPageSafety() {
  const currentUrl = window.location.href;
  
  // Intercept URL and send to background script for checking
  console.log("Check URL: Intercepting URL", currentUrl);
  
  // Send message to background script to analyze URL
  chrome.runtime.sendMessage(
    { action: "checkUrl", url: currentUrl },
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
