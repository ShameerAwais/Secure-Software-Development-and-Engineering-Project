const axios = require("axios");
const PhishingEngine = require("../utils/phishingDetectionEngine");
// Add config import
const config = require("../config/apiConfig.json");

// Controller for handling URL safety checks
exports.checkUrlSafety = async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: "URL is required" 
      });
    }

    console.log(`[URL Controller] Checking URL safety for: ${url}`);
    
    // Step 1: Check URL with Google Safe Browsing API (if API key is available)
    console.log("[URL Controller] Step 1: Checking with Google Safe Browsing API");
    const safeBrowsingResult = await checkWithGoogleSafeBrowsing(url);
    
    // Step 2: Run URL through Phishing Detection Engine for comprehensive analysis
    console.log("[URL Controller] Step 2: Running Phishing Detection Engine");
    const phishingAnalysis = await PhishingEngine.analyzeUrl(url, safeBrowsingResult);
    
    // Determine final safety verdict based on all checks
    // URL is unsafe if either Google Safe Browsing flags it OR phishing score is above threshold
    const isSafe = safeBrowsingResult.isSafe && !phishingAnalysis.isPhishing;
    
    // Get the main threat type 
    let threatType = null;
    if (!safeBrowsingResult.isSafe) {
      threatType = safeBrowsingResult.threatType;
    } else if (phishingAnalysis.isPhishing) {
      threatType = "PHISHING";
    }
    
    // No longer saving to database
    
    return res.status(200).json({
      success: true,
      data: {
        url,
        isSafe,
        threatType,
        phishingScore: phishingAnalysis.phishingScore,
        details: {
          safeBrowsing: {
            isSafe: safeBrowsingResult.isSafe,
            threatType: safeBrowsingResult.threatType
          },
          phishingAnalysis: {
            isPhishing: phishingAnalysis.isPhishing,
            score: phishingAnalysis.phishingScore,
            indicators: phishingAnalysis.phishingIndicators,
            threshold: PhishingEngine.PHISHING_THRESHOLD
          }
        }
      }
    });
    
  } catch (error) {
    console.error("[URL Controller] Error checking URL safety:", error);
    return res.status(500).json({
      success: false,
      message: "Error checking URL safety",
      error: error.message
    });
  }
};

// Function to check URL with Google Safe Browsing API
async function checkWithGoogleSafeBrowsing(url) {
  try {
    console.log("[Safe Browsing] Calling Google Safe Browsing API");
    
    // Configuration for Google Safe Browsing API request
    const apiKey = config.GOOGLE_SAFE_BROWSING_API_KEY;
    
    // More thorough check if API key is valid
    if (!apiKey || 
        apiKey === 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY_HERE' || 
        apiKey.includes('YOUR_') || 
        apiKey.includes('_KEY_HERE')) {
      console.warn("[Safe Browsing] Valid API key not found, skipping Google Safe Browsing check");
      return { 
        isSafe: true, 
        threatType: null, 
        note: "Google Safe Browsing check skipped - no valid API key" 
      };
    }
    
    // Log only the first few characters of the API key for security
    console.log(`[Safe Browsing] Using API key: ${apiKey.substring(0, 8)}...`);
    
    // Check if the API key has the correct format (typically a 39-character string)
    if (apiKey.length < 30) {
      console.warn("[Safe Browsing] API key appears to be malformed (too short)");
      return { 
        isSafe: true, 
        threatType: null, 
        note: "Google Safe Browsing check skipped - malformed API key" 
      };
    }
    
    // Prepare request body according to Google Safe Browsing API documentation
    const requestBody = {
      client: {
        clientId: "anti-phishing-extension",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: [
          "MALWARE", 
          "SOCIAL_ENGINEERING", 
          "UNWANTED_SOFTWARE", 
          "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ALL_PLATFORMS"], // Updated from ANY_PLATFORM to ALL_PLATFORMS per API docs
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    
    // Implement retry logic with improved timeout handling
    const maxRetries = 1; // Reduced from 2 to minimize waiting time
    let currentRetry = 0;
    let lastError = null;
    
    while (currentRetry <= maxRetries) {
      try {
        console.log(`[Safe Browsing] API request attempt ${currentRetry + 1}/${maxRetries + 1}`);
        
        // Improved debugging
        console.log(`[Safe Browsing] Request URL: https://safebrowsing.googleapis.com/v4/threatMatches:find`);
        console.log(`[Safe Browsing] Request body: ${JSON.stringify(requestBody, null, 2)}`);
        
        // Reduced timeout to prevent long waiting periods
        const response = await axios({
          method: 'post',
          url: `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          data: requestBody,
          timeout: 5000, // 5 second timeout for faster response
          validateStatus: function (status) {
            return status >= 200 && status < 500; // Accept any status in 2xx-4xx range
          }
        });
        
        // More detailed logging for debugging API issues
        console.log(`[Safe Browsing] Response status: ${response.status}`);
        
        // Check for HTTP error status codes
        if (response.status >= 400) {
          console.error(`[Safe Browsing] API error response: ${JSON.stringify(response.data, null, 2)}`);
          throw new Error(`API returned error status: ${response.status}`);
        }
        
        // Validate the response structure
        if (!response.data) {
          throw new Error("Empty response from API");
        }
        
        // Process the response from Google Safe Browsing API
        const matches = response.data.matches || [];
        
        const isSafe = matches.length === 0;
        
        const threatType = isSafe ? null : matches[0].threatType;
        
        console.log(`[Safe Browsing] Result for ${url}: ${isSafe ? 'Safe' : `Unsafe (${threatType})`}`);
        
        return { isSafe, threatType, matches };
        
      } catch (retryError) {
        lastError = retryError;
        
        // Provide more detailed error logging
        console.error(`[Safe Browsing] Error details: ${retryError.message}`);
        if (retryError.response) {
          console.error(`[Safe Browsing] Response data: ${JSON.stringify(retryError.response.data, null, 2)}`);
        }
        
        // Only retry on network errors or timeouts
        if (retryError.code === 'ECONNABORTED' || 
            retryError.code === 'ECONNRESET' ||
            retryError.code === 'ETIMEDOUT' ||
            retryError.message.includes('timeout') ||
            !retryError.response) {
          
          currentRetry++;
          
          if (currentRetry <= maxRetries) {
            const backoffTime = currentRetry * 1000; // Exponential backoff
            console.log(`[Safe Browsing] API connection issue. Retrying in ${backoffTime}ms...`);
            await new Promise(resolve => setTimeout(resolve, backoffTime));
            continue;
          }
        } else {
          // Non-network errors shouldn't be retried
          break;
        }
      }
    }
    
    console.log("[Safe Browsing] Switching to fallback detection methods");
    
    // Instead of throwing an error, we'll return a graceful fallback
    return { 
      isSafe: true,  // Default to safe when API fails
      threatType: null, 
      error: lastError ? lastError.message : "API connection timeout",
      fallback: true,
      note: "Falling back to local detection methods"
    };
    
  } catch (error) {
    console.error("[Safe Browsing] API Error:", error.message);
    
    // Provide more descriptive error for troubleshooting
    let errorType = "Unknown error";
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      errorType = `API responded with error ${error.response.status}: ${error.response.data?.error?.message || JSON.stringify(error.response.data) || 'Unknown API error'}`;
    } else if (error.request) {
      // The request was made but no response was received
      errorType = "No response from Google Safe Browsing API";
      
      // Add more context for connection issues
      if (error.code) {
        errorType += ` (${error.code})`;
      }
      
      if (error.message.includes('timeout')) {
        errorType = "Google Safe Browsing API request timed out";
      }
    } else {
      // Something happened in setting up the request that triggered an Error
      errorType = `Request setup error: ${error.message}`;
    }
    
    console.error(`[Safe Browsing] Error type: ${errorType}`);
    
    // If API call fails, default to treating URL as safe to avoid false positives
    // but include error information for debugging
    return { 
      isSafe: true, 
      threatType: null, 
      error: errorType,
      fallback: true,
      note: "Using local detection only"
    };
  }
}

// Controller for history endpoint - now just returns empty array since we're not storing URLs
exports.getUrlHistory = async (req, res) => {
  return res.status(200).json({
    success: true,
    count: 0,
    data: [],
    message: "URL history storage has been disabled"
  });
};
