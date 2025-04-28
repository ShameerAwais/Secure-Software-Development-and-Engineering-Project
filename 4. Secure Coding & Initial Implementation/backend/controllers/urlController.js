const axios = require("axios");
const PhishingEngine = require("../utils/phishingDetectionEngine");
// Add config import
const config = require("../config/apiConfig.json");
const URLHistory = require('../models/URLHistory');
const User = require('../models/User');
const phishingEngine = require('../utils/phishingDetectionEngine');

// Controller for handling URL safety checks
exports.checkUrlSafety = async (req, res) => {
  try {
    const { url, pageContent } = req.body;
    
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
    
    // If Google Safe Browsing detected it as unsafe, return immediately
    if (!safeBrowsingResult.isSafe && !safeBrowsingResult.fallback) {
      console.log(`[URL Controller] Google Safe Browsing detected unsafe URL: ${url} - ${safeBrowsingResult.threatType}`);
      
      return res.status(200).json({
        success: true,
        data: {
          url,
          isSafe: false,
          threatType: safeBrowsingResult.threatType,
          phishingScore: 100,
          details: {
            safeBrowsing: {
              isSafe: false,
              threatType: safeBrowsingResult.threatType
            },
            source: "Google Safe Browsing API"
          }
        }
      });
    }
    
    // Step 2: If URL is safe according to Google, analyze page content if available
    console.log("[URL Controller] Step 2: Running Page Content Analysis");
    const phishingAnalysis = await PhishingEngine.analyzeUrl(url, safeBrowsingResult, pageContent);
    
    // For URLs, we trust Google Safe Browsing entirely
    // For content, we use our own phishing detection engine
    const isSafe = safeBrowsingResult.isSafe;
    
    // Get the threat type
    let threatType = null;
    if (!safeBrowsingResult.isSafe) {
      threatType = safeBrowsingResult.threatType;
    } else if (phishingAnalysis.contentAnalysis && 
              phishingAnalysis.contentAnalysis.contentScore >= PhishingEngine.PHISHING_THRESHOLD) {
      threatType = "SUSPICIOUS_CONTENT";
    }
    
    // Prepare the response with additional content analysis info if available
    const responseDetails = {
      safeBrowsing: {
        isSafe: safeBrowsingResult.isSafe,
        threatType: safeBrowsingResult.threatType
      }
    };
    
    // Add content analysis details if available
    if (pageContent && phishingAnalysis.contentAnalysis) {
      responseDetails.contentAnalysis = {
        score: phishingAnalysis.contentAnalysis.contentScore,
        indicators: phishingAnalysis.phishingIndicators,
        threshold: PhishingEngine.PHISHING_THRESHOLD
      };
    }
    
    return res.status(200).json({
      success: true,
      data: {
        url,
        isSafe,
        threatType,
        phishingScore: phishingAnalysis.phishingScore,
        details: responseDetails
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
      note: "Falling back to content analysis only"
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
      note: "Using content analysis only due to API error"
    };
  }
}

// Function to check URL and save to user history if authenticated
exports.checkURL = async (req, res) => {
  try {
    const { url, pageContent } = req.body;
    
    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }
    
    // First check with Google Safe Browsing API
    const safeBrowsingResult = await checkWithGoogleSafeBrowsing(url);
    console.log(`[URL Check] Safe Browsing result for ${url}: isSafe=${safeBrowsingResult.isSafe}, threatType=${safeBrowsingResult.threatType || 'None'}`);
    
    // Only analyze content if URL is safe according to Google
    let contentAnalysisResult = null;
    let phishingScore = 0;
    if (pageContent) {
      // Use the phishing detection engine only for content analysis
      const phishingAnalysis = await phishingEngine.analyzeUrl(url, safeBrowsingResult, pageContent);
      contentAnalysisResult = phishingAnalysis.contentAnalysis;
      phishingScore = phishingAnalysis.phishingScore || 0;
    }
    
    // URL is unsafe only if Google Safe Browsing explicitly flags it
    // Make sure we use the actual values from safeBrowsingResult
    let isSafe = safeBrowsingResult.isSafe === true;
    let threatType = safeBrowsingResult.threatType;
    let result = {
      isSafe,
      threatType,
      phishingScore,
      details: {
        source: isSafe ? (safeBrowsingResult.fallback ? "Fallback detection" : "Google Safe Browsing API") : "Google Safe Browsing API"
      }
    };
    
    // Include content analysis if available
    if (contentAnalysisResult) {
      result.contentAnalysis = contentAnalysisResult;
    }
    
    // If user is authenticated, check personal lists and save to history
    if (req.isAuthenticated) {
      const user = await User.findById(req.user.id);
      
      if (user) {
        // Check if URL is in user's allowlist
        const isAllowed = user.allowList.some(item => url.includes(item.url));
        if (isAllowed) {
          result.isSafe = true;
          result.details = {
            ...result.details,
            source: 'User allowlist',
            message: 'URL is in your trusted sites list'
          };
        }
        
        // Check if URL is in user's blocklist
        const isBlocked = user.blockList.some(item => url.includes(item.url));
        if (isBlocked) {
          result.isSafe = false;
          result.details = {
            ...result.details,
            source: 'User blocklist',
            message: 'URL is in your blocked sites list'
          };
        }
        
        // Save to user history - include content analysis flag
        const history = new URLHistory({
          user: user._id,
          url,
          result,
          device: req.headers['user-agent'] || 'Unknown',
          hasContentAnalysis: pageContent ? true : false
        });
        
        await history.save();
      }
    }
    
    // Log the final result for debugging
    console.log(`[URL Check] Final result for ${url}: isSafe=${result.isSafe}, threatType=${result.threatType || 'None'}`);
    
    return res.status(200).json({
      success: true,
      result,
      userStatus: req.isAuthenticated ? 'authenticated' : 'anonymous'
    });
  } catch (error) {
    console.error('URL check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error checking URL',
      error: error.message
    });
  }
};

/**
 * Get URL history - legacy non-authenticated version
 */
exports.getUrlHistory = async (req, res) => {
  // For non-authenticated users, just return empty history with a message
  return res.status(200).json({
    success: true,
    message: 'Authentication required to view history',
    data: {
      history: [],
      totalCount: 0,
      page: 1,
      totalPages: 0
    }
  });
};

/**
 * Get authenticated user URL history with pagination
 */
exports.getUserHistory = async (req, res) => {
  try {
    // Check authentication
    if (!req.isAuthenticated) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const timeRange = req.query.timeRange || 'month';
    const skip = (page - 1) * limit;

    // Set date filter based on time range
    const dateFilter = {};
    const now = new Date();
    
    switch(timeRange) {
      case 'week':
        dateFilter.timestamp = { $gte: new Date(now.setDate(now.getDate() - 7)) };
        break;
      case 'this-month':
        // Start of current month
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        dateFilter.timestamp = { $gte: startOfMonth };
        break;
      case 'year':
        dateFilter.timestamp = { $gte: new Date(now.setFullYear(now.getFullYear() - 1)) };
        break;
      case 'month':
      default:
        // Past 30 days
        dateFilter.timestamp = { $gte: new Date(now.setMonth(now.getMonth() - 1)) };
    }

    // Query user history with pagination
    const totalCount = await URLHistory.countDocuments({ 
      user: userId,
      ...dateFilter
    });
    
    const history = await URLHistory.find({ 
      user: userId,
      ...dateFilter
    })
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit);
    
    // Calculate total pages
    const totalPages = Math.ceil(totalCount / limit);

    return res.status(200).json({
      success: true,
      data: {
        history,
        totalCount,
        page,
        totalPages
      }
    });
  } catch (error) {
    console.error('Error fetching user history:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error fetching history',
      error: error.message
    });
  }
};

/**
 * Update user action for a URL (e.g. mark as trusted, report as unsafe)
 */
exports.updateUserAction = async (req, res) => {
  try {
    // Check authentication
    if (!req.isAuthenticated) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const { historyId, action } = req.body;

    if (!historyId || !action) {
      return res.status(400).json({
        success: false,
        message: 'History ID and action are required'
      });
    }

    // Validate action
    const validActions = ['trust', 'block', 'report'];
    if (!validActions.includes(action)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid action. Must be one of: ' + validActions.join(', ')
      });
    }

    // Find the history entry
    const history = await URLHistory.findById(historyId);

    if (!history) {
      return res.status(404).json({
        success: false,
        message: 'History entry not found'
      });
    }

    // Verify ownership
    if (history.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this history entry'
      });
    }

    // Update the user action
    history.userAction = action;
    await history.save();

    return res.status(200).json({
      success: true,
      message: 'User action updated successfully',
      data: history
    });
  } catch (error) {
    console.error('Error updating user action:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error updating user action',
      error: error.message
    });
  }
};

/**
 * Get user URL safety statistics
 */
exports.getUserStats = async (req, res) => {
  try {
    // Check authentication
    if (!req.isAuthenticated) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const userId = req.user.id;
    const timeRange = req.query.range || 'month';
    
    // Set date filter based on time range
    const dateFilter = {};
    const now = new Date();
    
    switch(timeRange) {
      case 'week':
        dateFilter.timestamp = { $gte: new Date(now.setDate(now.getDate() - 7)) };
        break;
      case 'year':
        dateFilter.timestamp = { $gte: new Date(now.setFullYear(now.getFullYear() - 1)) };
        break;
      case 'month':
      default:
        dateFilter.timestamp = { $gte: new Date(now.setMonth(now.getMonth() - 1)) };
    }

    // Count safe and unsafe URLs
    const totalChecks = await URLHistory.countDocuments({ 
      user: userId,
      ...dateFilter
    });
    
    const safeChecks = await URLHistory.countDocuments({ 
      user: userId,
      'result.isSafe': true,
      ...dateFilter
    });
    
    const unsafeChecks = totalChecks - safeChecks;
    
    // Get breakdown of unsafe URLs by type
    const unsafeBreakdown = await URLHistory.aggregate([
      { 
        $match: { 
          user: userId,
          'result.isSafe': false,
          ...dateFilter
        } 
      },
      {
        $group: {
          _id: '$result.threatType',
          count: { $sum: 1 }
        }
      }
    ]);

    // Format the breakdown data
    const formattedBreakdown = unsafeBreakdown.map(item => ({
      threatType: item._id || 'Unknown',
      count: item.count
    }));

    return res.status(200).json({
      success: true,
      data: {
        totalChecks,
        safeChecks,
        unsafeChecks,
        safePercentage: totalChecks > 0 ? (safeChecks / totalChecks) * 100 : 0,
        unsafePercentage: totalChecks > 0 ? (unsafeChecks / totalChecks) * 100 : 0,
        unsafeBreakdown: formattedBreakdown,
        timeRange
      }
    });
  } catch (error) {
    console.error('Error generating user stats:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error generating statistics',
      error: error.message
    });
  }
};
