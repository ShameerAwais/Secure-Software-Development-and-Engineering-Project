/**
 * Authentication and user management for URL Safety Extension
 */

// Detect whether we're in a service worker environment or regular browser context
const isServiceWorker = typeof window === 'undefined';

class AuthService {
  constructor() {
    // Don't hardcode the API URL - get it from storage
    this.API_URL = null;
    this.user = null;
    this.token = null;
    this.refreshToken = null; // Store the refresh token
    this.tokenExpiry = null; // Store token expiration timestamp
    this.isAuthenticated = false;
    this.refreshInProgress = false; // Flag to prevent multiple concurrent refresh attempts
    this.refreshInterval = null; // Interval for automatic token refresh
    
    // Initialize authentication state from storage
    this.loadAuthState();
    
    // Setup cross-tab synchronization only in browser context
    if (!isServiceWorker) {
      this.setupSyncListeners();
    }
  }
  
  /**
   * Set up cross-tab synchronization listeners
   * Only runs in browser context, not in service worker
   */
  setupSyncListeners() {
    // Skip if we're in a service worker
    if (isServiceWorker) return;
    
    // Listen for storage changes - this enables cross-tab synchronization
    window.addEventListener('storage', (event) => {
      if (event.key === 'auth_logout_broadcast') {
        console.log('Received logout event from another tab');
        this.handleLogoutSync();
      }
    });
    
    // Run logout check on startup in case localStorage was modified while extension was not running
    setTimeout(() => this.checkExternalLogout(), 500);
  }
  
  /**
   * Handle logout synchronization from another tab
   */
  async handleLogoutSync() {
    console.log('Syncing logout from another tab/window');
    
    // Only take action if we're currently logged in
    if (this.isAuthenticated) {
      // Clear local auth state
      this.user = null;
      this.token = null;
      this.refreshToken = null;
      this.tokenExpiry = null;
      this.isAuthenticated = false;
      
      // Clear any refresh interval
      this.clearRefreshInterval();
      
      await this.saveAuthState();
      
      console.log('Synchronized logout complete');
      
      // Dispatch an event so any open UI can update
      this.dispatchAuthChangeEvent();
    }
  }
  
  /**
   * Check if logout happened externally while this instance was not active
   */
  async checkExternalLogout() {
    // Skip if we're in a service worker
    if (isServiceWorker) return;
    
    try {
      // Check if we're logged in but a logout event exists that's newer than our last login
      const lastLogoutTime = localStorage.getItem('auth_logout_broadcast');
      if (lastLogoutTime && this.isAuthenticated) {
        console.log('Detected previous logout event, syncing state');
        await this.handleLogoutSync();
      }
    } catch (e) {
      console.warn('Error checking for external logout:', e);
    }
  }
  
  /**
   * Dispatch authentication change event
   */
  dispatchAuthChangeEvent() {
    // Skip if we're in a service worker
    if (isServiceWorker) return;
    
    const event = new CustomEvent('auth_state_changed', {
      detail: {
        isAuthenticated: this.isAuthenticated,
        user: this.user
      }
    });
    document.dispatchEvent(event);
  }
  
  /**
   * Load authentication state from Chrome storage
   */
  async loadAuthState() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['user', 'token', 'refreshToken', 'tokenExpiry', 'isAuthenticated', 'apiUrl'], (result) => {
        this.user = result.user || null;
        this.token = result.token || null;
        this.refreshToken = result.refreshToken || null;
        this.tokenExpiry = result.tokenExpiry ? new Date(result.tokenExpiry) : null;
        this.isAuthenticated = result.isAuthenticated || false;
        // Get the API URL from storage (same one that background script uses)
        this.API_URL = result.apiUrl || 'http://localhost:5000/api/v1';
        
        console.log('AuthService initialized with API URL:', this.API_URL);
        console.log('Authentication state:', this.isAuthenticated ? 'Authenticated' : 'Not authenticated');
        
        // Set up token refresh if we're authenticated
        if (this.isAuthenticated) {
          this.setupTokenRefresh();
        }
        
        resolve({
          user: this.user,
          token: this.token,
          refreshToken: this.refreshToken,
          tokenExpiry: this.tokenExpiry,
          isAuthenticated: this.isAuthenticated
        });
      });
    });
  }
  
  /**
   * Save authentication state to Chrome storage
   */
  async saveAuthState() {
    return new Promise((resolve) => {
      console.log('Saving auth state:', { 
        isAuthenticated: this.isAuthenticated, 
        user: this.user ? this.user.email : 'none',
        hasRefreshToken: !!this.refreshToken
      });
      
      chrome.storage.local.set({
        user: this.user,
        token: this.token,
        refreshToken: this.refreshToken,
        tokenExpiry: this.tokenExpiry ? this.tokenExpiry.toISOString() : null,
        isAuthenticated: this.isAuthenticated
      }, () => {
        console.log('Auth state saved to storage');
        resolve();
      });
    });
  }
  
  /**
   * Setup automatic token refresh
   * This ensures tokens are refreshed before they expire
   */
  setupTokenRefresh() {
    // Clear any existing refresh interval
    this.clearRefreshInterval();
    
    // If we're not authenticated or don't have token expiry info, don't set up refresh
    if (!this.isAuthenticated || !this.tokenExpiry || !this.refreshToken) {
      return;
    }
    
    const now = new Date();
    const expiryTime = new Date(this.tokenExpiry);
    
    // If token is already expired, refresh immediately
    if (expiryTime <= now) {
      console.log('Token already expired, refreshing now');
      this.refreshTokenIfNeeded();
      return;
    }
    
    // Calculate time until we need to refresh (75% of remaining time)
    const timeUntilExpiry = expiryTime.getTime() - now.getTime();
    const refreshTime = timeUntilExpiry * 0.25; // Refresh when 25% of lifetime remains
    
    console.log(`Token expires in ${Math.round(timeUntilExpiry / (60 * 1000))} minutes, ` +
                `scheduling refresh in ${Math.round(refreshTime / (60 * 1000))} minutes`);
    
    // Set up interval to check token expiration every minute
    this.refreshInterval = setInterval(() => {
      this.refreshTokenIfNeeded();
    }, 60 * 1000); // Check every minute
    
    // Also do an immediate check just in case
    this.refreshTokenIfNeeded();
  }
  
  /**
   * Clear the token refresh interval
   */
  clearRefreshInterval() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }
  
  /**
   * Check if token needs refreshing and refresh if needed
   */
  async refreshTokenIfNeeded() {
    // Don't proceed if refresh is already in progress
    if (this.refreshInProgress) {
      return;
    }
    
    // Don't refresh if not authenticated or missing required data
    if (!this.isAuthenticated || !this.tokenExpiry || !this.refreshToken) {
      return;
    }
    
    const now = new Date();
    const expiryTime = new Date(this.tokenExpiry);
    
    // Calculate how much time remains until expiry
    const timeRemaining = expiryTime.getTime() - now.getTime();
    const timeThreshold = 15 * 60 * 1000; // 15 minutes
    
    console.log(`Token expires in ${Math.round(timeRemaining / (60 * 1000))} minutes`);
    
    // If token expires in less than threshold time, refresh it
    if (timeRemaining < timeThreshold) {
      console.log('Token expiring soon, refreshing...');
      await this.refreshAccessToken();
    }
  }
  
  /**
   * Refresh the access token using the refresh token
   * @returns {Promise<boolean>} True if refresh was successful, false otherwise
   */
  async refreshAccessToken() {
    if (this.refreshInProgress) {
      return false;
    }
    
    if (!this.refreshToken) {
      console.warn('No refresh token available');
      return false;
    }
    
    try {
      this.refreshInProgress = true;
      console.log('Refreshing access token...');
      
      const response = await fetch(`${this.API_URL}/auth/refresh-token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ refreshToken: this.refreshToken })
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('Token refresh failed:', errorText);
        
        // If we get a 401, the refresh token is invalid or expired
        if (response.status === 401) {
          console.warn('Refresh token invalid or expired, logging out');
          await this.handleLogoutSync(); // This will clear auth state
        }
        
        return false;
      }
      
      const data = await response.json();
      
      if (data.success) {
        // Update tokens
        this.token = data.token;
        this.refreshToken = data.refreshToken;
        this.tokenExpiry = new Date(data.tokenExpiry);
        
        // Save the updated state
        await this.saveAuthState();
        
        console.log('Token refreshed successfully, new expiry:', this.tokenExpiry);
        return true;
      } else {
        console.error('Token refresh failed:', data.message);
        return false;
      }
    } catch (error) {
      console.error('Error refreshing token:', error);
      return false;
    } finally {
      this.refreshInProgress = false;
    }
  }
  
  /**
   * Register a new user
   * @param {Object} userData - User registration data
   * @returns {Promise} - API response
   */
  async register(userData) {
    try {
      // Ensure API URL is loaded
      if (!this.API_URL) {
        await this.loadAuthState();
      }

      console.log('Registering user with API URL:', this.API_URL);
      
      const response = await fetch(`${this.API_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData),
        credentials: 'include' // Include cookies in the request
      });
      
      console.log('Registration response status:', response.status);
      
      // Handle non-JSON responses or server errors
      if (!response.ok) {
        const errorText = await response.text();
        console.error('Server error during registration:', errorText);
        return {
          success: false,
          message: `Server error: ${response.status} ${response.statusText}`
        };
      }
      
      let data;
      try {
        data = await response.json();
        console.log('Registration response data:', data);
      } catch (parseError) {
        console.error('Failed to parse JSON response:', parseError);
        return {
          success: false,
          message: 'Invalid response from server'
        };
      }
      
      if (data.success) {
        this.user = data.user;
        this.token = data.token;
        this.refreshToken = data.refreshToken;
        this.tokenExpiry = new Date(data.tokenExpiry);
        this.isAuthenticated = true;
        await this.saveAuthState();
        console.log('Registration successful, auth state updated');
        
        // Set up token refresh
        this.setupTokenRefresh();
      } else {
        console.warn('Registration failed:', data.message);
      }
      
      return data;
    } catch (error) {
      console.error('Registration error:', error);
      return {
        success: false,
        message: 'Network or server error during registration: ' + error.message
      };
    }
  }
  
  /**
   * Login a user
   * @param {Object} credentials - User login credentials
   * @returns {Promise} - API response
   */
  async login(credentials) {
    try {
      // Ensure API URL is loaded
      if (!this.API_URL) {
        await this.loadAuthState();
      }
      
      console.log('Logging in user with API URL:', this.API_URL);
      
      const response = await fetch(`${this.API_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentials),
        credentials: 'include' // Include cookies in the request
      });
      
      console.log('Login response status:', response.status);
      
      // Handle non-JSON responses or server errors
      if (!response.ok) {
        const errorText = await response.text();
        console.error('Server error during login:', errorText);
        return {
          success: false,
          message: `Server error: ${response.status} ${response.statusText}`
        };
      }
      
      let data;
      try {
        data = await response.json();
        console.log('Login response data:', data);
      } catch (parseError) {
        console.error('Failed to parse JSON response:', parseError);
        return {
          success: false,
          message: 'Invalid response from server'
        };
      }
      
      if (data.success) {
        this.user = data.user;
        this.token = data.token;
        this.refreshToken = data.refreshToken; 
        this.tokenExpiry = new Date(data.tokenExpiry);
        this.isAuthenticated = true;
        await this.saveAuthState();
        console.log('Login successful, auth state updated');
        
        // Set up token refresh
        this.setupTokenRefresh();
      } else {
        console.warn('Login failed:', data.message);
      }
      
      return data;
    } catch (error) {
      console.error('Login error:', error);
      return {
        success: false,
        message: 'Network or server error during login: ' + error.message
      };
    }
  }
  
  /**
   * Logout the current user
   * @returns {Promise} - API response
   */
  async logout() {
    try {
      console.log("Starting logout process");
      
      // Clear any token refresh interval 
      this.clearRefreshInterval();
      
      // Only attempt server-side logout if we have a token
      if (this.isAuthenticated && this.token) {
        try {
          console.log("Sending logout request to server");
          const response = await fetch(`${this.API_URL}/auth/logout`, {
            method: 'POST', // Changed to POST to send refreshToken in body
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify({ refreshToken: this.refreshToken }),
            credentials: 'include' // Include cookies in the request
          });
          
          if (!response.ok) {
            console.warn("Server-side logout encountered an issue:", response.status);
          } else {
            console.log("Server-side logout successful");
          }
        } catch (error) {
          // Log but don't fail if server is unavailable
          console.warn("Failed to connect to server for logout:", error.message);
        }
      }
      
      // Always clear local storage state regardless of server response
      console.log("Clearing local authentication state");
      this.user = null;
      this.token = null;
      this.refreshToken = null;
      this.tokenExpiry = null;
      this.isAuthenticated = false;
      
      // Save cleared state to storage
      await this.saveAuthState();
      
      // Broadcast logout event for multi-tab/window synchronization
      this.broadcastLogout();
      
      console.log("Logout completed successfully");
      return {
        success: true,
        message: 'Logged out successfully'
      };
    } catch (error) {
      console.error('Logout error:', error);
      
      // Still clear local auth state on error
      this.user = null;
      this.token = null;
      this.refreshToken = null;
      this.tokenExpiry = null;
      this.isAuthenticated = false;
      await this.saveAuthState();
      this.clearRefreshInterval();
      
      return {
        success: true, // Still consider it successful from user perspective
        message: 'Logged out successfully (offline)'
      };
    }
  }
  
  /**
   * Broadcast logout event to other tabs/windows
   * This enables cross-tab synchronization of auth state
   */
  broadcastLogout() {
    // Skip if we're in a service worker
    if (isServiceWorker) return;
    
    try {
      // Use localStorage for broadcasting events between tabs
      localStorage.setItem('auth_logout_broadcast', Date.now().toString());
      console.log("Logout event broadcasted");
    } catch (e) {
      console.warn("Failed to broadcast logout event:", e);
    }
  }
  
  /**
   * Get current user profile
   * @returns {Promise} - User data or error
   */
  async getProfile() {
    if (!this.isAuthenticated) {
      return {
        success: false,
        message: 'Not authenticated'
      };
    }
    
    try {
      // Refresh token if needed before making the request
      await this.refreshTokenIfNeeded();
      
      const response = await fetch(`${this.API_URL}/auth/profile`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });
      
      const data = await response.json();
      
      if (data.success) {
        // Update local user data
        this.user = data.user;
        await this.saveAuthState();
      } else if (response.status === 401) {
        // Try to refresh token on 401
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry the request with new token
          return this.getProfile();
        } else {
          // Token refresh failed, log out
          this.user = null;
          this.token = null;
          this.refreshToken = null;
          this.tokenExpiry = null;
          this.isAuthenticated = false;
          await this.saveAuthState();
          this.clearRefreshInterval();
        }
      }
      
      return data;
    } catch (error) {
      console.error('Get profile error:', error);
      return {
        success: false,
        message: 'Network or server error getting profile'
      };
    }
  }
  
  /**
   * Update user preferences
   * @param {Object} preferences - User preferences to update
   * @returns {Promise} - API response
   */
  async updatePreferences(preferences) {
    if (!this.isAuthenticated) {
      return {
        success: false,
        message: 'Not authenticated'
      };
    }
    
    try {
      // Refresh token if needed before making the request
      await this.refreshTokenIfNeeded();
      
      const response = await fetch(`${this.API_URL}/auth/preferences`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({ preferences })
      });
      
      const data = await response.json();
      
      if (data.success && this.user) {
        // Update local user preferences
        this.user.preferences = {
          ...this.user.preferences,
          ...preferences
        };
        await this.saveAuthState();
      } else if (response.status === 401) {
        // Try to refresh token on 401
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry the request with new token
          return this.updatePreferences(preferences);
        }
      }
      
      return data;
    } catch (error) {
      console.error('Update preferences error:', error);
      return {
        success: false,
        message: 'Network or server error updating preferences'
      };
    }
  }
  
  /**
   * Add or remove URLs from user's allow/block list
   * @param {string} action - 'add' or 'remove'
   * @param {string} listType - 'allowList' or 'blockList'
   * @param {string} url - URL to add or remove
   * @returns {Promise} - API response
   */
  async updateLists(action, listType, url) {
    if (!this.isAuthenticated) {
      return {
        success: false,
        message: 'Not authenticated'
      };
    }
    
    try {
      // Refresh token if needed before making the request
      await this.refreshTokenIfNeeded();
      
      const response = await fetch(`${this.API_URL}/auth/lists`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({ action, listType, url })
      });
      
      const data = await response.json();
      
      if (response.status === 401) {
        // Try to refresh token on 401
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry the request with new token
          return this.updateLists(action, listType, url);
        }
      }
      
      return data;
    } catch (error) {
      console.error('Update lists error:', error);
      return {
        success: false,
        message: 'Network or server error updating lists'
      };
    }
  }
  
  /**
   * Check a URL with user-specific settings
   * @param {string} url - URL to check
   * @returns {Promise} - API response with safety check result
   */
  async checkURL(url) {
    const endpoint = this.isAuthenticated ? 
      `${this.API_URL}/urls/user-check` : 
      `${this.API_URL}/urls/check`;
    
    const headers = {
      'Content-Type': 'application/json'
    };
    
    if (this.isAuthenticated) {
      // Refresh token if needed before making the request
      await this.refreshTokenIfNeeded();
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ url })
      });
      
      // If authenticated and got 401, try token refresh
      if (this.isAuthenticated && response.status === 401) {
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry the request with new token
          return this.checkURL(url);
        }
      }
      
      return await response.json();
    } catch (error) {
      console.error('URL check error:', error);
      return {
        success: false,
        message: 'Network or server error checking URL'
      };
    }
  }
  
  /**
   * Get user URL history
   * @param {number} page - Page number for pagination
   * @param {number} limit - Items per page
   * @returns {Promise} - API response with user history
   */
  async getUserHistory(page = 1, limit = 10) {
    if (!this.isAuthenticated) {
      return {
        success: false,
        message: 'Not authenticated'
      };
    }
    
    try {
      // Refresh token if needed before making the request
      await this.refreshTokenIfNeeded();
      
      const response = await fetch(`${this.API_URL}/urls/user-history?page=${page}&limit=${limit}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });
      
      // If we get a 401, try token refresh
      if (response.status === 401) {
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry the request with new token
          return this.getUserHistory(page, limit);
        }
      }
      
      return await response.json();
    } catch (error) {
      console.error('Get history error:', error);
      return {
        success: false,
        message: 'Network or server error getting history'
      };
    }
  }
  
  /**
   * Get user URL safety statistics
   * @param {string} timeRange - 'week', 'month', or 'year'
   * @returns {Promise} - API response with user statistics
   */
  async getUserStats(timeRange = 'month') {
    if (!this.isAuthenticated) {
      return {
        success: false,
        message: 'Not authenticated'
      };
    }
    
    try {
      // Refresh token if needed before making the request
      await this.refreshTokenIfNeeded();
      
      const response = await fetch(`${this.API_URL}/urls/user-stats?range=${timeRange}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });
      
      // If we get a 401, try token refresh
      if (response.status === 401) {
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          // Retry the request with new token
          return this.getUserStats(timeRange);
        }
      }
      
      return await response.json();
    } catch (error) {
      console.error('Get stats error:', error);
      return {
        success: false,
        message: 'Network or server error getting statistics'
      };
    }
  }
}

// Export a singleton instance
const authService = new AuthService();
export default authService;