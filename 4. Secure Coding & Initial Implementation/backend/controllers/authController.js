const User = require('../models/User');
const jwt = require('jsonwebtoken');
const config = require('../config/apiConfig.json');

const JWT_SECRET = config.JWT_SECRET || 'fallback_secret_key_for_development';
const JWT_EXPIRY = '1d'; // Token valid for 1 day
const REFRESH_TOKEN_EXPIRY = '7d'; // Refresh token valid for 7 days

// Store for invalidated tokens - in a real production app this would be in Redis or a database
const invalidatedTokens = new Map();
const refreshTokens = new Map(); // Map to store refresh tokens: { refreshToken: { userId, expiresAt } }

// Function to clean up expired tokens from the invalidated tokens store
const cleanupInvalidatedTokens = () => {
  const now = Date.now();
  for (const [token, expiryTime] of invalidatedTokens.entries()) {
    if (now > expiryTime) {
      invalidatedTokens.delete(token);
    }
  }
  
  // Also clean up expired refresh tokens
  for (const [token, data] of refreshTokens.entries()) {
    if (now > data.expiresAt) {
      refreshTokens.delete(token);
    }
  }
};

// Clean up invalidated tokens every hour
setInterval(cleanupInvalidatedTokens, 60 * 60 * 1000);

// Generate access token
const generateAccessToken = (user) => {
  return jwt.sign(
    { 
      id: user._id, 
      email: user.email,
      role: user.role
    }, 
    JWT_SECRET, 
    { expiresIn: JWT_EXPIRY }
  );
};

// Generate refresh token
const generateRefreshToken = (user) => {
  const refreshToken = jwt.sign(
    { 
      id: user._id,
      type: 'refresh'
    }, 
    JWT_SECRET, 
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );
  
  // Calculate expiration time
  const decoded = jwt.decode(refreshToken);
  const expiresAt = decoded.exp * 1000; // Convert from seconds to milliseconds
  
  // Store refresh token with user ID and expiration
  refreshTokens.set(refreshToken, {
    userId: user._id.toString(),
    expiresAt: expiresAt
  });
  
  return refreshToken;
};

// Token validation middleware - make sure this is used in your middleware chain
exports.validateToken = (req, res, next) => {
  // Check if token is invalidated
  if (req.token && invalidatedTokens.has(req.token)) {
    return res.status(401).json({
      success: false,
      message: 'Token has been invalidated. Please login again.'
    });
  }
  
  next();
};

// Register a new user
exports.register = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already registered' 
      });
    }
    
    // Create new user
    const user = new User({
      email,
      password,
      name,
      preferences: {
        securityLevel: 'medium',
        notifications: true
      }
    });
    
    await user.save();
    
    // Generate tokens
    const token = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds
      sameSite: 'strict'
    });
    
    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      refreshToken,
      tokenExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 1 day from now
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        preferences: user.preferences
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error registering user',
      error: error.message
    });
  }
};

// Login user
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    // Validate password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    // Update last login
    user.lastLogin = Date.now();
    await user.save();
    
    // Generate tokens
    const token = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds (matches JWT_EXPIRY)
      sameSite: 'strict'
    });
    
    return res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      refreshToken,
      tokenExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 1 day from now
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        preferences: user.preferences,
        allowList: user.allowList,
        blockList: user.blockList
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error logging in',
      error: error.message
    });
  }
};

// Refresh token endpoint
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }
    
    // Check if the refresh token exists in our store
    const tokenData = refreshTokens.get(refreshToken);
    if (!tokenData) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token'
      });
    }
    
    // Verify the refresh token signature and expiration
    try {
      const decoded = jwt.verify(refreshToken, JWT_SECRET);
      
      // Find the user
      const user = await User.findById(tokenData.userId);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }
      
      // Generate new access token
      const newAccessToken = generateAccessToken(user);
      
      // Optionally rotate the refresh token for better security
      // This means each refresh generates a new refresh token as well
      const newRefreshToken = generateRefreshToken(user);
      
      // Invalidate the old refresh token
      refreshTokens.delete(refreshToken);
      
      return res.status(200).json({
        success: true,
        token: newAccessToken,
        refreshToken: newRefreshToken,
        tokenExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 1 day from now
        message: 'Token refreshed successfully'
      });
      
    } catch (error) {
      // Token verification failed
      refreshTokens.delete(refreshToken); // Remove invalid token
      
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
        error: error.message
      });
    }
    
  } catch (error) {
    console.error('Token refresh error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error refreshing token',
      error: error.message
    });
  }
};

// Get user profile
exports.getProfile = async (req, res) => {
  try {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    return res.status(200).json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        preferences: user.preferences,
        allowList: user.allowList,
        blockList: user.blockList,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error getting profile',
      error: error.message
    });
  }
};

// Update user preferences
exports.updatePreferences = async (req, res) => {
  try {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    const { preferences } = req.body;
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Update only valid preference fields
    user.preferences = {
      ...user.preferences,
      ...(preferences || {})
    };
    
    await user.save();
    
    return res.status(200).json({
      success: true,
      message: 'Preferences updated successfully',
      preferences: user.preferences
    });
  } catch (error) {
    console.error('Update preferences error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating preferences',
      error: error.message
    });
  }
};

// Logout user
exports.logout = (req, res) => {
  // If the user has a valid token, invalidate it
  if (req.token) {
    try {
      // Decode token to get expiration time
      const decoded = jwt.verify(req.token, JWT_SECRET);
      const expiryTimeMs = decoded.exp * 1000; // Convert seconds to milliseconds
      
      // Add the token to invalidated tokens list with its expiration time
      invalidatedTokens.set(req.token, expiryTimeMs);
      console.log(`Token invalidated: ${req.token.substring(0, 10)}...`);
    } catch (error) {
      // Invalid token, no need to invalidate
      console.warn('Failed to invalidate token:', error.message);
    }
  }
  
  // Also remove refresh token if provided
  const refreshToken = req.body.refreshToken;
  if (refreshToken && refreshTokens.has(refreshToken)) {
    refreshTokens.delete(refreshToken);
    console.log('Refresh token removed');
  }
  
  // Clear the cookie regardless of token validation
  res.clearCookie('token');
  
  return res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
};

// Manage allowlist/blocklist
exports.updateLists = async (req, res) => {
  try {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    const { action, listType, url } = req.body;
    
    if (!['add', 'remove'].includes(action)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid action. Must be "add" or "remove"'
      });
    }
    
    if (!['allowList', 'blockList'].includes(listType)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid list type. Must be "allowList" or "blockList"'
      });
    }
    
    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Process the request
    if (action === 'add') {
      // Add URL to the specified list if not already there
      const list = user[listType];
      const existingEntry = list.find(item => item.url === url);
      
      if (!existingEntry) {
        list.push({ url, addedAt: new Date() });
        console.log(`Added ${url} to ${listType} for user ${user.email}`);
      }
      
      // If adding to allow list, remove from block list
      if (listType === 'allowList') {
        user.blockList = user.blockList.filter(item => item.url !== url);
      }
      // If adding to block list, remove from allow list
      else if (listType === 'blockList') {
        user.allowList = user.allowList.filter(item => item.url !== url);
      }
    } else {
      // Remove URL from the specified list
      user[listType] = user[listType].filter(item => item.url !== url);
      console.log(`Removed ${url} from ${listType} for user ${user.email}`);
    }
    
    await user.save();
    
    return res.status(200).json({
      success: true,
      message: `URL ${action === 'add' ? 'added to' : 'removed from'} ${listType} successfully`,
      list: user[listType]
    });
  } catch (error) {
    console.error('Update lists error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating lists',
      error: error.message
    });
  }
};