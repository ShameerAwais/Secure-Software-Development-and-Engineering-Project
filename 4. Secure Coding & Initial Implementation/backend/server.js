// Main server file for the URL safety backend API
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
// Replace dotenv with direct import of JSON config
const config = require("./config/apiConfig.json");

// Import routes
const urlRoutes = require("./routes/urlRoutes");
const authRoutes = require("./routes/authRoutes");

// Import auth controller for token validation
const authController = require("./controllers/authController");

const app = express();
const PORT = config.PORT || 5000;

// Connect to MongoDB with improved error handling
mongoose.connect(config.MONGODB_URI || 'mongodb://localhost:27017/urlsafety', {
  // Adding explicit connection options for stability
  serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
  socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
})
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    // Continue running even if MongoDB fails - for stateless operation
    console.log('Running in stateless mode (no data persistence)');
  });

// Enhanced CORS configuration to ensure Chrome extension can connect
const corsOptions = {
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps, curl requests)
    if (!origin) return callback(null, true);
    
    // Allow requests from chrome extensions and localhost
    if (origin && (origin.startsWith('chrome-extension://') || origin.startsWith('http://localhost'))) {
      return callback(null, true);
    }
    
    callback(null, true); // Temporarily allow all origins for debugging
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // Cache preflight requests for 24 hours
};

// Middleware
app.use(helmet({
  contentSecurityPolicy: false // Disable CSP to prevent blocking extension requests
}));
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"));

// Authentication middleware
const authenticateUser = (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
      req.isAuthenticated = false;
      return next(); // Allow anonymous access with limitations
    }
    
    // Store the token in the request object for validation and logout
    req.token = token;
    
    const decoded = jwt.verify(token, config.JWT_SECRET || 'fallback_secret_key_for_development');
    req.user = decoded;
    req.isAuthenticated = true;
    
    // Validate that the token hasn't been invalidated (logged out)
    authController.validateToken(req, res, next);
  } catch (error) {
    req.isAuthenticated = false;
    return next(); // Continue as anonymous user on invalid token
  }
};

app.use(authenticateUser);

// Routes
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/urls", urlRoutes);

// Health check endpoint - make it highly available
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", message: "API is running" });
});

// Status endpoint for the extension - simplified for reliability
app.get("/api/v1/status", (req, res) => {
  console.log("Status endpoint called");
  res.status(200).json({ 
    status: "online", 
    version: "1.0.0",
    message: "Backend service is operational",
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'production' ? null : err.message
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://localhost:${PORT}`);
  
  // More detailed API key status
  const apiKey = config.GOOGLE_SAFE_BROWSING_API_KEY;
  const apiKeyStatus = apiKey && apiKey.length > 30 && !apiKey.includes('YOUR_') 
    ? 'Valid format detected' 
    : 'Not properly configured';
    
  console.log(`Google Safe Browsing API key: ${apiKeyStatus}`);
  
  // JWT secret check
  if (!config.JWT_SECRET) {
    console.warn('⚠️ Warning: JWT_SECRET not configured in apiConfig.json. Using fallback secret.');
    console.warn('This is not secure for production environments.');
  }
});

// Handle server errors
server.on('error', (error) => {
  console.error('Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Please use a different port.`);
    process.exit(1);
  }
});

// Graceful shutdown
process.on('SIGTERM', shutDown);
process.on('SIGINT', shutDown);

function shutDown() {
  console.log('Received kill signal, shutting down gracefully');
  server.close(() => {
    console.log('Closed out remaining connections');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });

  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
}

module.exports = app;
