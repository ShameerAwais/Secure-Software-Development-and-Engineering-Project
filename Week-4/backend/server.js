// Main server file for the URL safety backend API
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
// Replace dotenv with direct import of JSON config
const config = require("./config/apiConfig.json");

// Import routes
const urlRoutes = require("./routes/urlRoutes");

const app = express();
const PORT = config.PORT || 5000;

// Enhanced CORS configuration to ensure Chrome extension can connect
const corsOptions = {
  origin: ['chrome-extension://*', 'http://localhost:*'],
  methods: ['GET', 'POST'],
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
app.use(morgan("dev"));

// Routes
app.use("/api/v1/urls", urlRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", message: "API is running" });
});

// Status endpoint for the extension
app.get("/api/v1/status", (req, res) => {
  res.status(200).json({ 
    status: "online", 
    version: "1.0.0",
    message: "Backend service is operational" 
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  // More detailed API key status
  const apiKey = config.GOOGLE_SAFE_BROWSING_API_KEY;
  const apiKeyStatus = apiKey && apiKey.length > 30 && !apiKey.includes('YOUR_') 
    ? 'Valid format detected' 
    : 'Not properly configured';
    
  console.log(`Google Safe Browsing API key: ${apiKeyStatus}`);
  
  if (apiKeyStatus !== 'Valid format detected') {
    console.warn('⚠️ Warning: Google Safe Browsing API key appears to be missing or invalid.');
    console.warn('Phishing detection will rely only on local analysis.');
  }
});

module.exports = app;
