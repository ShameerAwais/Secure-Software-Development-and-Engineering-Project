import { mlEngine } from './mlEngine.js';
import { secureApi } from './secureApi.js';

class URLSanitizer {
    sanitizeUrl(url) {
        try {
            // Remove any null bytes or control characters
            url = url.replace(/[\x00-\x1F\x7F]/g, '');
            
            // Ensure URL is properly encoded
            const sanitizedUrl = new URL(url).href;
            
            // Check for common injection patterns
            const suspiciousPatterns = [
                /javascript:/i,
                /data:/i,
                /vbscript:/i,
                /<script/i,
                /onload=/i,
                /onerror=/i
            ];
            
            if (suspiciousPatterns.some(pattern => pattern.test(sanitizedUrl))) {
                throw new Error('Potentially malicious URL detected');
            }
            
            return sanitizedUrl;
        } catch (error) {
            throw new Error(`URL Sanitization failed: ${error.message}`);
        }
    }
}

class URLChecker {
    constructor() {
        this.sanitizer = new URLSanitizer();
        this.API_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
        this.phishingData = new Map(); // Real-time phishing data storage
    }

    async extractFeatures(url) {
        // Extract relevant features for ML model
        const features = new Array(100).fill(0); // Initialize feature vector
        
        // Add basic features
        features[0] = url.length;
        features[1] = url.split('/').length;
        features[2] = url.split('.').length;
        features[3] = /^https/.test(url) ? 1 : 0;
        // Add more feature extraction logic here
        
        return features;
    }

    async checkPhishingURL(url, clientId) {
        try {
            // Validate session and rate limit
            if (!secureApi.checkRateLimit(clientId)) {
                throw new Error('Rate limit exceeded');
            }

            // Sanitize URL
            const sanitizedUrl = this.sanitizer.sanitizeUrl(url);

            // Extract features for ML model
            const features = await this.extractFeatures(sanitizedUrl);

            // Get ML prediction
            const mlPrediction = await mlEngine.predict(features);

            // Check against real-time phishing data
            const isKnownPhishing = this.phishingData.has(sanitizedUrl);

            // Log the check
            await secureApi.log('info', 'URL check performed', { clientId }, {
                url: sanitizedUrl,
                mlPrediction,
                isKnownPhishing
            });

            return mlPrediction > 0.7 || isKnownPhishing;
        } catch (error) {
            await secureApi.log('error', 'URL check failed', { clientId }, { error: error.message });
            throw error;
        }
    }

    async updatePhishingData(newData) {
        // Update real-time phishing data
        for (const [url, data] of Object.entries(newData)) {
            this.phishingData.set(url, data);
        }
    }
}

export const urlChecker = new URLChecker();
export const checkPhishingURL = urlChecker.checkPhishingURL.bind(urlChecker);