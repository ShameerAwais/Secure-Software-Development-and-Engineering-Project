import { mlEngine } from './mlEngine.js';

// URL checker service
export const checkPhishingURL = async (url, clientId) => {
  try {
    // Basic URL validation
    if (!url || typeof url !== 'string') {
      throw new Error('Invalid URL');
    }

    // Use ML engine to check URL
    const isPhishing = await mlEngine.predict(url);
    return isPhishing;
  } catch (error) {
    console.error('Error checking URL:', error);
    throw error;
  }
}; 