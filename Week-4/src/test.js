// Test URLs from Google's Safe Browsing test page
const testUrls = {
  safe: [
    'https://google.com',
    'https://github.com'
  ],
  unsafe: [
    'https://testsafebrowsing.appspot.com/s/phishing.html',
    'https://testsafebrowsing.appspot.com/s/malware.html'
  ]
};

// Import the checkPhishingURL function
import { checkPhishingURL } from './urlChecker.js';

async function runTests() {
  console.log('🏃‍♂️ Starting extension tests...');

  // Test safe URLs
  console.log('\n📝 Testing safe URLs:');
  for (const url of testUrls.safe) {
    try {
      const result = await checkPhishingURL(url);
      console.log(`${url}: ${result ? '❌ Failed (false positive)' : '✅ Passed'}`);
    } catch (error) {
      console.error(`Error testing ${url}:`, error);
    }
  }

  // Test unsafe URLs
  console.log('\n📝 Testing unsafe URLs:');
  for (const url of testUrls.unsafe) {
    try {
      const result = await checkPhishingURL(url);
      console.log(`${url}: ${result ? '✅ Passed' : '❌ Failed (false negative)'}`);
    } catch (error) {
      console.error(`Error testing ${url}:`, error);
    }
  }
}

// Run the tests when the script is loaded
runTests();