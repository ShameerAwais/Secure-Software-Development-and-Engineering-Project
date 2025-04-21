const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');
require('dotenv').config({ path: path.resolve(__dirname, '.env') }); // Explicitly set the path to .env file

// Improved API key validation and logging
const apiKey = process.env.GSB_API_KEY;
if (!apiKey) {
  console.error('❌ ERROR: GSB_API_KEY not found in .env file!');
  console.error('❌ Create a .env file with GSB_API_KEY=your_api_key before building');
  process.exit(1); // Exit with error
}

console.log(`🔑 API Key from env: Found (length: ${apiKey.length})`);
console.log(`🔑 API Key first 5 chars: ${apiKey.substring(0, 5)}...`);

// Obfuscation options - adjust as needed for security vs performance
const obfuscationOptions = {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.75,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.4,
  debugProtection: false,
  debugProtectionInterval: 0,
  disableConsoleOutput: true,
  identifierNamesGenerator: 'hexadecimal',
  log: false,
  renameGlobals: false,
  rotateStringArray: true,
  selfDefending: true,
  shuffleStringArray: true,
  simplify: true,
  splitStrings: true,
  splitStringsChunkLength: 10,
  stringArray: true,
  stringArrayEncoding: ['base64'],
  stringArrayThreshold: 0.75,
  transformObjectKeys: true,
  unicodeEscapeSequence: false
};

// Source and output directories
const SOURCE_DIR = path.join(__dirname, 'src');
const OUTPUT_DIR = path.join(__dirname, 'dist');

// Make sure the output directory exists
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Copy manifest.json with adjusted paths
const updateManifest = () => {
  const manifestPath = path.join(__dirname, 'manifest.json');
  const outputManifestPath = path.join(OUTPUT_DIR, 'manifest.json');
  
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  
  // Update service worker path
  manifest.background.service_worker = manifest.background.service_worker.replace('src/', '');
  
  // Update content scripts paths
  if (manifest.content_scripts) {
    manifest.content_scripts.forEach(script => {
      script.js = script.js.map(js => js.replace('src/', ''));
    });
  }
  
  // Update web accessible resources
  if (manifest.web_accessible_resources) {
    manifest.web_accessible_resources.forEach(resource => {
      resource.resources = resource.resources.map(res => res.replace('src/', ''));
    });
  }
  
  // Update options page
  if (manifest.options_ui) {
    manifest.options_ui.page = manifest.options_ui.page.replace('src/', '');
  }
  
  // Update action popup
  if (manifest.action && manifest.action.default_popup) {
    manifest.action.default_popup = manifest.action.default_popup.replace('src/', '');
  }
  
  fs.writeFileSync(outputManifestPath, JSON.stringify(manifest, null, 2));
  console.log('✅ manifest.json updated and copied');
};

// Copy icons
const copyIcons = () => {
  const icons = ['test-icon16.png', 'test-icon48.png', 'test-icon128.png'];
  icons.forEach(icon => {
    const sourceIconPath = path.join(__dirname, icon);
    const outputIconPath = path.join(OUTPUT_DIR, icon);
    fs.copyFileSync(sourceIconPath, outputIconPath);
  });
  console.log('✅ Icons copied');
};

// Process config.js to securely handle API key
const processConfigFile = () => {
  const sourcePath = path.join(SOURCE_DIR, 'utils', 'config.js');
  const outputPath = path.join(OUTPUT_DIR, 'utils', 'config.js');
  
  // Make sure the output directory exists
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  // Read the original config file
  let configContent = fs.readFileSync(sourcePath, 'utf8');
  
  // Replace API key placeholder with a safe value for obfuscation
  const modifiedContent = configContent.replace(
    /apiKey:\s*['"]([^'"]*)['"]/,
    `apiKey: 'KEY_PLACEHOLDER'`
  );
  
  try {
    // Write the modified and obfuscated config file
    const obfuscatedCode = JavaScriptObfuscator.obfuscate(
      modifiedContent,
      obfuscationOptions
    ).getObfuscatedCode();
    
    fs.writeFileSync(outputPath, obfuscatedCode);
    console.log('✅ Config processed with secure API key handling');
  } catch (error) {
    console.error('❌ Error obfuscating config file:', error.message);
    // Fallback to just writing the modified file without obfuscation
    fs.writeFileSync(outputPath, modifiedContent);
    console.log('✅ Config processed (without obfuscation) with secure API key handling');
  }
  
  return apiKey;
};

// Recursively process all files in the source directory
const processFiles = (dirPath, baseDir = '', apiKey) => {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  
  for (const entry of entries) {
    const sourcePath = path.join(dirPath, entry.name);
    const relativePath = path.join(baseDir, entry.name);
    const outputPath = path.join(OUTPUT_DIR, relativePath);
    
    // Skip the config.js file as it's handled separately
    if (sourcePath === path.join(SOURCE_DIR, 'utils', 'config.js')) {
      continue;
    }
    
    if (entry.isDirectory()) {
      // Create the output directory if it doesn't exist
      if (!fs.existsSync(outputPath)) {
        fs.mkdirSync(outputPath, { recursive: true });
      }
      processFiles(sourcePath, relativePath, apiKey);
    } else {
      const extension = path.extname(entry.name).toLowerCase();
      
      // Handle different file types appropriately
      if (extension === '.js') {
        // Read file content
        let code = fs.readFileSync(sourcePath, 'utf8');
        
        // Special handling for gsb-api.js to inject API key retrieval logic
        if (sourcePath === path.join(SOURCE_DIR, 'background', 'gsb-api.js')) {
          code = injectApiKeyRetrieval(code);
        }
        
        // Obfuscate JavaScript files
        const obfuscatedCode = JavaScriptObfuscator.obfuscate(code, obfuscationOptions).getObfuscatedCode();
        fs.writeFileSync(outputPath, obfuscatedCode);
        console.log(`✅ Obfuscated: ${relativePath}`);
      } else if (extension === '.html' || extension === '.css') {
        // Copy HTML and CSS files
        fs.copyFileSync(sourcePath, outputPath);
        console.log(`✅ Copied: ${relativePath}`);
      }
    }
  }
};

// Inject code to retrieve the API key from secure storage
const injectApiKeyRetrieval = (code) => {
  // Add code to retrieve the API key from secure storage before making the request
  return code.replace(
    'apiUrl.searchParams.append(\'key\', GSB_CONFIG.apiKey);',
    `// Try to get API key from secure storage first
    let apiKey = GSB_CONFIG.apiKey;
    try {
      // Check if we have a stored API key
      const storedKey = await secureStorage.secureGet('gsb_api_key');
      if (storedKey) {
        apiKey = storedKey;
      }
    } catch (error) {
      logger.error(MODULE_NAME, 'Error retrieving API key from secure storage', error);
      // Fallback to config key
    }
    apiUrl.searchParams.append('key', apiKey);`
  );
};

// Create key-installation script
const createKeyInstaller = (apiKey) => {
  const installerDir = path.join(OUTPUT_DIR, 'background');
  const installerPath = path.join(installerDir, 'key-installer.js');
  
  if (!fs.existsSync(installerDir)) {
    fs.mkdirSync(installerDir, { recursive: true });
  }
  
  // Check if API key exists and is valid
  if (!apiKey || apiKey === 'KEY_PLACEHOLDER') {
    console.error('❌ ERROR: No valid API key found in .env file!');
    console.error('❌ Make sure you have a valid GSB_API_KEY in your .env file');
    process.exit(1); // Exit the build process with an error
  }
  
  // Create the key installer script with proper string escaping
  const safeApiKey = apiKey.replace(/'/g, "\\'");
  
  console.log(`🔑 Using API Key: ${safeApiKey.substring(0, 5)}... (${safeApiKey.length} characters)`);
  
  // Create the installer script that directly exposes the API key
  const directScript = `
  import * as secureStorage from '../utils/secure-storage.js';
  import * as logger from '../utils/logger.js';
  
  const MODULE_NAME = 'KeyInstaller';
  
  /**
   * This function installs or refreshes the Google Safe Browsing API key
   * in secure storage. The actual key is injected during the build process.
   */
  export const installApiKey = async () => {
    try {
      // API key directly injected by build process - no placeholder
      const apiKey = '${safeApiKey}';
      
      if (apiKey === 'KEY_PLACEHOLDER') {
        logger.error(MODULE_NAME, 'Production API key not injected during build process');
        // Try to check browser storage as a fallback
        const storedKey = await secureStorage.secureGet('gsb_api_key_backup');
        if (storedKey && storedKey !== 'KEY_PLACEHOLDER') {
          await secureStorage.secureSet('gsb_api_key', storedKey);
          logger.info(MODULE_NAME, 'API key restored from backup storage');
          return true;
        }
        return false;
      }
      
      // Store the API key securely
      await secureStorage.secureSet('gsb_api_key', apiKey);
      // Also keep a backup copy
      await secureStorage.secureSet('gsb_api_key_backup', apiKey);
      logger.info(MODULE_NAME, 'API key securely stored');
      return true;
    } catch (error) {
      logger.error(MODULE_NAME, 'Error storing API key', error);
      return false;
    }
  };
  
  /**
   * Get the stored API key from secure storage
   * @returns {Promise<string|null>} The API key or null if not found
   */
  export const getApiKey = async () => {
    try {
      const apiKey = await secureStorage.secureGet('gsb_api_key');
      if (!apiKey || apiKey === 'KEY_PLACEHOLDER') {
        logger.warn(MODULE_NAME, 'API key not found or is a placeholder');
        return null;
      }
      return apiKey;
    } catch (error) {
      logger.error(MODULE_NAME, 'Error retrieving API key', error);
      return null;
    }
  };
  `;
  
  try {
    // Write the non-obfuscated version first for debugging
    const debugPath = path.join(installerDir, 'key-installer.debug.js');
    fs.writeFileSync(debugPath, directScript);
    
    // Then create the obfuscated version for production
    const obfuscatedScript = JavaScriptObfuscator.obfuscate(
      directScript,
      {
        ...obfuscationOptions,
        stringArrayEncoding: ['rc4'],
        stringArrayThreshold: 1,
        transformObjectKeys: false, // Disable object key transformation for better compatibility
        unicodeEscapeSequence: false // Avoid Unicode escaping that might break the key
      }
    ).getObfuscatedCode();
    
    // Write the obfuscated version
    fs.writeFileSync(installerPath, obfuscatedScript);
    console.log('✅ Key installer script created with proper API key and obfuscated');
  } catch (error) {
    console.error('❌ Error obfuscating key installer:', error.message);
    // Fall back to non-obfuscated version
    fs.writeFileSync(installerPath, directScript);
    console.log('✅ Key installer script created with proper API key (without obfuscation)');
  }
};

// Main build process
const build = () => {
  console.log('🔨 Building Anti-Phishing Extension with code obfuscation...');
  
  // Start with an empty output directory
  if (fs.existsSync(OUTPUT_DIR)) {
    fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(OUTPUT_DIR);
  
  // Update and copy manifest.json
  updateManifest();
  
  // Copy icons
  copyIcons();
  
  // Process config file and get API key
  processConfigFile();
  
  // Create API key installer
  createKeyInstaller(apiKey);
  
  // Process all files in src directory
  processFiles(SOURCE_DIR, '', apiKey);
  
  console.log('🎉 Build completed successfully!');
};

// Execute the build
build();