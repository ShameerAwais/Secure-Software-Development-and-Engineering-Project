const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');

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

// Recursively process all files in the source directory
const processFiles = (dirPath, baseDir = '') => {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  
  for (const entry of entries) {
    const sourcePath = path.join(dirPath, entry.name);
    const relativePath = path.join(baseDir, entry.name);
    const outputPath = path.join(OUTPUT_DIR, relativePath);
    
    if (entry.isDirectory()) {
      // Create the output directory if it doesn't exist
      if (!fs.existsSync(outputPath)) {
        fs.mkdirSync(outputPath, { recursive: true });
      }
      processFiles(sourcePath, relativePath);
    } else {
      const extension = path.extname(entry.name).toLowerCase();
      
      // Handle different file types appropriately
      if (extension === '.js') {
        // Obfuscate JavaScript files
        const code = fs.readFileSync(sourcePath, 'utf8');
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
  
  // Process all files in src directory
  processFiles(SOURCE_DIR);
  
  console.log('🎉 Build completed successfully!');
};

// Execute the build
build();