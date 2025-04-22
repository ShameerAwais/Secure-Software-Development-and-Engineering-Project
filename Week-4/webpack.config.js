const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const WebpackObfuscator = require('webpack-obfuscator');
const webpack = require('webpack');
const dotenv = require('dotenv');
const fs = require('fs');

// Load env variables from .env file
const env = dotenv.config().parsed || {};

// Validate API key
const apiKey = env.GSB_API_KEY;
if (!apiKey || apiKey === 'KEY_PLACEHOLDER') {
  console.error('❌ ERROR: No valid API key found in .env file!');
  console.error('❌ Make sure you have a valid GSB_API_KEY in your .env file');
  process.exit(1); // Exit with error
}

module.exports = {
  mode: 'production',
  entry: {
    // Background scripts
    background: './src/background/background.js',
    
    // Content scripts
    content: './src/content/content.js',
    
    // Popup
    popup: './src/popup/popup.js',
    
    // Settings page
    settings: './src/settings/settings.js',
    
    // Block page
    'block_page/blocked': './src/block_page/blocked.js',
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean: {
      keep: /background\/key-installer\.js/, // Keep our manually created key-installer.js
    },
  },
  // Fix module configuration
  experiments: {
    outputModule: false,
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', {
                targets: {
                  chrome: '80'
                },
                modules: 'commonjs' // Transform ES modules to CommonJS
              }]
            ],
            plugins: [
              '@babel/plugin-transform-modules-commonjs'
            ]
          }
        }
      }
    ]
  },
  resolve: {
    extensions: ['.js']
  },
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          format: {
            comments: false,
          },
          compress: {
            drop_console: true,
          },
        },
        extractComments: false,
      }),
    ],
  },
  plugins: [
    // Replace API key placeholder in key-installer.js
    new webpack.DefinePlugin({
      'process.env.GSB_API_KEY': JSON.stringify(env.GSB_API_KEY || 'KEY_PLACEHOLDER'),
    }),
    
    // String replacements - better approach for injecting API key
    new webpack.NormalModuleReplacementPlugin(
      /src\/background\/key-installer\.js/,
      (resource) => {
        // This will run for the key-installer.js file
        resource.loaders = [{
          loader: 'string-replace-loader',
          options: {
            search: /const apiKey = ['"]KEY_PLACEHOLDER['"]/g,
            replace: `const apiKey = '${apiKey.replace(/'/g, "\\'")}'`,
            flags: 'g'
          }
        }];
      }
    ),
    
    // Apply obfuscation as a plugin
    new WebpackObfuscator({
      rotateStringArray: true,
      stringArray: true,
      stringArrayEncoding: ['base64'],
      stringArrayThreshold: 0.8,
      identifierNamesGenerator: 'hexadecimal',
      deadCodeInjection: true,
      deadCodeInjectionThreshold: 0.4,
      renameGlobals: false,
      selfDefending: true,
      splitStrings: true,
      splitStringsChunkLength: 10,
      transformObjectKeys: true,
      unicodeEscapeSequence: false,
      controlFlowFlattening: true,
      controlFlowFlatteningThreshold: 0.75,
      disableConsoleOutput: true,
    }),
    // Copy static assets to the dist folder
    new CopyPlugin({
      patterns: [
        { 
          from: 'manifest.json',
          to: 'manifest.json',
          transform(content) {
            // Update paths in the manifest to point to the new dist structure
            const manifest = JSON.parse(content.toString());
            
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
            
            return JSON.stringify(manifest, null, 2);
          },
        },
        { from: '*.png', to: '[name][ext]' },
        { from: 'src/popup/popup.html', to: 'popup/popup.html' },
        { from: 'src/popup/popup.css', to: 'popup/popup.css' },
        { from: 'src/settings/settings.html', to: 'settings/settings.html' },
        { from: 'src/settings/settings.css', to: 'settings/settings.css' },
        { from: 'src/block_page/blocked.html', to: 'block_page/blocked.html' },
        { from: 'src/block_page/blocked.css', to: 'block_page/blocked.css' },
      ],
    }),
  ],
};