const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const WebpackObfuscator = require('webpack-obfuscator');

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
    clean: true,
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
                modules: false,
                targets: {
                  chrome: '80'
                }
              }]
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