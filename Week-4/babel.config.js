module.exports = {
  presets: [
    [
      '@babel/preset-env',
      {
        modules: false, // Keep ES modules as-is for webpack to handle
        targets: {
          browsers: [
            'last 2 Chrome versions',
            'last 2 Firefox versions',
            'last 2 Safari versions',
            'last 2 Edge versions',
          ],
        },
        useBuiltIns: 'usage', // Add polyfills based on usage
        corejs: 3, // Use core-js v3
      },
    ],
  ],
  plugins: [
    '@babel/plugin-syntax-import-assertions',
    // Enable dynamic imports
    '@babel/plugin-syntax-dynamic-import',
    // Optional - only add this if you specifically need to transform ESM to CommonJS
    // ['@babel/plugin-transform-modules-commonjs', { strictMode: true }]
  ],
  sourceType: 'module', // Explicitly tell Babel we're using ES modules
  // Different configs for different environments
  env: {
    test: {
      presets: [
        ['@babel/preset-env', { targets: { node: 'current' } }]
      ],
      plugins: [
        '@babel/plugin-transform-modules-commonjs'
      ]
    },
    development: {
      // Development-specific settings
      compact: false,
      retainLines: true,
    },
    production: {
      // Production-specific settings
      compact: true,
      minified: true
    }
  }
};