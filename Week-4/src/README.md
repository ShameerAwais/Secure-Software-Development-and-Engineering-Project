# No Phish - Anti-Phishing Browser Extension

A browser extension that helps protect users from phishing websites using machine learning and secure architecture.

## Features

- Real-time phishing detection using ML algorithms
- Secure API communication with rate limiting
- User consent-based data collection
- Configurable protection settings
- Desktop notifications for detected threats
- Badge indicators for suspicious sites
- Whitelist support for trusted domains

## Development Setup

1. Install dependencies:
```bash
npm install
```

2. Build the extension:
```bash
npm run build
```

3. For development with hot reloading:
```bash
npm run dev
```

4. Load the extension in your browser:
- Open Chrome/Edge
- Go to `chrome://extensions/` or `edge://extensions/`
- Enable "Developer mode"
- Click "Load unpacked"
- Select the `dist` directory

## Project Structure

```
src/
├── background.js      # Background service worker for URL monitoring
├── content.js         # Content script for inline warnings
├── mlEngine.js        # Machine learning engine for phishing detection
├── options.js         # Options page logic
├── popup.js           # Popup UI logic
├── secureApi.js       # Secure API communication
├── urlChecker.js      # URL checking service
├── icons/             # Extension icons
│   └── icon48.png
├── popup.html         # Popup UI
└── options.html       # Options page UI
```

## Core Components

### ML Engine (`mlEngine.js`)
- Implements phishing detection patterns
- Checks for suspicious subdomains, IP addresses, and TLDs
- Analyzes URL structure and keywords

### URL Checker (`urlChecker.js`)
- Validates URLs
- Integrates with ML engine for phishing detection
- Handles error cases and logging

### Secure API (`secureApi.js`)
- Manages client authentication
- Implements rate limiting
- Handles secure logging
- Manages session tokens

### Background Service (`background.js`)
- Monitors web navigation
- Manages extension state
- Handles notifications and badges
- Implements whitelist functionality

## Development Workflow

1. Code changes should be made in the `src` directory
2. Run `npm run lint` to check code quality
3. Run `npm test` to run tests
4. Build the extension with `npm run build`
5. Load the extension in your browser to test

## Security Features

- Secure session management
- Rate limiting to prevent abuse
- User consent for data collection
- Encrypted logging
- Whitelist for trusted domains
- Secure API communication

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

MIT 