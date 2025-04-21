# No Phish - Anti-Phishing Browser Extension

A browser extension that helps protect users from phishing websites using machine learning and secure architecture.

## Features

- Real-time phishing detection
- Machine learning-based URL analysis
- Secure API communication
- User consent-based data collection
- Configurable protection settings

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
├── background/     # Background scripts for extension functionality
├── block_page/     # UI for blocked page display
├── common/         # Shared utilities and constants
├── content/        # Content scripts that run in web pages
├── popup/          # Extension popup interface
├── settings/       # Settings page interface
└── utils/          # Utility functions for security and validation
```

## Development Workflow

1. Code changes should be made in the `src` directory
2. Run `npm run lint` to check code quality
3. Run `npm test` to run tests
4. Build the extension with `npm run build`
5. Load the extension in your browser to test

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

MIT