# PhishGuard

A browser extension that helps protect users from phishing websites using secure architecture.

## Features

- Real-time phishing detection
- Machine learning-based URL analysis
- Secure API communication
- User consent-based data collection
- Configurable protection settings

## Project Structure

```
backend/                # Server-side application
├── config/             # API configuration
├── controllers/        # Request handlers
├── models/             # Database models
├── routes/             # API routes
└── utils/              # Utility functions including phishing detection engine

extension/              # Browser extension
├── css/                # Stylesheets
├── images/             # Extension icons
├── js/                 # JavaScript functionality
│   ├── auth.js         # Authentication handling
│   ├── background.js   # Background service worker
│   ├── content.js      # Content scripts for web pages
│   └── popup.js        # Extension popup functionality
└── pages/              # HTML pages for extension UI
```

## Development Setup

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Install backend dependencies:
```bash
npm install
```

3. Start the backend server:
```bash
node server.js
```

### Extension Setup

1. Navigate to the extension directory:
```bash
cd extension
```

2. Load the extension in your browser:
- Open Chrome/Edge
- Go to `chrome://extensions/` or `edge://extensions/`
- Enable "Developer mode"
- Click "Load unpacked"
- Select the `extension` directory

## Development Workflow

1. Make changes to the relevant files in either the backend or extension directories
2. For backend changes, restart the server to see effects
3. For extension changes, reload the extension in your browser's extension page

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test your implementation thoroughly
5. Submit a pull request

## License

MIT