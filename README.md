# Enhanced Network Tab

A lightweight Firefox extension for capturing, analyzing, and modifying HTTP/HTTPS requests in real-time.

[![Install from Firefox Add-ons](https://img.shields.io/badge/Firefox-Install-orange?logo=firefox)](https://addons.mozilla.org/en-US/firefox/addon/enhanced-network-tab/)

## Features

- **Request Capture**: Monitor all HTTP/HTTPS traffic from the active tab
- **Request Interception**: Apply native URL/request-header edits or opt into experimental cancel-and-send behavior for edited method/body requests
- **Response Interception**: Intercept text and binary responses before they reach the browser; binary or unknown bodies are edited as Base64, while responses over the 10 MiB edit limit are forwarded unchanged
- **Match & Replace**: Create rules for request URLs, header-scoped request values, and text response bodies
- **Security Scanner**: Automatically scan response bodies for sensitive data and security issues
- **Vulnerable JS Library Scanner**: Detect outdated JavaScript libraries with known CVEs (Thanks to Retire.js)
- **Request Repeater**: Resend requests with custom modifications for testing
- **Advanced Filtering**: Filter requests by method, URL patterns, and file types
- **Responsive UI**: Optimized layout that automatically adapts to vertical split views or narrower windows
- **Dark/Light Theme**: Automatic or manual theme switching
- **Export as cURL**: Copy any request (original or modified) as a cURL command
- **Decoder**: Built-in tool for encoding/decoding URL, Base64, Hex, HTML, and JWT
- **Column Sorting**: Sort and resize request table columns
- **Search**: Search through request/response headers and bodies
- **Highlighting Rules**: Color-code requests based on custom URL patterns

### Security Scanner (Beta)

The built-in security scanner automatically analyzes response bodies while you browse, detecting potential security issues. **This feature is currently in beta.**

**Supported API Key Patterns (100+ patterns):**

| Service | Detected Token Types |
|---------|---------------------|
| **AWS** | Access Key ID, Secret Key |
| **Google Cloud** | API Key, OAuth Access Token |
| **GitHub** | Classic PAT, Fine-Grained PAT, OAuth, User-to-Server, Server-to-Server, Refresh Token |
| **OpenAI** | User API Key, Project Key, Service Key (with T3BlbkFJ marker) |
| **Stripe** | Live/Test Secret Key, Restricted Key, Publishable Key |
| **Slack** | Bot Token, User Token, Config Token, Refresh Token, Webhook |
| **Facebook** | Access Token, OAuth 2.0 |
| **Square** | Access Token, OAuth Secret |
| **PayPal/Braintree** | Access Token |
| **Twilio** | API Key |
| **SendGrid** | API Key |
| **Mailgun** | API Key |
| **MailChimp** | Access Token |
| **WakaTime** | API Key |
| **Amazon MWS** | Auth Token |
| **Foursquare** | Secret Key |
| **Picatic** | API Key |
| **GitLab** | Personal Access Token |
| **Anthropic** | API Key |
| **HuggingFace** | API Token |
| **Replicate** | API Token |
| **DigitalOcean** | Personal Access Token |
| **Notion** | Integration Token |
| **Azure** | Storage Connection String |
| **Firebase** | Cloud Messaging Token |
| **Dropbox** | Access Token |
| **Cloudflare** | API Token |
| **Terraform** | Token |

**Other Detection Categories:**
- **Credentials**: Hardcoded passwords, usernames, database credentials, connection strings
- **JWT Tokens**: JSON Web Tokens with validation
- **Private Keys**: RSA, DSA, EC, OpenSSH, PGP private keys
- **Basic Auth**: Credentials embedded in URLs
- **Generic Secrets**: API keys, access tokens, client secrets in variable assignments
- **Emails**: Email addresses found in JavaScript code
- **API Endpoints**: Hardcoded fetch/axios/XHR URLs and API base configurations
- **Sensitive Files**: Environment files (.env), SSH keys, Git exposure, backup files

**Database Connection URLs:**
- **MongoDB**: Connection URLs with embedded credentials (`mongodb://`, `mongodb+srv://`)
- **PostgreSQL**: Connection URLs (`postgres://`, `postgresql://`)
- **MySQL**: Connection URLs (`mysql://`)
- **Redis**: Connection URLs (`redis://`)
- **RabbitMQ**: Connection URLs (`amqp://`)

**Features:**
- Background scanning even when DevTools is closed (with Capture enabled)
- Real-time scanning with badge notification on extension icon
- iOS-style notification badge showing unseen findings count
- Filterable by category and severity (Critical, High, Medium, Low, Info)
- Per-request Security tab showing findings for selected request
- Export findings as JSON for further analysis
- False positive filtering for placeholder values
- JSON and config file format support

### Vulnerable JavaScript Library Scanner (Beta)

Automatically detects outdated JavaScript libraries with known security vulnerabilities, similar to [Retire.js](https://github.com/AleenCloud/retire.js).

**How It Works:**
- Scans JavaScript files loaded by websites
- Detects library versions via filename patterns, URL paths, and file content signatures
- Checks versions against a bundled vulnerability database (64+ libraries)
- Displays CVE identifiers, CWE categories, and severity ratings

**Supported Libraries Include:**
| Category | Libraries |
|----------|-----------|
| **DOM/UI** | jQuery, jQuery UI, jQuery Mobile, jQuery Migrate, Bootstrap, Angular, AngularJS, React, Vue.js, Ember.js, Backbone.js |
| **Utilities** | Lodash, Underscore.js, Moment.js, Handlebars, Mustache |
| **Editors** | TinyMCE, CKEditor, CodeMirror |
| **Media** | Video.js, jPlayer, Plyr |
| **Other** | D3.js, Chart.js, Socket.io, Three.js, Knockout, YUI, Prototype.js, Dojo, MooTools |

**Features:**
- Offline detection using bundled vulnerability database
- Merged findings for same library+version with multiple vulnerabilities
- Clickable CVE links to NVD database
- Severity-based filtering (Critical, High, Medium, Low)
- Detection method indicator (filename, URI, or file content)

## Screenshots

### Main Dashboard
![Enhanced Network Tab Dashboard](readme-pictures/dashboard.png)

### Request Interception
![Request Interception Modal](readme-pictures/interception.png)

## Installation

### From Firefox Add-ons

**[Install directly from Firefox Add-ons →](https://addons.mozilla.org/en-US/firefox/addon/enhanced-network-tab/)**

Click the link above or search for "Enhanced Network Tab" in Firefox Add-ons.

### From Source

1. Clone or download this repository
2. Open Firefox and navigate to `about:debugging`
3. Click "This Firefox" in the left sidebar
4. Click "Load Temporary Add-on"
5. Navigate to the extension directory and select the `manifest.json` file

## Usage

1. Open Firefox Developer Tools (F12)
2. Navigate to the "Enhanced Network Tab" panel
3. Toggle "Capture" to start monitoring network traffic
4. Toggle "Intercept" to intercept and modify requests (optional)
5. Click on any request to view details
6. Use "Send to Repeater" to resend modified requests
7. Configure intercept rules via "Intercept Settings"
8. Click "Automated Scanner" button to view security findings (badge shows unseen count)

`Intercept Settings → Method/body edit handling` controls edits that Firefox cannot apply to the original request. The safe default forwards the original and opens an unsent Repeater draft. The experimental option cancels the page request and automatically sends the edited copy from the extension.

### Firefox API limitation

Firefox WebExtensions cannot transparently replace the HTTP method or request body of an existing page request. In the default safe mode, Enhanced Network Tab forwards the original page request and opens the edited request as an **unsent Repeater draft**. The draft only reaches the network after you explicitly send it.

The opt-in experimental mode provides a different workflow: after validation, it cancels the original request and sends the edited copy immediately as an extension-origin request. The page's fetch/XHR fails and never receives the replacement response; the response is available only in the extension's Repeater view. Cookie, origin, CORS and service-worker behavior can differ from the page request. Early Interception is disabled while this mode is active because request headers are not available at the early stage.

After the release that introduces this feature is installed as an update, the first opened DevTools panel shows a one-time banner. `Review in Settings` opens Intercept Settings, scrolls to the relevant option and highlights it; it never enables the mode automatically. Selecting the experimental option still requires an explicit confirmation when the settings are saved, while `Dismiss` leaves the safe default unchanged.

URL and request-header changes can be applied to the original request. Response-header and response-body changes can also be applied to the response. A transparent method/body proxy would require a separate native application and local proxy; this extension does not install or claim to provide one.


## Privacy & Security

Scanning and vulnerability lookup run locally in the extension:

- No analytics, tracking, or telemetry
- Captured requests and exact scanner matches stay in extension memory and are limited per tab
- Persisted scanner findings are masked, omit surrounding secret context, and expire after 24 hours
- Local storage also holds UI preferences, interception settings, and Match & Replace rules
- Repeater sends a network request only after an explicit user action; the request originates from the extension and can differ from a page-origin request (for example, cookies or CORS context)
- Experimental cancel-and-send is disabled by default. When enabled, each edited replacement still requires the explicit `Cancel Original & Send Edited` action; cross-origin Cookie/Authorization forwarding requires an additional confirmation
- The extension requires access to all URLs because Firefox's `webRequest` API needs host access to capture and modify traffic

The bundled library vulnerability database is read locally. Captured data is not sent to an analytics or vendor service by the extension. Normal page traffic and explicit Repeater requests still communicate with their requested destinations.

## Browser Compatibility

- **Firefox Desktop**: Version 78 or later
- **Firefox for Android**: Not supported (Firefox Android does not expose the desktop DevTools panel used by this extension)
- **Chrome/Edge**: Not supported (uses Firefox-specific WebExtension APIs)

## Development

The extension is built using vanilla JavaScript with Firefox Manifest V2 WebExtension APIs. The background entry is a persistent MV2 background page, not a service worker.

### Commands

```sh
npm ci
npm run check
npm run lint:addon
npm run package
```

Packaging copies an explicit allowlist into a temporary directory before building `dist/enhanced_network_tab-<version>.zip`, so development files and local archives cannot enter the release artifact.

### File Structure

```
├── background/
│   └── background.js          # Persistent MV2 background logic
├── devtools/
│   ├── devtools.html          # DevTools panel entry point
│   ├── devtools.js            # DevTools panel initialization
│   ├── panel.html             # Main UI
│   ├── panel.js               # UI logic and event handlers
│   ├── panel.css              # Styles with theme support
│   └── security-scanner.js    # Security scanning module
├── shared/                    # Shared HTTP/session/lifecycle/privacy cores
├── scripts/                   # Development checks and release packaging
├── icons/                     # Extension icons
├── jsrepository.json          # Vulnerable JS library database (Retire.js format)
└── manifest.json              # Extension manifest
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

For bugs, feature requests, or questions, please open an issue on GitHub.
