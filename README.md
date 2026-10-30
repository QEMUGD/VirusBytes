# VirusBytes

VirusBytes is a responsive security dashboard for on-demand file and URL checks using the official VirusTotal API v3. It has its own branding and is not affiliated with Malwarebytes or VirusTotal.

## Features

- Responsive, Malwarebytes-inspired dashboard with file and URL scan modes.
- File uploads up to 32 MB through VirusTotal's standard `/files` endpoint.
- HTTP and HTTPS URL submission through VirusTotal's `/urls` endpoint.
- Analysis status polling, detection totals, and individual engine verdicts.
- Recent scan history stored locally in the current browser.
- Server-side API key handling; the key is never delivered to browser JavaScript.
- Submission consent prompt and request rate limiting.
- A shared server-side request queue spaces VirusTotal API calls at least 15 seconds apart.

## Important limitations

VirusBytes is an on-demand scanning dashboard, **not a resident antivirus**. It does not continuously monitor your device, block file execution, remove malware, or quarantine files. Keep a reputable endpoint-protection product enabled.

A result with zero detections does not prove an item is safe. Engine coverage and verdicts vary, and new or targeted threats may not be detected.

Files and URLs submitted to the public VirusTotal service may be shared with VirusTotal's security community and security partners. Never submit confidential, personal, proprietary, or otherwise sensitive material. Use VirusTotal's private-scanning service only if your account has the required entitlement and your data-handling policy permits it.

The public VirusTotal API has strict quotas. The app serializes all outgoing API requests and spaces them at least 15 seconds apart, targeting no more than four requests per minute per server process. Your account's plan and current VirusTotal terms apply. When deploying multiple app instances, use a shared distributed rate limiter to coordinate their API calls.

## Setup

1. Install Node.js 20 or newer.
2. Clone this repository and run `npm install`.
3. Copy `.env.example` to `.env`.
4. Set your VirusTotal API v3 key in `.env` as `VT_API_KEY=your_real_api_key`.
5. Run `npm start` and visit [http://localhost:3000](http://localhost:3000).

**Never commit your `.env` file or put your API key in browser code.**

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Server and API-key configuration status |
| POST | `/api/scan/file` | Submit a multipart file field named `file` |
| POST | `/api/scan/url` | Submit JSON containing a `url` field |
| GET | `/api/analyses/:id` | Retrieve an analysis result |

## Configuration

- `VT_API_KEY` — required VirusTotal API v3 key.
- `PORT` — optional HTTP port (defaults to `3000`).

The current version supports files up to 32 MB. Larger-file upload URLs, private scanning, user accounts, and server-side persistent history are not implemented.

## Technology

Node.js, Express, Multer, Helmet, express-rate-limit, and vanilla HTML/CSS/JavaScript.

## License

MIT
