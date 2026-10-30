# VirusBytes

VirusBytes is an independent security dashboard and native Android companion for on-demand file and URL checks using the official VirusTotal API v3. It is not affiliated with Malwarebytes or VirusTotal.

## Android app

The native Android app is in `app/` and is built with Kotlin and Jetpack Compose. It includes a dark security dashboard, file picker, URL scanner, scan history, result summaries, engine verdicts, and server connection settings.

### Build the Android app

1. Open this repository in Android Studio (Ladybug or newer).
2. Allow Gradle to sync and install the Android SDK platform 35 if prompted.
3. Select the `app` run configuration and run it on an Android 8.0+ device or emulator.
4. The emulator defaults to `http://10.0.2.2:3000`, which reaches the Node server running on your development computer.
5. For a physical phone, start the Node server on your computer, ensure both devices are on the same Wi-Fi, and set the server URL in **Settings** to your computer's LAN address, for example `http://192.168.1.10:3000`.

To create an APK in Android Studio, choose **Build → Build Bundle(s) / APK(s) → Build APK(s)**. The debug APK is normally written to `app/build/outputs/apk/debug/app-debug.apk`.

## Web dashboard and server

The web dashboard remains available. It uses the Node.js server as a secure proxy so the VirusTotal API key is never embedded in the browser or Android app.

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Copy `.env.example` to `.env`.
4. Set `VT_API_KEY=your_real_api_key` in `.env`.
5. Run `npm start` and visit [http://localhost:3000](http://localhost:3000).

Never commit `.env` or put your VirusTotal API key in client code.

## Features

- Responsive dark web dashboard and native Android UI.
- File uploads up to 32 MB and HTTP/HTTPS URL submission.
- VirusTotal analysis polling, detection totals, and individual engine verdicts.
- Browser and Android scan history stored locally on the device.
- Server-side API key handling, submission consent notices, and API request pacing.

## Important limitations and privacy

VirusBytes is an **on-demand scanning tool, not a resident antivirus**. It does not continuously monitor your device, block file execution, quarantine files, or remove malware. Keep a reputable endpoint-protection product enabled.

A zero-detection result does not prove an item is safe. Engine coverage and verdicts vary.

Files and URLs submitted to the public VirusTotal service may be shared with VirusTotal's security community and security partners. Never submit confidential, personal, proprietary, or otherwise sensitive material. The Android app uploads selected files to the VirusBytes server, which forwards them to VirusTotal.

The public VirusTotal API has strict quotas. The server serializes upstream requests and spaces them at least 15 seconds apart per server process. Your account plan and current VirusTotal terms apply. Multiple server instances require a shared distributed rate limiter.

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Server and API-key configuration status |
| POST | `/api/scan/file` | Submit a multipart file field named `file` |
| POST | `/api/scan/url` | Submit JSON containing a `url` field |
| GET | `/api/analyses/:id` | Retrieve an analysis result |

## Technology

- Android: Kotlin, Jetpack Compose, Material 3, Android document picker.
- Server: Node.js, Express, Multer, Helmet, express-rate-limit.
- Web: vanilla HTML, CSS, and JavaScript.

## License

MIT
