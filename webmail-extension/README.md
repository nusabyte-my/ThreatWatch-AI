# ThreatWatch AI Webmail Extension

Combined browser extension for:

- Gmail on `mail.google.com`
- Outlook Web on `outlook.office.com`
- Outlook Live on `outlook.live.com`

## What it does

- detects the currently open webmail message
- sends the message content to the ThreatWatch API
- shows an inline verdict badge in Gmail or Outlook
- stores the latest result for the popup view

## Local test

1. Start the ThreatWatch backend on `http://127.0.0.1:8100`
2. Open `chrome://extensions`
3. Enable `Developer mode`
4. Click `Load unpacked`
5. Select the `webmail-extension/` folder
6. Open Gmail or Outlook Web and click an email
7. Open the extension options page if you want to change API URL or switch to AI mode

## Notes

- Both Gmail and Outlook content scripts use the same background service worker for API requests.
- The popup reflects the latest scan result from either webmail surface.
- For local development, prefer `http://127.0.0.1:8100` over `http://localhost:8100`.
