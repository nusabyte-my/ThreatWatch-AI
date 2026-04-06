# ThreatWatch AI Outlook Web Extension Stub

Minimal browser extension for Outlook on the web that scans the open message with the existing ThreatWatch API and injects a verdict badge into the reading pane.

## What it does

- watches Outlook Web / Outlook Live for the currently open message
- extracts the visible subject and message body
- sends the content to either `POST /api/v1/scan` or `POST /api/v1/scan/ai`
- injects a small verdict badge in the reading view

## Local test

1. Start the ThreatWatch backend on `http://localhost:8100`
2. Open `chrome://extensions`
3. Enable `Developer mode`
4. Click `Load unpacked`
5. Select the `outlook-web-extension/` folder
6. Open Outlook Web and click an email
7. Open the extension options page if you want to change API URL or switch to AI mode

## Notes

- This is a DOM-based stub, so selectors may need tuning if Outlook Web changes its UI.
- The extension supports both `outlook.office.com` and `outlook.live.com`.
- AI mode can surface the agent explanation directly in the Outlook badge.
- This is a demo/prototype scaffold, not a production-hardened extension.
