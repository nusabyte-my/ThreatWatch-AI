# ThreatWatch AI Gmail Extension Stub

Minimal Chrome Extension (Manifest V3) for scanning open Gmail messages with the existing ThreatWatch API.

## What it does

- watches Gmail for the currently open message
- extracts subject + visible message body
- sends the content to `POST /api/v1/scan`
- injects a small verdict badge under the Gmail subject line

## Local test

1. Start the ThreatWatch backend on `http://localhost:8100`
2. Open `chrome://extensions`
3. Enable `Developer mode`
4. Click `Load unpacked`
5. Select this `chrome-extension/` folder
6. Open Gmail and click an email thread

## API target

The extension defaults to `http://localhost:8100`.

To change it:

1. Open the extension details page in Chrome
2. Open `Extension options`
3. Set the ThreatWatch API URL
4. Choose `Standard scan` or `AI scan`
5. Save

## Notes

- This is a stub for demo and hackathon use, not a hardened browser extension.
- Gmail DOM selectors can drift over time, so the extractor may need adjustment if Gmail changes its layout.
- The extension can use either `/api/v1/scan` or `/api/v1/scan/ai`.
- AI mode can surface the agent explanation directly in the Gmail badge.
