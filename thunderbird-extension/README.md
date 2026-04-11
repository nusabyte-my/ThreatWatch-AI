# ThreatWatch AI Thunderbird Add-on Stub

Minimal Thunderbird MailExtension that scans the currently displayed email with the existing ThreatWatch API and injects a verdict banner into the message display.

## What it does

- listens for `onMessageDisplayed`
- reads the current message through Thunderbird's `messages` and `messageDisplay` APIs
- extracts sender, subject, text body, and first URL
- sends the payload to `POST /api/v1/scan`
- injects a banner into the displayed message document

## Files

- `manifest.json` — MailExtension manifest
- `background.js` — message event handling, message extraction, API call
- `message_display_script.js` — in-message verdict banner renderer

## Test

1. Make sure the ThreatWatch backend is reachable at `https://threatwatch-ai.nusabyte.cloud`
2. Zip the contents of `thunderbird-extension/` into an `.xpi` archive, or load it temporarily in Thunderbird dev tools
3. In Thunderbird, open `Tools` -> `Add-ons and Themes`
4. Install the add-on temporarily for testing
5. Open an email message
6. The add-on should inject a ThreatWatch verdict banner at the top of the message

## Notes

- This uses Thunderbird APIs instead of DOM scraping, so it should be more stable than generic webmail extensions.
- The add-on defaults to `https://threatwatch-ai.nusabyte.cloud`.
- To change it, open the add-on preferences/options page and set the ThreatWatch API URL there.
- You can also choose between `Standard scan` and `AI scan`.
- AI mode can surface the agent explanation directly in the Thunderbird banner.
- This is a stub for demo/prototyping, not a reviewed production add-on.
