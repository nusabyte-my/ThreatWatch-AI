# ThreatWatch AI Executive Summary

## What It Is

ThreatWatch AI is a threat-operations platform that helps teams identify, explain, and respond to phishing, scam, and suspicious communications across email, chat, SMS, and URLs.

## Why It Matters

Most scam-detection tools stop at a binary flag. ThreatWatch AI is designed to go further:
- explain why a message is risky
- show evidence and indicators
- recommend next action
- support analyst workflow and executive reporting

## What The Platform Delivers

- real-time message and URL assessment
- clear verdicts: `safe`, `suspicious`, `scam`
- business-ready incident summaries
- investigation timeline and threat evidence
- analytics for posture, repeated patterns, and quality signals
- AI copilot assistance for summary, escalation, and reporting
- self-hosted AI support through Ollama/Gemma or hosted BYOK models

## Business Outcomes

- faster triage for suspicious communications
- improved analyst consistency
- better visibility for leadership
- explainable detection instead of opaque scoring
- a foundation for governance, workflow, and threat reporting

## Current State

The platform currently includes:
- executive dashboard
- investigation workspace
- analytics view
- rules management
- AI copilot
- branded incident print brief
- self-hosted Gemma support
- extension stubs for Gmail, Thunderbird, and Outlook Web

## Deployment Model

Local runtime is containerized and exposed through:
- UI: `http://localhost:5080`
- API: `http://localhost:5080/api/v1/...`

## Recommended Next Step

Move from buildout to validation:
- run full browser QA
- validate end-to-end operator flow
- tune final layout and interactions
- prepare packaging and deployment workflow for production use
