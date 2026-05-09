# NullPrompt

NullPrompt is a Zero-Trust Privacy Proxy for AI that intercepts sensitive data before it leaves the browser, redacts it locally, and safely restores context in AI responses — all without external servers, tracking, or cloud processing.

Built as a Manifest V3 Chrome Extension, NullPrompt uses in-browser request interception, fetch/XHR monkey-patching, and local NLP-based detection to identify sensitive information such as emails, API keys, credentials, and personal data before prompts are sent to AI platforms like ChatGPT, Claude, and Gemini.

## Core Features

* Universal AI prompt interception
* Local-only processing (Zero-Trust architecture)
* Fetch + XMLHttpRequest interception
* Sensitive data detection and redaction
* Placeholder synthesis and secure reconstruction
* Manifest V3 compliant
* No telemetry, no logins, no cloud storage
* Cross-site compatibility with modern AI platforms

## Tech Stack

* Chrome Extension Manifest V3
* JavaScript
* WebAssembly (planned)
* WinkNLP / Compromise.js (planned)
* Shadow DOM UI overlays
* chrome.storage.local

## Current Status

Phase 1 Completed:

* Universal injector system
* Main World script injection
* Fetch interception
* XHR interception
* Prompt detection pipeline

Upcoming:

* Redaction Engine
* Consent UI
* Streaming Response Reconstruction
* Advanced PII Detection
* SSE Handling & Edge Cases

## Vision

NullPrompt aims to become a browser-native privacy firewall for AI interactions — giving users complete control over what data is exposed to AI systems while maintaining seamless usability.
