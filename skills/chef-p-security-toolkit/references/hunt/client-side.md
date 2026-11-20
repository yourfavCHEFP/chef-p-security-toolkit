# Client-side and mobile
Look for: DOM XSS sinks (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`), postMessage handlers without origin checks, tokens in localStorage with XSS exposure, open redirects after login, prototype pollution in merge utilities, ReDoS on user input, secrets bundled in client code, deep-link/intent handling that trusts parameters, insecure WebView settings, missing certificate validation.
Kills false positives: sanitizer in front of the sink (verify it is the right context), CSP that actually blocks the vector, data that is not attacker-controlled.
