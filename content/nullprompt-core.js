(function() {
    console.log(">>> [NullPrompt] UNIFIED CORE BOOTED");

    const NullEngine = {
        activeSensitives: new Map(),
        counter: 0,
        isInternalMutation: false,
        lastActionTime: 0,
        patterns: {
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
        },
        SECRET_PATTERNS: {
            openai: /\bsk-[A-Za-z0-9]{20,}\b/g,
            openai_test: /\bsk_test_[A-Za-z0-9]{20,}\b/g,
            github: /\bghp_[A-Za-z0-9]{30,}\b/g,
            google: /\bAIza[0-9A-Za-z-_]{30,}\b/g,
            aws: /\bAKIA[0-9A-Z]{16}\b/g,
            slack: /\bxoxb-[0-9A-Za-z-]{20,}\b/g,
            generic: /\b[A-Za-z0-9]{32,}\b/g
        },
        getOrCreatePlaceholder: function(value, type) {
            if (NullEngine.activeSensitives.has(value)) {
                console.log(">>> [NullPrompt] ATOMIC: Reusing placeholder for existing match:", value);
                return NullEngine.activeSensitives.get(value);
            }
            NullEngine.counter++;
            const placeholder = `[NULL_${type.toUpperCase()}_${NullEngine.counter}]`;
            NullEngine.activeSensitives.set(value, placeholder);
            console.log(">>> [NullPrompt] FULL SECRET MATCH:", value);
            console.log(">>> [NullPrompt] SECRET PLACEHOLDER:", placeholder);
            return placeholder;
        },
        scanTextForSensitives: function(text) {
            if (text.includes('[NULL_') && !text.includes('@')) {
                return;
            }
            for (const [type, regex] of Object.entries(NullEngine.patterns)) {
                const matches = text.matchAll(regex);
                for (const match of matches) {
                    NullEngine.getOrCreatePlaceholder(match[0], type);
                }
            }
            for (const [type, regex] of Object.entries(NullEngine.SECRET_PATTERNS)) {
                const matches = text.matchAll(regex);
                for (const match of matches) {
                    NullEngine.getOrCreatePlaceholder(match[0], "SECRET");
                }
            }
        },
        processText: function(text) {
            if (text.includes('[NULL_') && !text.includes('@')) {
                return text;
            }
            let sanitized = text;
            for (const [type, regex] of Object.entries(NullEngine.patterns)) {
                sanitized = sanitized.replace(regex, (match) => {
                    return NullEngine.getOrCreatePlaceholder(match, type);
                });
            }
            for (const [type, regex] of Object.entries(NullEngine.SECRET_PATTERNS)) {
                sanitized = sanitized.replace(regex, (match) => {
                    return NullEngine.getOrCreatePlaceholder(match, "SECRET");
                });
            }
            return sanitized;
        },
        redactString: function(text) {
            return NullEngine.processText(text);
        }
    };

    let debounceTimer = null;

    function handleInput(text) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            NullEngine.scanTextForSensitives(text);
        }, 300);
    }

    function attachInputListener(element) {
        if (element.__nullprompt_active__) return;
        element.__nullprompt_active__ = true;

        element.addEventListener('input', (e) => {
            if (NullEngine.isInternalMutation) return;
            if (Date.now() - NullEngine.lastActionTime < 50) return;
            const text = e.target.value || e.target.innerText || e.target.textContent || '';
            handleInput(text);
        }, true);

        element.addEventListener('paste', (e) => {
            if (NullEngine.isInternalMutation) return;
            if (Date.now() - NullEngine.lastActionTime < 50) return;
            e.preventDefault();
            e.stopImmediatePropagation();
            const rawText = (e.clipboardData || window.clipboardData).getData('text');
            const sanitized = NullEngine.processText(rawText);
            console.log(">>> [NullPrompt] PASTE INTERCEPTED:", rawText, "->", sanitized);
            console.log(">>> [NullPrompt] ATOMIC TRANSACTION: Intercepted and replaced PASTE");
            
            NullEngine.isInternalMutation = true;
            NullEngine.lastActionTime = Date.now();
            document.execCommand('insertText', false, sanitized);
            setTimeout(() => { NullEngine.isInternalMutation = false; }, 50);
        }, true);

        element.addEventListener('drop', (e) => {
            if (NullEngine.isInternalMutation) return;
            if (Date.now() - NullEngine.lastActionTime < 50) return;
            e.preventDefault();
            e.stopImmediatePropagation();
            const rawText = (e.dataTransfer || window.dataTransfer).getData('text');
            const sanitized = NullEngine.processText(rawText);
            console.log(">>> [NullPrompt] DROP INTERCEPTED:", rawText, "->", sanitized);
            console.log(">>> [NullPrompt] ATOMIC TRANSACTION: Intercepted and replaced DROP");
            
            NullEngine.isInternalMutation = true;
            NullEngine.lastActionTime = Date.now();
            document.execCommand('insertText', false, sanitized);
            setTimeout(() => { NullEngine.isInternalMutation = false; }, 50);
        }, true);

        element.addEventListener('compositionend', (e) => {
            if (NullEngine.isInternalMutation) return;
            if (Date.now() - NullEngine.lastActionTime < 50) return;
            const text = e.target.value || e.target.innerText || e.target.textContent || '';
            handleInput(text);
        }, true);

        element.addEventListener('blur', (e) => {
            if (NullEngine.isInternalMutation) return;
            if (Date.now() - NullEngine.lastActionTime < 50) return;
            const text = e.target.value || e.target.innerText || e.target.textContent || '';
            handleInput(text);
        }, true);

        console.log(">>> [NullPrompt] Attached full-spectrum input listener to", element);
    }

    const observer = new MutationObserver((mutations) => {
        if (NullEngine.isInternalMutation) return;
        if (Date.now() - NullEngine.lastActionTime < 50) return;
        
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;

                if (node.id === 'prompt-textarea') {
                    attachInputListener(node);
                }
                if (node.getAttribute && node.getAttribute('contenteditable') === 'true') {
                    attachInputListener(node);
                }

                const textareas = node.querySelectorAll?.('#prompt-textarea');
                textareas?.forEach(el => attachInputListener(el));

                const editables = node.querySelectorAll?.('[contenteditable="true"]');
                editables?.forEach(el => attachInputListener(el));
            }
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const resource = args[0];
        const config = args[1];
        const url = (typeof resource === 'string') ? resource : resource.url;
        const method = (config?.method || resource?.method || 'GET').toUpperCase();

        const isTarget = (url.includes('chatgpt.com') || url.includes('openai.com')) && method === 'POST';

        if (isTarget && NullEngine.activeSensitives.size > 0) {
            try {
                let bodyText = "";
                if (typeof config?.body === 'string') {
                    bodyText = config.body;
                } else if (resource instanceof Request) {
                    const clone = resource.clone();
                    bodyText = await clone.text();
                }

                if (bodyText) {
                    let sanitizedBody = bodyText;
                    for (const [actualValue, placeholder] of NullEngine.activeSensitives.entries()) {
                        if (sanitizedBody.includes(actualValue)) {
                            console.log(">>> [NullPrompt] Network Match: Redacting", actualValue, "in outgoing stream to", url);
                            sanitizedBody = sanitizedBody.split(actualValue).join(placeholder);
                        }
                    }

                    if (sanitizedBody !== bodyText) {
                        console.log(">>> [NullPrompt] Sanitized outgoing request");
                        if (typeof config?.body === 'string') {
                            config.body = sanitizedBody;
                        } else if (resource instanceof Request) {
                            const newRequest = new Request(resource, { ...config, body: sanitizedBody });
                            return originalFetch(newRequest);
                        }
                    }
                }
            } catch (e) {
                console.error(">>> [NullPrompt] Network interception error, passing original:", e);
            }
        }

        return originalFetch.apply(this, args);
    };

    console.log(">>> [NullPrompt] INTERCEPTOR ACTIVE ON FETCH");
    console.log(">>> [NullPrompt] DOM OBSERVER ACTIVE");
})();
