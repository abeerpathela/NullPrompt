/**
 * NullPrompt Core Detection & Sanitization Engine
 */
(function() {
    'use strict';

    // Store current findings
    let currentFindings = [];
    let lastShownFindingsHash = '';
    let notificationTimeout = null;

    // Helper function to escape HTML to prevent XSS
    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return String(unsafe);
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Entropy calculation to detect random strings
    function calculateEntropy(str) {
        const len = str.length;
        if (len === 0) return 0;
        const freq = {};
        for (let i = 0; i < len; i++) {
            freq[str[i]] = (freq[str[i]] || 0) + 1;
        }
        let entropy = 0;
        for (const char in freq) {
            const p = freq[char] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    // Character diversity check
    function hasCharacterDiversity(str) {
        const hasLower = /[a-z]/.test(str);
        const hasUpper = /[A-Z]/.test(str);
        const hasDigit = /[0-9]/.test(str);
        const hasSpecial = /[^a-zA-Z0-9]/.test(str);
        return [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length >= 2;
    }

    // Luhn algorithm for credit card validation
    function luhnCheck(cardNumber) {
        const digits = cardNumber.replace(/\D/g, '');
        if (digits.length < 13 || digits.length > 19) return false;
        
        let sum = 0;
        let isEven = false;
        for (let i = digits.length - 1; i >= 0; i--) {
            let digit = parseInt(digits[i], 10);
            if (isEven) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
            isEven = !isEven;
        }
        return sum % 10 === 0;
    }

    // Generate a unique hash for findings
    function getFindingsHash(findings) {
        return findings.map(f => `${f.id}-${f.value}`).join('|');
    }

    // Sensitive patterns configuration
    const SensitivePatterns = [
        // ======================================
        // CRITICAL SEVERITY
        // ======================================
        
        {
            id: 'private_key_rsa',
            name: 'RSA Private Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'Cryptographic Keys',
            regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----/gi
        },
        {
            id: 'private_key_ec',
            name: 'EC Private Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'Cryptographic Keys',
            regex: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----/gi
        },
        {
            id: 'private_key_openssh',
            name: 'OpenSSH Private Key',
            severity: 'Critical',
            confidence: 0.95,
            category: 'Cryptographic Keys',
            regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/gi
        },
        {
            id: 'openai_api_key',
            name: 'OpenAI API Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'API Keys',
            regex: /\bsk-[A-Za-z0-9]{20,}\b/gi
        },
        {
            id: 'openai_test_key',
            name: 'OpenAI Test API Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'API Keys',
            regex: /\bsk_test_[A-Za-z0-9]{24,}\b/gi
        },
        {
            id: 'stripe_secret_key',
            name: 'Stripe Secret Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'API Keys',
            regex: /\bsk_live_[A-Za-z0-9]{24,}\b/gi
        },
        {
            id: 'stripe_test_key',
            name: 'Stripe Test Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'API Keys',
            regex: /\bsk_test_[A-Za-z0-9]{24,}\b/gi
        },
        {
            id: 'aws_access_key',
            name: 'AWS Access Key',
            severity: 'Critical',
            confidence: 0.95,
            category: 'Cloud Credentials',
            regex: /\bAKIA[0-9A-Z]{16}\b/gi
        },
        {
            id: 'aws_access_key_env',
            name: 'AWS Access Key (Environment Variable)',
            severity: 'Critical',
            confidence: 0.95,
            category: 'Cloud Credentials',
            regex: /\bAWS_ACCESS_KEY_ID\s*[:=]\s*([A-Z0-9]{20})\b/gi,
            extractGroup: 1
        },
        {
            id: 'aws_secret_key_env',
            name: 'AWS Secret Key (Environment Variable)',
            severity: 'Critical',
            confidence: 0.9,
            category: 'Cloud Credentials',
            regex: /\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*([A-Za-z0-9/+=]{40,})\b/gi,
            extractGroup: 1
        },

        // ======================================
        // HIGH SEVERITY
        // ======================================
        {
            id: 'github_pat',
            name: 'GitHub Personal Access Token',
            severity: 'High',
            confidence: 0.95,
            category: 'API Keys',
            regex: /\bghp_[A-Za-z0-9]{36,}\b/gi
        },
        {
            id: 'google_api_key',
            name: 'Google API Key',
            severity: 'High',
            confidence: 0.95,
            category: 'API Keys',
            regex: /\bAIza[0-9A-Za-z\-_]{35}\b/gi
        },
        {
            id: 'slack_token',
            name: 'Slack Token',
            severity: 'High',
            confidence: 0.9,
            category: 'API Keys',
            regex: /\bxox[bapr]-[0-9]{12,}-[0-9]{12,}-[0-9a-zA-Z]{24,}\b/gi
        },
        {
            id: 'jwt_token',
            name: 'JWT Token',
            severity: 'High',
            confidence: 0.9,
            category: 'Authentication',
            regex: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/gi
        },
        {
            id: 'bearer_token',
            name: 'Bearer Token',
            severity: 'High',
            confidence: 0.85,
            category: 'Authentication',
            regex: /\b(?:Authorization|Bearer)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi,
            extractGroup: 1
        },
        {
            id: 'postgresql_conn_str',
            name: 'PostgreSQL Connection String',
            severity: 'High',
            confidence: 0.95,
            category: 'Database',
            regex: /\bpostgresql?:\/\/[^\s"'<>{}|\\^`\[\]]+/gi
        },
        {
            id: 'mongodb_uri',
            name: 'MongoDB URI',
            severity: 'High',
            confidence: 0.95,
            category: 'Database',
            regex: /\bmongodb(?:\+srv)?:\/\/[^\s"'<>{}|\\^`\[\]]+/gi
        },
        {
            id: 'redis_url',
            name: 'Redis URL',
            severity: 'High',
            confidence: 0.9,
            category: 'Database',
            regex: /\bredis(?:s)?:\/\/[^\s"'<>{}|\\^`\[\]]+/gi
        },
        {
            id: 'credit_card',
            name: 'Credit/Debit Card Number',
            severity: 'High',
            confidence: 0.9,
            category: 'Financial',
            regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
            validator: luhnCheck
        },

        // ======================================
        // MEDIUM SEVERITY
        // ======================================
        
        {
            id: 'context_aware_secret',
            name: 'Context-Aware Secret',
            severity: 'High',
            confidence: 0.85,
            category: 'Secrets',
            regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|client[_-]?secret|jwt[_-]?secret|auth[_-]?token|private[_-]?key)\s*[:=]\s*['"]?([^\s"'`<>]{6,})['"]?/gi,
            extractGroup: 1
        },

        {
            id: 'env_var_secret',
            name: 'Environment Variable Secret',
            severity: 'High',
            confidence: 0.8,
            category: 'Secrets',
            regex: /\b(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|JWT_SECRET|PASSWORD|DB_PASSWORD)\s*[:=]\s*['"]?([^\s"'`<>]{6,})['"]?/gi,
            extractGroup: 1
        },

        {
            id: 'email_address',
            name: 'Email Address',
            severity: 'Medium',
            confidence: 0.9,
            category: 'Personal',
            regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/gi,
            validator: (email) => !email.includes('@example.com') && !email.includes('@test.')
        },
        {
            id: 'phone_number',
            name: 'Phone Number',
            severity: 'Medium',
            confidence: 0.75,
            category: 'Personal',
            regex: /\b(?:\+1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b/g
        },
        {
            id: 'crypto_btc',
            name: 'Bitcoin Address',
            severity: 'Medium',
            confidence: 0.85,
            category: 'Financial',
            regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/gi
        },
        {
            id: 'crypto_eth',
            name: 'Ethereum Address',
            severity: 'Medium',
            confidence: 0.9,
            category: 'Financial',
            regex: /\b0x[a-fA-F0-9]{40}\b/gi
        },

        // ======================================
        // LOW SEVERITY
        // ======================================
        {
            id: 'ipv4_address',
            name: 'IPv4 Address',
            severity: 'Low',
            confidence: 0.9,
            category: 'Network',
            regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
        },
        {
            id: 'ipv6_address',
            name: 'IPv6 Address',
            severity: 'Low',
            confidence: 0.85,
            category: 'Network',
            regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/gi
        },
        {
            id: 'mac_address',
            name: 'MAC Address',
            severity: 'Low',
            confidence: 0.9,
            category: 'Network',
            regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/gi
        },

        // ======================================
        // GENERIC SECRETS (fallback)
        // ======================================
        {
            id: 'generic_secret',
            name: 'Generic Secret (long random string)',
            severity: 'Medium',
            confidence: 0.65,
            category: 'Secrets',
            regex: /\b[A-Za-z0-9_\-]{16,}\b/g,
            validator: (str) => {
                if (/^[0-9]+$/.test(str)) return false;
                if (/^[a-z]+$/.test(str)) return false;
                if (/^[A-Z]+$/.test(str)) return false;
                const entropy = calculateEntropy(str);
                return entropy > 3.5 && hasCharacterDiversity(str);
            }
        }
    ];

    let patternCounter = 1;

    // ==================== SCAN & SANITIZE ====================
    function scanText(text) {
        let findings = [];
        let seenValues = new Set();

        for (const pattern of SensitivePatterns) {
            const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
            let match;
            while ((match = regex.exec(text)) !== null) {
                const matchValue = pattern.extractGroup ? match[pattern.extractGroup] : match[0];
                const matchedText = match[0];

                if (seenValues.has(matchValue)) {
                    continue;
                }

                // Apply validator if present
                if (pattern.validator) {
                    if (!pattern.validator(matchValue)) {
                        continue;
                    }
                }

                findings.push({
                    id: pattern.id,
                    name: pattern.name,
                    severity: pattern.severity,
                    confidence: pattern.confidence,
                    category: pattern.category,
                    value: matchValue,
                    fullMatch: matchedText,
                    index: match.index
                });
                seenValues.add(matchValue);
            }
        }

        return findings;
    }

    function sanitizeText(text, findings) {
        let sanitized = text;
        
        findings.sort((a, b) => b.index - a.index);
        
        for (const finding of findings) {
            const placeholder = `[NULL_${finding.id.toUpperCase()}_${patternCounter++}]`;
            sanitized = sanitized.substring(0, finding.index) + 
                       sanitized.substring(finding.index).replace(finding.fullMatch, placeholder);
        }
        
        return sanitized;
    }

    // ==================== NOTIFICATION ====================
    function showNotification(findings) {
        // Check if we've already shown this exact set of findings recently
        const findingsHash = getFindingsHash(findings);
        if (findingsHash === lastShownFindingsHash) {
            return;
        }
        lastShownFindingsHash = findingsHash;

        // Create unique categories
        const categories = [...new Set(findings.map(f => f.category || f.name))];
        
        // Determine risk level
        const riskLevel = findings.some(f => f.severity === 'Critical') ? 'Critical' 
                        : findings.some(f => f.severity === 'High') ? 'High' 
                        : findings.some(f => f.severity === 'Medium') ? 'Medium' 
                        : 'Low';

        // Create notification element
        const notification = document.createElement('div');
        notification.id = 'nullprompt-notification';
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            width: 400px;
            max-width: calc(100vw - 40px);
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 12px;
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.3);
            z-index: 2147483647;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: #e2e8f0;
            overflow: hidden;
        `;

        // Add animation styles if not already added
        if (!document.getElementById('nullprompt-animation-styles')) {
            const style = document.createElement('style');
            style.id = 'nullprompt-animation-styles';
            style.textContent = `
                @keyframes nullprompt-slidein {
                    from { transform: translateX(420px); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes nullprompt-slideout {
                    from { transform: translateX(0); opacity: 1; }
                    to { transform: translateX(420px); opacity: 0; }
                }
            `;
            document.head.appendChild(style);
        }

        // Apply animation
        notification.style.animation = 'nullprompt-slidein 0.3s ease-out';

        notification.innerHTML = `
            <div style="padding: 16px;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
                    <div style="width: 40px; height: 40px; background: #fef2f2; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px;">⚠️</div>
                    <div>
                        <div style="font-weight: 700; font-size: 16px; color: #ffffff;">Sensitive Information Detected</div>
                        <div style="font-size: 13px; color: #94a3b8;">${findings.length} sensitive item${findings.length !== 1 ? 's' : ''} found.</div>
                    </div>
                    <button id="np-close-notif" style="margin-left: auto; background: transparent; border: 0; color: #64748b; font-size: 20px; cursor: pointer; padding: 4px; line-height: 1;">×</button>
                </div>
                
                <div style="margin-bottom: 12px;">
                    <div style="font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 6px;">Categories:</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                        ${categories.map(cat => `<span style="background: #1e293b; padding: 4px 10px; border-radius: 999px; font-size: 11px;">• ${escapeHtml(cat)}</span>`).join('')}
                    </div>
                </div>
                
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;">
                    <span style="font-size: 12px; font-weight: 600; color: #94a3b8;">Risk Level:</span>
                    <span style="background: ${riskLevel === 'Critical' ? '#fef2f2' : riskLevel === 'High' ? '#fff7ed' : riskLevel === 'Medium' ? '#fefce8' : '#f0fdf4'}; color: ${riskLevel === 'Critical' ? '#991b1b' : riskLevel === 'High' ? '#9a3412' : riskLevel === 'Medium' ? '#713f12' : '#166534'}; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700;">${escapeHtml(riskLevel)}</span>
                </div>
                
                <div style="background: #1e293b; padding: 12px; border-radius: 8px; font-size: 12px; color: #94a3b8; line-height: 1.5;">
                    Please review or redact the detected information before sending.
                </div>
            </div>
        `;

        // Remove any existing notification
        const existingNotif = document.getElementById('nullprompt-notification');
        if (existingNotif) {
            existingNotif.remove();
        }

        document.body.appendChild(notification);

        // Close button
        const closeBtn = notification.querySelector('#np-close-notif');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                notification.style.animation = 'nullprompt-slideout 0.3s ease-in forwards';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.remove();
                    }
                }, 300);
            });
        }

        // Auto-remove after 10 seconds
        clearTimeout(notificationTimeout);
        notificationTimeout = setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'nullprompt-slideout 0.3s ease-in forwards';
                setTimeout(() => notification.remove(), 300);
            }
        }, 10000);
    }

    // ==================== DOM INTEGRATION ====================
    function monitorInputFields() {
        const inputTypes = ['textarea', 'input[type="text"]', 'input[type="email"]', 'input[type="password"]', 'div[contenteditable="true"]'];
        
        const checkAndSanitize = (element) => {
            const text = element.value || element.innerText || element.textContent;
            currentFindings = scanText(text);
            if (currentFindings.length > 0) {
                // Show notification only once per set of findings
                showNotification(currentFindings);
            }
        };
        
        document.querySelectorAll(inputTypes.join(',')).forEach(el => {
            el.addEventListener('blur', () => checkAndSanitize(el));
            el.addEventListener('input', () => {
                // Debounce to avoid too many scans
                clearTimeout(el._npDebounce);
                el._npDebounce = setTimeout(() => checkAndSanitize(el), 300);
            });
        });
    }

    // ==================== NETWORK MONITORING ====================
    function monitorNetworkRequests() {
        const originalFetch = window.fetch;
        window.fetch = async function(...args) {
            const [url, options] = args;
            
            if (options && options.body) {
                let body = options.body;
                if (typeof body === 'string') {
                    const findings = scanText(body);
                    if (findings.length > 0) {
                        currentFindings = findings;
                        showNotification(findings);
                        options.body = sanitizeText(body, findings);
                    }
                }
            }
            
            return originalFetch.apply(this, args);
        };
        
        const originalXHROpen = XMLHttpRequest.prototype.open;
        const originalXHRSend = XMLHttpRequest.prototype.send;
        
        XMLHttpRequest.prototype.open = function(...args) {
            this._npMethod = args[0];
            this._npUrl = args[1];
            return originalXHROpen.apply(this, args);
        };
        
        XMLHttpRequest.prototype.send = function(body) {
            if (body && typeof body === 'string') {
                const findings = scanText(body);
                if (findings.length > 0) {
                    currentFindings = findings;
                    showNotification(findings);
                    body = sanitizeText(body, findings);
                }
            }
            return originalXHRSend.call(this, body);
        };
    }

    // ==================== MESSAGE HANDLING ====================
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'getFindings') {
            sendResponse({ findings: currentFindings });
        }
        return true; // Keep message channel open for async response
    });

    // ==================== INITIALIZE ====================
    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                monitorInputFields();
                monitorNetworkRequests();
            });
        } else {
            monitorInputFields();
            monitorNetworkRequests();
        }
        
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.addedNodes.length) {
                    monitorInputFields();
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        
        console.log('NullPrompt initialized and monitoring');
    }

    init();

    // Expose to window for debugging
    window.NullPrompt = {
        scanText,
        sanitizeText,
        SensitivePatterns,
        currentFindings,
        showNotification
    };
})();
