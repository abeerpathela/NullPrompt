/**
 * NullPrompt Core Detection & Sanitization Engine
 * Supported Platforms: ChatGPT, Claude
 */
(function() {
    'use strict';

    // ------------------ GLOBAL STATE ------------------
    let currentFindings = [];
    let lastScanText = '';
    let lastProcessedPromptHash = '';
    let notificationShownForHash = '';
    let successShownForHash = '';
    let lastFindingsForHash = new Map();

    // ------------------ NULLENGINE (PLACEHOLDER/REDACTION) ------------------
    const NullEngine = {
        activeSensitives: new Map(),
        reverseLookup: new Map(),
        counter: 0,
        isInternalMutation: false,
        lastActionTime: 0,

        getOrCreatePlaceholder: function(value, type) {
            if (NullEngine.activeSensitives.has(value)) {
                return NullEngine.activeSensitives.get(value);
            }
            NullEngine.counter++;
            const placeholder = `[NULL_${type.toUpperCase()}_${NullEngine.counter}]`;
            NullEngine.activeSensitives.set(value, placeholder);
            NullEngine.reverseLookup.set(placeholder, value);
            return placeholder;
        },

        processText: function(text) {
            if (text.includes('[NULL_')) {
                return text;
            }
            let sanitized = text;
            currentFindings.forEach(finding => {
                const placeholder = NullEngine.getOrCreatePlaceholder(
                    finding.value, 
                    finding.id
                );
                sanitized = sanitized.split(finding.value).join(placeholder);
            });
            return sanitized;
        },

        restoreText: function(text) {
            let restored = text;
            for (const [placeholder, value] of NullEngine.reverseLookup.entries()) {
                restored = restored.split(placeholder).join(value);
            }
            return restored;
        }
    };

    // ------------------ UTILITIES ------------------
    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return String(unsafe);
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

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

    function generatePromptHash(text) {
        let hash = 0;
        if (text.length === 0) return hash;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(36);
    }

    // ------------------ SENSITIVE PATTERNS ------------------
    const SensitivePatterns = [
        {
            id: 'private_key_rsa',
            name: 'RSA Private Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'Cryptographic Keys',
            regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----\s*[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----/gi
        },
        {
            id: 'private_key_ec',
            name: 'EC Private Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'Cryptographic Keys',
            regex: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----\s*[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----/gi
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
            id: 'stripe_secret_key',
            name: 'Stripe Secret Key',
            severity: 'Critical',
            confidence: 0.98,
            category: 'API Keys',
            regex: /\bsk_live_[A-Za-z0-9]{24,}\b/gi
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
            name: 'AWS Access Key',
            severity: 'Critical',
            confidence: 0.95,
            category: 'Cloud Credentials',
            regex: /\bAWS_ACCESS_KEY_ID\s*[:=]\s*([A-Z0-9]{20})\b/gi,
            extractGroup: 1
        },
        {
            id: 'aws_secret_key_env',
            name: 'AWS Secret Key',
            severity: 'Critical',
            confidence: 0.9,
            category: 'Cloud Credentials',
            regex: /\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*([A-Za-z0-9/+=]{40,})\b/gi,
            extractGroup: 1
        },
        {
            id: 'github_pat',
            name: 'GitHub PAT',
            severity: 'High',
            confidence: 0.95,
            category: 'API Keys',
            regex: /\bgh[psu]_[A-Za-z0-9]{35,}\b/gi
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
            id: 'jwt_token',
            name: 'JWT Token',
            severity: 'High',
            confidence: 0.9,
            category: 'Authentication',
            regex: /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/gi
        },
        {
            id: 'postgresql_conn_str',
            name: 'PostgreSQL URL',
            severity: 'High',
            confidence: 0.95,
            category: 'Database Credentials',
            regex: /\bpostgresql?:\/\/[^\s"'<>{}|\\^`\[\]]+/gi
        },
        {
            id: 'mongodb_uri',
            name: 'MongoDB URL',
            severity: 'High',
            confidence: 0.95,
            category: 'Database Credentials',
            regex: /\bmongodb(?:\+srv)?:\/\/[^\s"'<>{}|\\^`\[\]]+/gi
        },
        {
            id: 'redis_url',
            name: 'Redis URL',
            severity: 'High',
            confidence: 0.9,
            category: 'Database Credentials',
            regex: /\bredis(?:s)?:\/\/[^\s"'<>{}|\\^`\[\]]+/gi
        },
        {
            id: 'credit_card',
            name: 'Credit Card',
            severity: 'High',
            confidence: 0.9,
            category: 'Financial',
            regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
            validator: luhnCheck
        },
        {
            id: 'context_secret',
            name: 'Context-Aware Secret',
            severity: 'High',
            confidence: 0.85,
            category: 'Secrets',
            regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|client[_-]?secret|jwt[_-]?secret|auth[_-]?token|private[_-]?key)\s*[:=]\s*['"]?([^\s"'`<>]{6,})['"]?/gi,
            extractGroup: 1
        },
        {
            id: 'env_var_secret',
            name: 'Environment Variable',
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
            category: 'Emails',
            regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/gi,
            validator: (email) => !email.includes('@example.com') && !email.includes('@test.')
        },
        {
            id: 'phone_number',
            name: 'Phone Number',
            severity: 'Medium',
            confidence: 0.75,
            category: 'Phone Numbers',
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
        {
            id: 'ipv4_address',
            name: 'IPv4 Address',
            severity: 'Low',
            confidence: 0.9,
            category: 'Network',
            regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
        },
        {
            id: 'mac_address',
            name: 'MAC Address',
            severity: 'Low',
            confidence: 0.9,
            category: 'Network',
            regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/gi
        }
    ];

    // ------------------ SCAN & SUMMARY ------------------
    function scanText(text) {
        let findings = [];
        let seenValues = new Set();

        for (const pattern of SensitivePatterns) {
            const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
            let match;
            while ((match = regex.exec(text)) !== null) {
                const matchValue = pattern.extractGroup ? match[pattern.extractGroup] : match[0];
                const matchedText = match[0];

                if (seenValues.has(matchValue)) continue;
                if (pattern.validator && !pattern.validator(matchValue)) continue;

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

    function generateSummary(findings) {
        const summary = {};
        findings.forEach(f => {
            summary[f.category] = (summary[f.category] || 0) + 1;
        });
        return summary;
    }

    function getOverallRisk(findings) {
        if (findings.some(f => f.severity === 'Critical')) return 'Critical';
        if (findings.some(f => f.severity === 'High')) return 'High';
        if (findings.some(f => f.severity === 'Medium')) return 'Medium';
        return 'Low';
    }

    // ------------------ NOTIFICATION MANAGER ------------------
    const NotificationManager = (function() {
        let currentNotificationEl = null;
        let successNotificationTimeout = null;

        function removeNotification() {
            if (currentNotificationEl && currentNotificationEl.parentNode) {
                currentNotificationEl.style.animation = 'nullprompt-slideout 0.3s ease-in forwards';
                setTimeout(() => {
                    if (currentNotificationEl && currentNotificationEl.parentNode) {
                        currentNotificationEl.remove();
                    }
                    currentNotificationEl = null;
                }, 300);
            }
        }

        function createStyles() {
            if (document.getElementById('nullprompt-styles')) return;
            const styleEl = document.createElement('style');
            styleEl.id = 'nullprompt-styles';
            styleEl.textContent = `
                @keyframes nullprompt-slidein {
                    from { transform: translateX(420px); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes nullprompt-slideout {
                    from { transform: translateX(0); opacity: 1; }
                    to { transform: translateX(420px); opacity: 0; }
                }
            `;
            document.head.appendChild(styleEl);
        }

        function createWarningNotification(findings, summary, riskLevel) {
            removeNotification();
            clearTimeout(successNotificationTimeout);
            createStyles();

            currentNotificationEl = document.createElement('div');
            currentNotificationEl.id = 'nullprompt-warning-notification';
            currentNotificationEl.style.position = 'fixed';
            currentNotificationEl.style.top = '20px';
            currentNotificationEl.style.right = '20px';
            currentNotificationEl.style.width = '400px';
            currentNotificationEl.style.maxWidth = 'calc(100vw - 40px)';
            currentNotificationEl.style.background = '#0f172a';
            currentNotificationEl.style.border = '1px solid #1e293b';
            currentNotificationEl.style.borderRadius = '12px';
            currentNotificationEl.style.boxShadow = '0 20px 25px -5px rgba(0,0,0,0.3)';
            currentNotificationEl.style.zIndex = '2147483647';
            currentNotificationEl.style.fontFamily = 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
            currentNotificationEl.style.color = '#e2e8f0';
            currentNotificationEl.style.overflow = 'hidden';
            currentNotificationEl.style.animation = 'nullprompt-slidein 0.3s ease-out';

            const container = document.createElement('div');
            container.style.padding = '20px';

            const header = document.createElement('div');
            header.style.display = 'flex';
            header.style.alignItems = 'center';
            header.style.gap = '12px';
            header.style.marginBottom = '20px';

            const iconDiv = document.createElement('div');
            iconDiv.style.width = '48px';
            iconDiv.style.height = '48px';
            iconDiv.style.borderRadius = '12px';
            iconDiv.style.display = 'flex';
            iconDiv.style.alignItems = 'center';
            iconDiv.style.justifyContent = 'center';
            iconDiv.style.fontSize = '24px';
            if (riskLevel === 'Critical') iconDiv.style.background = '#fef2f2';
            else if (riskLevel === 'High') iconDiv.style.background = '#fff7ed';
            else if (riskLevel === 'Medium') iconDiv.style.background = '#fefce8';
            else iconDiv.style.background = '#f0fdf4';
            iconDiv.textContent = '⚠️';

            const titleDiv = document.createElement('div');
            const title = document.createElement('div');
            title.style.fontWeight = '700';
            title.style.fontSize = '18px';
            title.style.color = '#ffffff';
            title.textContent = 'Sensitive Information Detected';
            const count = document.createElement('div');
            count.style.fontSize = '14px';
            count.style.color = '#94a3b8';
            count.textContent = `Found ${findings.length} item${findings.length !== 1 ? 's' : ''}`;
            titleDiv.appendChild(title);
            titleDiv.appendChild(count);

            header.appendChild(iconDiv);
            header.appendChild(titleDiv);
            container.appendChild(header);

            const summaryLabel = document.createElement('div');
            summaryLabel.style.fontSize = '12px';
            summaryLabel.style.fontWeight = '600';
            summaryLabel.style.color = '#94a3b8';
            summaryLabel.style.textTransform = 'uppercase';
            summaryLabel.style.letterSpacing = '0.5px';
            summaryLabel.style.marginBottom = '10px';
            summaryLabel.textContent = 'Summary';

            const summaryBox = document.createElement('div');
            summaryBox.style.background = '#1e293b';
            summaryBox.style.borderRadius = '8px';
            summaryBox.style.padding = '16px';
            for (const [cat, num] of Object.entries(summary)) {
                const catEl = document.createElement('div');
                catEl.style.fontSize = '14px';
                catEl.style.marginBottom = '6px';
                catEl.textContent = `• ${escapeHtml(cat)} (${num})`;
                summaryBox.appendChild(catEl);
            }

            const summarySection = document.createElement('div');
            summarySection.style.marginBottom = '20px';
            summarySection.appendChild(summaryLabel);
            summarySection.appendChild(summaryBox);
            container.appendChild(summarySection);

            const riskSection = document.createElement('div');
            riskSection.style.display = 'flex';
            riskSection.style.alignItems = 'center';
            riskSection.style.gap = '10px';
            riskSection.style.marginBottom = '24px';

            const riskLabel = document.createElement('span');
            riskLabel.style.fontSize = '12px';
            riskLabel.style.fontWeight = '600';
            riskLabel.style.color = '#94a3b8';
            riskLabel.textContent = 'Overall Risk:';

            const riskBadge = document.createElement('span');
            riskBadge.style.padding = '6px 14px';
            riskBadge.style.borderRadius = '999px';
            riskBadge.style.fontSize = '12px';
            riskBadge.style.fontWeight = '700';
            if (riskLevel === 'Critical') {
                riskBadge.style.background = '#fef2f2';
                riskBadge.style.color = '#991b1b';
            } else if (riskLevel === 'High') {
                riskBadge.style.background = '#fff7ed';
                riskBadge.style.color = '#9a3412';
            } else if (riskLevel === 'Medium') {
                riskBadge.style.background = '#fefce8';
                riskBadge.style.color = '#713f12';
            } else {
                riskBadge.style.background = '#f0fdf4';
                riskBadge.style.color = '#166534';
            }
            riskBadge.textContent = escapeHtml(riskLevel);

            riskSection.appendChild(riskLabel);
            riskSection.appendChild(riskBadge);
            container.appendChild(riskSection);

            const buttonContainer = document.createElement('div');
            buttonContainer.style.display = 'grid';
            buttonContainer.style.gridTemplateColumns = 'repeat(3, 1fr)';
            buttonContainer.style.gap = '10px';

            const reviewBtn = document.createElement('button');
            reviewBtn.style.padding = '12px';
            reviewBtn.style.borderRadius = '8px';
            reviewBtn.style.border = '1px solid #334155';
            reviewBtn.style.background = '#1e293b';
            reviewBtn.style.color = '#e2e8f0';
            reviewBtn.style.fontSize = '14px';
            reviewBtn.style.fontWeight = '600';
            reviewBtn.style.cursor = 'pointer';
            reviewBtn.textContent = 'Review';

            const sendBtn = document.createElement('button');
            sendBtn.style.padding = '12px';
            sendBtn.style.borderRadius = '8px';
            sendBtn.style.border = '1px solid #f59e0b';
            sendBtn.style.background = '#fefce8';
            sendBtn.style.color = '#92400e';
            sendBtn.style.fontSize = '14px';
            sendBtn.style.fontWeight = '600';
            sendBtn.style.cursor = 'pointer';
            sendBtn.textContent = 'Send Anyway';

            const cancelBtn = document.createElement('button');
            cancelBtn.style.padding = '12px';
            cancelBtn.style.borderRadius = '8px';
            cancelBtn.style.border = 'none';
            cancelBtn.style.background = '#22c55e';
            cancelBtn.style.color = 'white';
            cancelBtn.style.fontSize = '14px';
            cancelBtn.style.fontWeight = '600';
            cancelBtn.style.cursor = 'pointer';
            cancelBtn.textContent = 'Cancel';

            reviewBtn.addEventListener('click', () => removeNotification());
            sendBtn.addEventListener('click', () => removeNotification());
            cancelBtn.addEventListener('click', () => removeNotification());

            buttonContainer.appendChild(reviewBtn);
            buttonContainer.appendChild(sendBtn);
            buttonContainer.appendChild(cancelBtn);
            container.appendChild(buttonContainer);

            currentNotificationEl.appendChild(container);
            document.body.appendChild(currentNotificationEl);
        }

        function createSuccessNotification(count) {
            removeNotification();
            clearTimeout(successNotificationTimeout);
            createStyles();

            currentNotificationEl = document.createElement('div');
            currentNotificationEl.id = 'nullprompt-success-notification';
            currentNotificationEl.style.position = 'fixed';
            currentNotificationEl.style.top = '20px';
            currentNotificationEl.style.right = '20px';
            currentNotificationEl.style.width = '400px';
            currentNotificationEl.style.maxWidth = 'calc(100vw - 40px)';
            currentNotificationEl.style.background = '#0f172a';
            currentNotificationEl.style.border = '1px solid #22c55e';
            currentNotificationEl.style.borderRadius = '12px';
            currentNotificationEl.style.boxShadow = '0 20px 25px -5px rgba(0,0,0,0.3)';
            currentNotificationEl.style.zIndex = '2147483647';
            currentNotificationEl.style.fontFamily = 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
            currentNotificationEl.style.color = '#e2e8f0';
            currentNotificationEl.style.overflow = 'hidden';
            currentNotificationEl.style.animation = 'nullprompt-slidein 0.3s ease-out';

            const container = document.createElement('div');
            container.style.padding = '20px';

            const header = document.createElement('div');
            header.style.display = 'flex';
            header.style.alignItems = 'center';
            header.style.gap = '12px';
            header.style.marginBottom = '16px';

            const iconDiv = document.createElement('div');
            iconDiv.style.width = '48px';
            iconDiv.style.height = '48px';
            iconDiv.style.borderRadius = '12px';
            iconDiv.style.display = 'flex';
            iconDiv.style.alignItems = 'center';
            iconDiv.style.justifyContent = 'center';
            iconDiv.style.fontSize = '24px';
            iconDiv.style.background = '#f0fdf4';
            iconDiv.textContent = '🛡️';

            const titleDiv = document.createElement('div');
            const title = document.createElement('div');
            title.style.fontWeight = '700';
            title.style.fontSize = '18px';
            title.style.color = '#ffffff';
            title.textContent = 'NullPrompt';
            titleDiv.appendChild(title);

            header.appendChild(iconDiv);
            header.appendChild(titleDiv);
            container.appendChild(header);

            const subtitle = document.createElement('div');
            subtitle.style.fontSize = '16px';
            subtitle.style.color = '#e2e8f0';
            subtitle.style.marginBottom = '16px';
            subtitle.textContent = 'Prompt protected successfully';
            container.appendChild(subtitle);

            const pointsContainer = document.createElement('div');
            pointsContainer.style.display = 'flex';
            pointsContainer.style.flexDirection = 'column';
            pointsContainer.style.gap = '8px';

            const point1 = document.createElement('div');
            point1.style.fontSize = '14px';
            point1.style.color = '#94a3b8';
            point1.textContent = `• ${count} sensitive items detected`;
            pointsContainer.appendChild(point1);

            const point2 = document.createElement('div');
            point2.style.fontSize = '14px';
            point2.style.color = '#94a3b8';
            point2.textContent = `• ${count} items replaced with secure placeholders`;
            pointsContainer.appendChild(point2);

            const point3 = document.createElement('div');
            point3.style.fontSize = '14px';
            point3.style.color = '#94a3b8';
            point3.textContent = '• Original values never left your browser';
            pointsContainer.appendChild(point3);

            container.appendChild(pointsContainer);

            currentNotificationEl.appendChild(container);
            document.body.appendChild(currentNotificationEl);

            successNotificationTimeout = setTimeout(() => {
                removeNotification();
            }, 4000);
        }

        function showWarning(findings) {
            if (findings.length === 0) {
                removeNotification();
                return;
            }
            const summary = generateSummary(findings);
            const riskLevel = getOverallRisk(findings);
            const promptHash = generatePromptHash(findings.map(f => f.value).join(''));
            
            if (notificationShownForHash === promptHash) {
                return;
            }
            
            notificationShownForHash = promptHash;
            createWarningNotification(findings, summary, riskLevel);
        }

        function showSuccess(count, promptHash) {
            if (successShownForHash === promptHash) {
                return;
            }
            successShownForHash = promptHash;
            createSuccessNotification(count);
        }

        function hide() {
            removeNotification();
            clearTimeout(successNotificationTimeout);
        }

        return {
            showWarning,
            showSuccess,
            hide
        };
    })();

    // ------------------ INPUT MONITORING ------------------
    let debounceTimer = null;

    function handleInput(text) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            scanAndNotify(text);
        }, 300);
    }

    function scanAndNotify(text) {
        const fullText = text.trim();
        const promptHash = generatePromptHash(fullText);

        if (fullText === lastScanText.trim()) return;

        lastScanText = fullText;
        lastProcessedPromptHash = promptHash;
        currentFindings = scanText(fullText);
        
        if (currentFindings.length > 0) {
            lastFindingsForHash.set(promptHash, [...currentFindings]);
        }

        if (currentFindings.length > 0) {
            NotificationManager.showWarning(currentFindings);
        } else {
            NotificationManager.hide();
        }
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
            scanAndNotify(rawText);
            const sanitized = NullEngine.processText(rawText);

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
            scanAndNotify(rawText);
            const sanitized = NullEngine.processText(rawText);

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
    }

    // ------------------ DOM MONITOR ------------------
    const DOMMonitor = (function() {
        let observer = null;
        let monitoredElements = new WeakSet();

        function collectPromptText() {
            const textParts = [];
            const selectors = [
                'textarea',
                'input[type="text"]',
                'input[type="email"]',
                'input[type="password"]',
                'div[contenteditable="true"]',
                'p[contenteditable="true"]'
            ];
            
            selectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    const text = el.value || el.innerText || el.textContent || '';
                    if (text.trim().length > 0) textParts.push(text);
                });
            });
            
            return textParts.join('\n');
        }

        function scanCurrentInputs() {
            const fullText = collectPromptText();
            scanAndNotify(fullText);
        }

        function monitorElement(el) {
            if (monitoredElements.has(el)) return;
            monitoredElements.add(el);
            attachInputListener(el);
        }

        function init() {
            if (observer) {
                observer.disconnect();
                observer = null;
            }

            const selectors = [
                'textarea',
                'input[type="text"]',
                'input[type="email"]',
                'input[type="password"]',
                'div[contenteditable="true"]',
                'p[contenteditable="true"]'
            ];
            
            selectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(monitorElement);
            });

            observer = new MutationObserver((mutations) => {
                if (NullEngine.isInternalMutation) return;
                if (Date.now() - NullEngine.lastActionTime < 50) return;
                
                let shouldScan = false;
                const selectorString = selectors.join(',');
                
                mutations.forEach(mutation => {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType !== Node.ELEMENT_NODE) return;
                        
                        const isTextarea = node.tagName === 'TEXTAREA';
                        const isInput = node.tagName === 'INPUT' && 
                            ['text', 'email', 'password'].includes(node.type);
                        const isContentEditable = 
                            (node.tagName === 'DIV' || node.tagName === 'P') &&
                            node.getAttribute('contenteditable') === 'true';
                        
                        if (isTextarea || isInput || isContentEditable) {
                            monitorElement(node);
                            shouldScan = true;
                        }

                        const newInputs = node.querySelectorAll?.(selectorString);
                        if (newInputs) {
                            newInputs.forEach(monitorElement);
                            if (newInputs.length > 0) shouldScan = true;
                        }
                    });
                });

                if (shouldScan) {
                    clearTimeout(debounceTimer);
                    debounceTimer = setTimeout(scanCurrentInputs, 300);
                }
            });

            observer.observe(document.documentElement, {
                childList: true,
                subtree: true
            });
        }

        return {
            init,
            scanCurrentInputs,
            collectPromptText,
            getPromptHash: () => generatePromptHash(collectPromptText().trim())
        };
    })();

    // ------------------ MESSAGE HANDLER ------------------
    if (typeof chrome !== 'undefined' && chrome.runtime) {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            if (message.action === 'getFindings') {
                DOMMonitor.scanCurrentInputs();
                sendResponse({ findings: currentFindings });
            }
            return true;
        });
    }

    // ------------------ NETWORK INTERCEPTION ------------------
    function monitorSubmissions() {
        const originalFetch = window.fetch;
        window.fetch = async function(...args) {
            const resource = args[0];
            const config = args[1];
            const url = (typeof resource === 'string') ? resource : resource.url;  
            const method = (config?.method || resource?.method || 'GET').toUpperCase();

            const isTarget = (
                url.includes('chatgpt.com') || 
                url.includes('openai.com') || 
                url.includes('claude.ai') || 
                url.includes('anthropic.com')
            ) && method === 'POST';

            let usedPromptHash = null;
            let hasSanitized = false;

            if (isTarget) {
                try {
                    let bodyText = "";
                    if (typeof config?.body === 'string') {
                        bodyText = config.body;
                    } else if (resource instanceof Request) {
                        const clone = resource.clone();
                        bodyText = await clone.text();
                    }

                    if (bodyText) {
                        if (currentFindings.length === 0) {
                            DOMMonitor.scanCurrentInputs();
                        }
                        
                        const fullText = DOMMonitor.collectPromptText();
                        usedPromptHash = generatePromptHash(fullText.trim());
                        
                        let sanitizedBody = NullEngine.processText(bodyText);

                        if (sanitizedBody !== bodyText) {
                            hasSanitized = true;
                            if (typeof config?.body === 'string') {
                                config.body = sanitizedBody;
                            } else if (resource instanceof Request) {
                                const newRequest = new Request(resource, { ...config, body: sanitizedBody });
                                const response = await originalFetch(newRequest);
                                
                                if (usedPromptHash && lastFindingsForHash.has(usedPromptHash)) {
                                    const findings = lastFindingsForHash.get(usedPromptHash);
                                    if (findings.length > 0) {
                                        NotificationManager.showSuccess(findings.length, usedPromptHash);
                                    }
                                }
                                
                                const responseClone = response.clone();
                                const responseText = await responseClone.text();
                                const restoredResponseText = NullEngine.restoreText(responseText);
                                const restoredResponse = new Response(restoredResponseText, {
                                    status: response.status,
                                    statusText: response.statusText,
                                    headers: response.headers
                                });
                                return restoredResponse;
                            }
                        }
                    }
                } catch (e) {
                    // Pass through original request if interception fails
                }
            }

            const response = await originalFetch.apply(this, args);
            
            if (isTarget && hasSanitized && usedPromptHash && lastFindingsForHash.has(usedPromptHash)) {
                const findings = lastFindingsForHash.get(usedPromptHash);
                if (findings.length > 0) {
                    NotificationManager.showSuccess(findings.length, usedPromptHash);
                }
            }
            
            try {
                const responseClone = response.clone();
                const responseText = await responseClone.text();
                const restoredResponseText = NullEngine.restoreText(responseText);
                if (restoredResponseText !== responseText) {
                    return new Response(restoredResponseText, {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers
                    });
                }
            } catch (e) {
                // Ignore if we can't process response
            }
            return response;
        };
    }

    // ------------------ INIT ------------------
    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                monitorSubmissions();
                DOMMonitor.init();
            });
        } else {
            monitorSubmissions();
            DOMMonitor.init();
        }
    }

    init();

    window.NullPrompt = {
        scanText,
        NotificationManager,
        DOMMonitor,
        currentFindings,
        NullEngine
    };
})();
