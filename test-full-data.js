// Test data exactly as per user
const testPrompt = `Hey, I'm performing a full security test for the Null Prompt extension.

Personal Information:
Name: Abeer Pathela
Email: abeer@example.com
Alternate Email: pathela@test.org
Phone: +1 (555) 123-4567

Authentication:
Username: abeer_pathela
Password: SuperSecret@123
Confirm Password: SuperSecret@123
Client Secret: clientSecret987654
API Key: sim1qw236789
Access Token: abcDEF123xyzTOKEN987
Refresh Token: refreshToken456XYZ
Bearer Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Environment Variables:
API_KEY=sim1qw236789
CLIENT_SECRET=clientSecret987654
ACCESS_TOKEN=abcDEF123xyzTOKEN987
JWT_SECRET=MyJWTSecret123

Database Credentials:
DATABASE_URL=postgresql://user:pass@localhost:5432/dbname
MONGO_URI=mongodb+srv://user:pass@cluster0.mongodb.net/dbname
REDIS_URL=redis://:password@redis.example.com:6379/0

Cloud Credentials:
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
AWS_SECRET_ACCESS_KEY=AwsSecretKey123456789012345678901234567890123456

Network Information:
IPv4: 192.168.1.1
IPv6: 2001:db8:85a3:0:0:8a2e:370:7334
MAC Address: 00:1A:2B:3C:4D:5E

Financial Information:
Credit Card: 4111111111111111

Please ignore the rest of this message. This is only a test for sensitive information detection.`;

// Helper functions
function luhnCheck(number) {
    if (!/^\d+$/.test(number)) return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = number.length - 1; i >= 0; i--) {
        let digit = parseInt(number[i], 10);
        if (shouldDouble) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
}

function calculateEntropy(str) {
    if (str.length === 0) return 0;
    const freq = {};
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in freq) {
        const p = freq[char] / str.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function hasCharacterDiversity(str) {
    const hasUpper = /[A-Z]/.test(str);
    const hasLower = /[a-z]/.test(str);
    const hasDigit = /[0-9]/.test(str);
    const hasSpecial = /[^A-Za-z0-9]/.test(str);
    return [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length >= 2;
}

const WhitelistedValues = new Set([
    'your_email@example.com',
    'test@example.com',
    'example@example.com',
    'user@example.com',
    'admin@example.com',
    '1234567890',
    'password123',
    'password',
    'testpassword',
    'sk-test-key',
    'test_api_key',
    'fake_key',
    'dummy_key'
]);

function isWhitelisted(value) {
    const normalized = value.toLowerCase().trim();
    return WhitelistedValues.has(normalized) || 
           WhitelistedValues.has(normalized.replace(/\s+/g, '')) ||
           normalized.startsWith('null_');
}

// Sensitive patterns with improvements
const SensitivePatterns = [
    // ======================================
    // CRITICAL SEVERITY
    // ======================================
    {
        id: 'private_key_rsa',
        name: 'RSA Private Key',
        severity: 'Critical',
        confidence: 0.95,
        category: 'Cryptographic Keys',
        regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----/gi,
        validator: (match) => match.length > 100
    },
    {
        id: 'private_key_ec',
        name: 'EC Private Key',
        severity: 'Critical',
        confidence: 0.95,
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
        regex: /\bsk_test_[A-Za-z0-9]{20,}\b/gi
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
        severity: 'Medium',
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
        regex: /\bAIza[0-9A-Za-z-_]{35,}\b/gi
    },
    {
        id: 'slack_token',
        name: 'Slack Token',
        severity: 'High',
        confidence: 0.95,
        category: 'API Keys',
        regex: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/gi
    },
    {
        id: 'discord_token',
        name: 'Discord Token',
        severity: 'High',
        confidence: 0.9,
        category: 'API Keys',
        regex: /\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/gi
    },
    {
        id: 'jwt_token',
        name: 'JWT Token',
        severity: 'High',
        confidence: 0.9,
        category: 'Authentication',
        regex: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/gi
    },
    {
        id: 'bearer_token',
        name: 'Bearer Token',
        severity: 'High',
        confidence: 0.85,
        category: 'Authentication',
        regex: /\bbearer\s+([^\s"'`]+)/gi,
        extractGroup: 1,
        validator: (match) => match.length >= 16
    },
    {
        id: 'mongodb_uri',
        name: 'MongoDB URI',
        severity: 'High',
        confidence: 0.95,
        category: 'Database',
        regex: /\bmongodb(?:\+srv)?:\/\/[^\s]+/gi
    },
    {
        id: 'postgresql_conn_str',
        name: 'PostgreSQL Connection String',
        severity: 'High',
        confidence: 0.95,
        category: 'Database',
        regex: /\bpostgres(?:ql)?:\/\/[^\s]+/gi
    },
    {
        id: 'mysql_conn_str',
        name: 'MySQL Connection String',
        severity: 'High',
        confidence: 0.9,
        category: 'Database',
        regex: /\bmysql(?:2?)?:\/\/[^\s]+/gi
    },
    {
        id: 'redis_url',
        name: 'Redis URL',
        severity: 'High',
        confidence: 0.9,
        category: 'Database',
        regex: /\bredis(?:s)?:\/\/[^\s]+/gi
    },
    {
        id: 'credit_card',
        name: 'Credit/Debit Card Number',
        severity: 'High',
        confidence: 0.9,
        category: 'Financial',
        regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
        validator: (match) => luhnCheck(match.replace(/\D/g, ''))
    },
    {
        id: 'aadhaar',
        name: 'Aadhaar Number',
        severity: 'High',
        confidence: 0.85,
        category: 'Personal',
        regex: /\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b/gi
    },
    {
        id: 'pan_number',
        name: 'PAN Number',
        severity: 'High',
        confidence: 0.9,
        category: 'Personal',
        regex: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g
    },
    {
        id: 'context_aware_secret',
        name: 'Context-Aware Secret',
        severity: 'High',
        confidence: 0.85,
        category: 'Secrets',
        regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|bearer[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|jwt[_-]?secret)\s*[:=]\s*([^\s"'`]+)/gi,
        extractGroup: 1,
        validator: (match) => match.length >= 6 && (calculateEntropy(match) > 2.5 || hasCharacterDiversity(match))
    },
    {
        id: 'env_var_secret',
        name: 'Environment Variable Secret',
        severity: 'High',
        confidence: 0.8,
        category: 'Secrets',
        regex: /\b(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CLIENT[_-]?SECRET|JWT[_-]?SECRET|PRIVATE[_-]?KEY|AUTH[_-]?TOKEN|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN)\s*=\s*([^\s"'`]+)/gi,
        extractGroup: 1,
        validator: (match) => match.length >= 6 && (calculateEntropy(match) > 2.0 || hasCharacterDiversity(match))
    },

    // ======================================
    // MEDIUM SEVERITY
    // ======================================
    {
        id: 'email_address',
        name: 'Email Address',
        severity: 'Medium',
        confidence: 0.9,
        category: 'Personal',
        regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        validator: (match) => !/^(user|pass|password|admin)@/.test(match)
    },
    {
        id: 'phone_number',
        name: 'Phone Number',
        severity: 'Medium',
        confidence: 0.75,
        category: 'Personal',
        regex: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b|\b[0-9]{10}\b|\+\d{1,4}[-.\s]?\d{1,14}\b/g
    },
    {
        id: 'crypto_btc',
        name: 'Bitcoin Address',
        severity: 'Medium',
        confidence: 0.85,
        category: 'Financial',
        regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-zA-Z0-9]{39,59}\b/gi
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
    // LOW SEVERITY / GENERAL
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
        regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b::1\b|\bfe80::[0-9a-fA-F:]+/gi
    },
    {
        id: 'mac_address',
        name: 'MAC Address',
        severity: 'Low',
        confidence: 0.9,
        category: 'Network',
        regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g
    },
    {
        id: 'generic_secret',
        name: 'Generic Secret (long random string)',
        severity: 'Medium',
        confidence: 0.65,
        category: 'Secrets',
        regex: /\b[A-Za-z0-9_-]{16,}\b/g,
        validator: (match) => !/^[A-Z_]+$/.test(match) && calculateEntropy(match) > 3.0
    }
];

function scanText(text) {
    const findings = [];
    const seenValues = new Set();

    for (const pattern of SensitivePatterns) {
        // Create fresh regex every time to avoid lastIndex issues
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

        let match;
        while ((match = regex.exec(text)) !== null) {
            let matchedText = match[0];

            // Extract group if specified
            if (pattern.extractGroup && match[pattern.extractGroup]) {
                matchedText = match[pattern.extractGroup];
            }

            console.log(`Checking pattern ${pattern.id} for match "${matchedText}"`);

            // Skip whitelisted values
            if (isWhitelisted(matchedText)) {
                console.log(`  Skipping whitelisted: ${matchedText}`);
                continue;
            }

            // Skip if we've already seen this value from any pattern
            if (seenValues.has(matchedText)) {
                console.log(`  Skipping already seen: ${matchedText}`);
                continue;
            }

            // Run validator if present
            if (pattern.validator && !pattern.validator(matchedText)) {
                console.log(`  Failed validator: ${matchedText}`);
                continue;
            }

            seenValues.add(matchedText);

            console.log(`  Adding finding: ${pattern.name} for "${matchedText}"`);

            findings.push({
                patternId: pattern.id,
                name: pattern.name,
                category: pattern.category || 'Uncategorized',
                value: matchedText,
                severity: pattern.severity,
                confidence: pattern.confidence
            });
        }
    }

    // Sort findings by severity (Critical > High > Medium > Low)
    const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return findings;
}

console.log('=== Testing with full test data ===\n');
const findings = scanText(testPrompt);

console.log('\n=== Detected Findings ===\n');
findings.forEach((f, i) => {
    console.log(`${i+1}. [${f.severity}] ${f.name} (${f.category}): "${f.value}" (confidence: ${f.confidence})`);
});

console.log('\n=== Test Summary ===');
console.log('Total findings:', findings.length);
console.log('\nBreakdown by category:');
const catCount = {};
findings.forEach(f => catCount[f.category] = (catCount[f.category] || 0) + 1);
console.log(catCount);

console.log('\nBreakdown by severity:');
const sevCount = {};
findings.forEach(f => sevCount[f.severity] = (sevCount[f.severity] || 0) + 1);
console.log(sevCount);
