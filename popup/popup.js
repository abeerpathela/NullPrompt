function renderFindings(findings) {
    const container = document.getElementById('findings-list');
    if (findings.length === 0) {
        container.innerHTML = `
            <div class="no-findings">
                <div class="no-findings-icon">🛡️</div>
                No sensitive data detected
            </div>
        `;
        return;
    }
    container.innerHTML = findings.map(f => {
        // Escape user-controlled values to prevent XSS
        const safeName = escapeHtml(f.name);
        const safeSeverity = escapeHtml(f.severity);
        const safeValue = escapeHtml(f.value);
        const safeConfidence = Math.round(f.confidence * 100);
        
        return `
            <div class="finding-card ${safeSeverity}">
                <div class="finding-header">
                    <span class="finding-name">${safeName}</span>
                    <span class="severity-badge ${safeSeverity}">${safeSeverity}</span>
                </div>
                <div class="finding-value">${safeValue}</div>
                <div class="confidence">Confidence: ${safeConfidence}%</div>
            </div>
        `;
    }).join('');
}

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

// Try to get findings from active tab
async function refreshFindings() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) {
            renderFindings([]);
            return;
        }

        const response = await chrome.tabs.sendMessage(tab.id, { action: 'getFindings' });
        renderFindings(response?.findings || []);
    } catch (e) {
        // If content script not available, show no findings
        renderFindings([]);
    }
}

// Refresh on load and every 500ms
document.addEventListener('DOMContentLoaded', () => {
    refreshFindings();
    setInterval(refreshFindings, 500);
});
