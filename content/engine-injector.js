(function() {
    const { fetch: originalFetch } = window;

    window.fetch = async (...args) => {
        let [resource, config] = args;

        if (config && config.method === 'POST' && config.body) {
            try {
                const bodyStr = typeof config.body === 'string' ? config.body : JSON.stringify(config.body);
                
                const aiKeywords = ['"prompt"', '"messages"', '"content"', '"input"'];
                const isAI = aiKeywords.some(key => bodyStr.includes(key));

                if (isAI) {
                    console.warn("NullPrompt: AI Data Stream Detected. Analyzing...");
                    
                    window.dispatchEvent(new CustomEvent("NULLPROMPT_SIGNAL", {
                        detail: { type: 'PROMPT_DETECTED', body: bodyStr }
                    }));
                }
            } catch (e) {
            }
        }
        return originalFetch(resource, config);
    };

    console.log("NullPrompt Engine: Interceptor Hooked.");
})();
