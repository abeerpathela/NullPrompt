try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('content/engine-injector.js');
    script.onload = () => script.remove();
    (document.head || document.documentElement).appendChild(script);
} catch (e) {
    console.error("NullPrompt Bridge Error:", e);
}

window.addEventListener("NULLPROMPT_SIGNAL", (event) => {
    const { type, data } = event.detail;
    if (type === 'PROMPT_DETECTED') {
        console.log("NullPrompt intercepted a prompt. Ready for Agent 1.");
    }
});
