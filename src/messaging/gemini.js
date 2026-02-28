// c:\Users\PC LBS\kernel-killers\src\messaging\gemini.js
const https = require('https');

async function queryGemini(conversationContext, userQuery) {
    if (process.env.ENABLE_AI !== 'true') {
        return '[AI disabled — run with ENABLE_AI=true]';
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        return '[AI error — GEMINI_API_KEY not set]';
    }

    const prompt = buildPrompt(conversationContext, userQuery);
    const body = JSON.stringify({
        contents: [{
            role: 'user',
            parts: [{ text: prompt }]
        }]
    });

    return new Promise((resolve) => {
        const req = https.request('https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=' + apiKey, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
            },
            timeout: 8000
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    if (parsed.error) {
                        resolve('[AI error: ' + parsed.error.message + ']');
                        return;
                    }
                    const text = parsed.candidates[0].content.parts[0].text;
                    resolve(text);
                } catch (e) {
                    resolve('[AI parsing error]');
                }
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve('[AI timeout — offline mode active]');
        });

        req.on('error', () => {
            resolve('[AI unavailable]');
        });

        req.write(body);
        req.end();
    });
}

function buildPrompt(context, query) {
    let prompt = "System: You are a node in the Archipel P2P network. Answer concisely.\n";
    if (context && context.length > 0) {
        prompt += "Context (last messages):\n" + context.join('\n') + "\n\n";
    }
    prompt += "User query: " + query;
    return prompt;
}

module.exports = { queryGemini, buildPrompt };
