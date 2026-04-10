/**
 * AI Service Configuration (Gemini)
 */
// NOTE: Configuration: centralizes setup for external systems and runtime options.


const axios = require('axios');
const logger = require('../utils/logger');

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const GEMINI_MODEL_VERSION = process.env.GEMINI_MODEL_VERSION || 'v1beta';
const GEMINI_API_BASE_URL = `https://generativelanguage.googleapis.com/${GEMINI_MODEL_VERSION}/models`;
const DETERMINISTIC_TEMPERATURE = Number(process.env.GEMINI_TEMPERATURE || 0);
const JSON_REPAIR_TEMPERATURE = Number(process.env.GEMINI_REPAIR_TEMPERATURE || 0);
const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 300;
const DEFAULT_MODEL_FALLBACKS = ['gemini-2.5-flash-lite', 'gemini-2.5-pro'];

function getGeminiApiUrl(modelName) {
    return `${GEMINI_API_BASE_URL}/${modelName}:generateContent?key=${GEMINI_API_KEY}`;
}

function isTransientError(error) {
    const transientHttpStatuses = [408, 429, 500, 502, 503, 504];
    const transientNetworkCodes = ['ECONNABORTED', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT'];

    const statusCode = error?.response?.status;
    if (transientHttpStatuses.includes(statusCode)) {
        return true;
    }

    return transientNetworkCodes.includes(error?.code);
}

function isMalformedJsonError(error) {
    if (!error) {
        return false;
    }

    if (error.name === 'GeminiParseError') {
        return true;
    }

    if (error instanceof SyntaxError) {
        return true;
    }

    const message = String(error.message || '');
    return /json|unterminated|string|unexpected token|end of json/i.test(message);
}

function sanitizeJsonText(rawText = '') {
    const trimmed = String(rawText || '').trim();
    if (!trimmed) {
        return trimmed;
    }

    if (trimmed.startsWith('```')) {
        return trimmed
            .replace(/^```(?:json)?\s*/i, '')
            .replace(/\s*```$/i, '')
            .trim();
    }

    return trimmed;
}

function extractJsonPayload(rawText = '') {
    const sanitized = sanitizeJsonText(rawText);
    if (!sanitized) {
        return '';
    }

    const startCandidates = [sanitized.indexOf('{'), sanitized.indexOf('[')]
        .filter((index) => index >= 0)
        .sort((a, b) => a - b);

    if (startCandidates.length === 0) {
        return sanitized;
    }

    const startIndex = startCandidates[0];
    const openingChar = sanitized[startIndex];
    const closingChar = openingChar === '{' ? '}' : ']';
    const endIndex = sanitized.lastIndexOf(closingChar);

    if (endIndex <= startIndex) {
        return sanitized;
    }

    return sanitized.slice(startIndex, endIndex + 1);
}

function parseGeminiJson(rawText = '') {
    const strictPayload = sanitizeJsonText(rawText);
    try {
        return JSON.parse(strictPayload);
    } catch (strictError) {
        const extractedPayload = extractJsonPayload(rawText);
        return JSON.parse(extractedPayload);
    }
}

function extractTextFromGeminiResponse(responseData = {}) {
    const parts = responseData?.candidates?.[0]?.content?.parts || [];
    const joinedText = parts
        .map((part) => part?.text || '')
        .join('\n')
        .trim();

    return joinedText;
}

async function waitBeforeRetry(attempt) {
    const delay = RETRY_BASE_DELAY_MS * (2 ** attempt);
    await new Promise((resolve) => setTimeout(resolve, delay));
}

function isModelNotFoundError(error) {
    return error?.response?.status === 404;
}

function isInvalidArgumentError(error) {
    return error?.response?.status === 400;
}

function isHighDemandError(error) {
    const statusCode = error?.response?.status;
    const message = String(error?.response?.data?.error?.message || error?.message || '');
    return statusCode === 503 && /high demand|try again later|temporar/i.test(message);
}

function getCandidateModels() {
    const configuredModel = String(GEMINI_MODEL || '').trim();
    const configuredFallbacks = String(process.env.GEMINI_MODEL_FALLBACKS || '')
        .split(',')
        .map((modelName) => modelName.trim())
        .filter(Boolean);

    const fallbackModels = configuredFallbacks.length > 0
        ? configuredFallbacks
        : DEFAULT_MODEL_FALLBACKS;

    const modelList = [configuredModel, ...fallbackModels].filter(Boolean);
    return [...new Set(modelList)];
}

async function sendGeminiRequest(modelName, requestBody) {
    return axios.post(getGeminiApiUrl(modelName), requestBody, {
        headers: {
            'Content-Type': 'application/json',
        },
        timeout: 20000,
    });
}

async function requestGeminiJson(modelName, requestBody) {
    const response = await sendGeminiRequest(modelName, requestBody);

    const rawText = extractTextFromGeminiResponse(response.data);
    if (!rawText) {
        throw new Error('Gemini returned empty content');
    }

    try {
        return parseGeminiJson(rawText);
    } catch (parseError) {
        const wrappedError = new Error(parseError.message);
        wrappedError.name = 'GeminiParseError';
        wrappedError.rawText = rawText;
        wrappedError.cause = parseError;
        throw wrappedError;
    }
}

async function repairMalformedJson(modelName, malformedText) {
    const repairPrompt = `
You are a strict JSON formatter.
Convert the content below into valid JSON.
Respond with valid JSON only. No markdown, no explanation.

Content:
${malformedText}
`;

    const repairRequestBody = {
        contents: [{
            role: 'user',
            parts: [{ text: repairPrompt }],
        }],
        generationConfig: {
            temperature: JSON_REPAIR_TEMPERATURE,
            maxOutputTokens: 1400,
        },
    };

    return requestGeminiJson(modelName, repairRequestBody);
}

async function generateJsonWithGemini(prompt) {
    if (!GEMINI_API_KEY) {
        throw new Error('Gemini API key not configured');
    }

    const requestBody = {
        contents: [{
            role: 'user',
            parts: [{ text: prompt }],
        }],
        generationConfig: {
            temperature: DETERMINISTIC_TEMPERATURE,
            maxOutputTokens: 1400,
            responseMimeType: 'application/json',
        },
    };

    const plainRequestBody = {
        ...requestBody,
        generationConfig: {
            temperature: requestBody.generationConfig.temperature,
            maxOutputTokens: requestBody.generationConfig.maxOutputTokens,
        },
    };

    const candidateModels = getCandidateModels();
    const modelErrors = [];

    for (const modelName of candidateModels) {
        for (let attempt = 0; attempt < MAX_RETRIES; attempt += 1) {
            try {
                return await requestGeminiJson(modelName, requestBody);
            } catch (error) {
                const isLastAttempt = attempt === MAX_RETRIES - 1;

                if (isModelNotFoundError(error)) {
                    modelErrors.push(`${modelName}: model not found`);
                    break;
                }

                if (isMalformedJsonError(error)) {
                    const malformedText = error?.rawText || '';

                    if (malformedText) {
                        try {
                            return await repairMalformedJson(modelName, malformedText);
                        } catch (repairError) {
                            const repairMessage = repairError?.response?.data?.error?.message || repairError.message;
                            modelErrors.push(`${modelName}: malformed-json ${repairMessage}`);
                        }
                    }

                    if (!isLastAttempt) {
                        await waitBeforeRetry(attempt);
                        continue;
                    }

                    modelErrors.push(`${modelName}: malformed-json ${error.message}`);
                    break;
                }

                if (isInvalidArgumentError(error)) {
                    try {
                        return await requestGeminiJson(modelName, plainRequestBody);
                    } catch (plainError) {
                        const plainStatusCode = plainError?.response?.status;
                        const plainErrorMessage = plainError?.response?.data?.error?.message || plainError.message;
                        modelErrors.push(`${modelName}: ${plainStatusCode || 'unknown'} ${plainErrorMessage}`);
                        break;
                    }
                }

                if (isHighDemandError(error)) {
                    const statusCode = error?.response?.status;
                    const errorMessage = error?.response?.data?.error?.message || error.message;
                    modelErrors.push(`${modelName}: ${statusCode || 'unknown'} ${errorMessage}`);
                    break;
                }

                if (isTransientError(error) && !isLastAttempt) {
                    await waitBeforeRetry(attempt);
                    continue;
                }

                const statusCode = error?.response?.status;
                const errorMessage = error?.response?.data?.error?.message || error.message;
                modelErrors.push(`${modelName}: ${statusCode || 'unknown'} ${errorMessage}`);
                break;
            }
        }
    }

    throw new Error(`Unexpected Gemini failure: ${modelErrors.join(' | ')}`);
}

function formatSecurityContextForPrompt(securityContext) {
    if (!securityContext) {
        return 'No additional scan or CVE context provided.';
    }

    const liveScan = securityContext.liveScan || {};
    const cve = securityContext.cve || {};
    const cveQuery = cve.query || {};
    const cveMatches = Array.isArray(cve.matches) ? cve.matches : [];

    const cveSummary = cveMatches.length > 0
        ? cveMatches.map((entry) => `${entry.cveId} (${entry.severity || 'Unknown'})`).join(', ')
        : 'None';

    return [
        `Live scan enabled: ${Boolean(liveScan.enabled)}`,
        `Live scan target: ${liveScan.target || 'Unknown'}`,
        `Detected OS: ${liveScan.osInfo || cveQuery.osName || 'Unknown'}`,
        `Detected CPE URI: ${cveQuery.cpeUri || 'None'}`,
        `Detected vendor: ${cveQuery.vendor || 'Unknown'}`,
        `Detected product: ${cveQuery.product || 'Unknown'}`,
        `Detected product version: ${cveQuery.productVersion || 'Unknown'}`,
        `Observed open ports: ${(liveScan.observedOpenPorts || []).join(', ') || 'None'}`,
        `Service count: ${(liveScan.services || []).length || 0}`,
        `CVE matches: ${cveSummary}`,
    ].join('\n');
}

async function analyzeThreatWithAI(description, securityContext = null) {
    try {
        const prompt = `
You are a cybersecurity analyst for hotels.
Analyze the incident description and return valid JSON only.

Required JSON shape:
{
  "threatType": "Phishing|Malware|Ransomware|DDoS|Unauthorized Access|Data Breach",
  "threatCategory": "short category name",
  "affectedAsset": "best-fit asset type",
  "confidence": 0-100 integer,
  "likelihood": 1-4 integer,
  "impact": 1-4 integer,
  "mitigationSteps": ["3 to 5 concise actions"],
  "nistFunctions": ["Identify|Protect|Detect|Respond|Recover"],
  "nistControls": ["NIST CSF control IDs like PR.AC, DE.CM, RS.RP"]
}

Rules:
- Ensure likelihood and impact are integers from 1 to 4.
- Keep recommendations practical for small hotel operations.
- Align controls/functions with the described attack behavior.

Additional Security Context:
${formatSecurityContextForPrompt(securityContext)}

Incident Description:
"${description}"
`;

        const analysis = await generateJsonWithGemini(prompt);
        return analysis;
    } catch (error) {
        logger.error(`Gemini threat analysis error: ${error.message}`);
        throw new Error('Failed to analyze threat with AI');
    }
}

async function generateRecommendations(threatType, threatDetails) {
    try {
        const prompt = `
You are a cybersecurity advisor for a small hotel.
Return valid JSON only as an array of 5 to 7 concise recommendation strings.

Threat context:
- threatType: ${threatType}
- threatCategory: ${threatDetails.threatCategory || 'Unknown'}
- affectedAsset: ${threatDetails.affectedAsset || 'Unknown'}
- likelihood: ${threatDetails.likelihood || 'Unknown'}
- impact: ${threatDetails.impact || 'Unknown'}
- additionalContext: ${formatSecurityContextForPrompt(threatDetails.securityContext)}

Requirements:
- Include immediate containment actions and longer-term improvements.
- Keep actions realistic for low/medium budget organizations.
- Reference NIST-aligned security practices where useful.
`;

        const result = await generateJsonWithGemini(prompt);
        return Array.isArray(result) ? result : [];
    } catch (error) {
        logger.error(`Gemini recommendation generation error: ${error.message}`);
        return [];
    }
}

module.exports = {
    analyzeThreatWithAI,
    generateRecommendations,
    __private: {
        sanitizeJsonText,
        extractJsonPayload,
        extractTextFromGeminiResponse,
        isTransientError,
        isMalformedJsonError,
        isHighDemandError,
        getCandidateModels,
    },
};
