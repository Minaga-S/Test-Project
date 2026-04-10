process.env.GEMINI_API_KEY = 'test-gemini-key-' + Date.now();
process.env.GEMINI_MODEL = 'gemini-2.5-flash';
process.env.GEMINI_MODEL_VERSION = 'v1beta';
delete process.env.GEMINI_MODEL_FALLBACKS;

const axios = require('axios');
jest.mock('axios');

const { analyzeThreatWithAI, generateRecommendations, __private } = require('./ai-config');

describe('ai-config (Gemini)', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should sanitize fenced JSON text', () => {
        const raw = '```json\n{"threatType":"Phishing"}\n```';

        const sanitized = __private.sanitizeJsonText(raw);

        expect(sanitized).toBe('{"threatType":"Phishing"}');
    });

    it('should extract text parts from Gemini response', () => {
        const responseData = {
            candidates: [{
                content: {
                    parts: [{ text: '{"a":1}' }, { text: '{"b":2}' }],
                },
            }],
        };

        const extracted = __private.extractTextFromGeminiResponse(responseData);

        expect(extracted).toBe('{"a":1}\n{"b":2}');
    });

    it('should detect transient HTTP errors', () => {
        const isTransient = __private.isTransientError({ response: { status: 429 } });

        expect(isTransient).toBe(true);
    });

    it('should detect malformed JSON errors', () => {
        const malformed = __private.isMalformedJsonError(new SyntaxError('Unterminated string in JSON'));

        expect(malformed).toBe(true);
    });

    it('should prioritize gemini-2.5-flash-lite as fallback after configured model', () => {
        const candidates = __private.getCandidateModels();

        expect(candidates[0]).toBe('gemini-2.5-flash');
        expect(candidates[1]).toBe('gemini-2.5-flash-lite');
        expect(candidates[2]).toBe('gemini-2.5-pro');
    });

    it('should use GEMINI_MODEL_FALLBACKS when provided', () => {
        process.env.GEMINI_MODEL_FALLBACKS = 'gemini-2.5-flash-lite, gemini-2.5-pro';
        jest.resetModules();
        const reloaded = require('./ai-config');

        const candidates = reloaded.__private.getCandidateModels();

        expect(candidates).toEqual(['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-2.5-pro']);

        delete process.env.GEMINI_MODEL_FALLBACKS;
        jest.resetModules();
    });

    it('should return parsed analysis from Gemini response', async () => {
        axios.post.mockResolvedValue({
            data: {
                candidates: [{
                    content: {
                        parts: [{ text: '{"threatType":"Malware","likelihood":3,"impact":3}' }],
                    },
                }],
            },
        });

        const result = await analyzeThreatWithAI('POS machine is showing popups and running slow.');

        expect(result.threatType).toBe('Malware');
        expect(result.likelihood).toBe(3);
        expect(result.impact).toBe(3);
        expect(axios.post).toHaveBeenCalledTimes(1);
    });

    it('should retry with plain generationConfig when responseMimeType request is invalid', async () => {
        axios.post
            .mockRejectedValueOnce({
                response: {
                    status: 400,
                    data: {
                        error: {
                            message: 'Invalid argument: responseMimeType is not supported',
                        },
                    },
                },
            })
            .mockResolvedValueOnce({
                data: {
                    candidates: [{
                        content: {
                            parts: [{ text: '{"threatType":"Phishing","likelihood":2,"impact":2}' }],
                        },
                    }],
                },
            });

        const result = await analyzeThreatWithAI('A suspicious email requested login details.');

        expect(result.threatType).toBe('Phishing');
        expect(axios.post).toHaveBeenCalledTimes(2);
    });

    it('should switch to the next model when the primary model returns high-demand 503', async () => {
        axios.post
            .mockRejectedValueOnce({
                response: {
                    status: 503,
                    data: {
                        error: {
                            message: 'This model is currently experiencing high demand. Please try again later.',
                        },
                    },
                },
            })
            .mockResolvedValueOnce({
                data: {
                    candidates: [{
                        content: {
                            parts: [{ text: '{"threatType":"Malware","likelihood":3,"impact":3}' }],
                        },
                    }],
                },
            });

        const result = await analyzeThreatWithAI('Endpoint is showing signs of malicious behavior.');

        expect(result.threatType).toBe('Malware');
        expect(axios.post.mock.calls[0][0]).toContain('/models/gemini-2.5-flash:generateContent');
        expect(axios.post.mock.calls[1][0]).toContain('/models/gemini-2.5-flash-lite:generateContent');
    });

    it('should repair malformed JSON when first model output is invalid', async () => {
        axios.post
            .mockResolvedValueOnce({
                data: {
                    candidates: [{
                        content: {
                            parts: [{ text: '{"threatType":"Ransomware","likelihood":4,"impact":"' }],
                        },
                    }],
                },
            })
            .mockResolvedValueOnce({
                data: {
                    candidates: [{
                        content: {
                            parts: [{ text: '{"threatType":"Ransomware","likelihood":4,"impact":4}' }],
                        },
                    }],
                },
            });

        const result = await analyzeThreatWithAI('Booking and payment systems are encrypted and unavailable.');

        expect(result.threatType).toBe('Ransomware');
        expect(result.impact).toBe(4);
        expect(axios.post).toHaveBeenCalledTimes(2);
    });

    it('should return recommendation array when Gemini returns a JSON array', async () => {
        axios.post.mockResolvedValue({
            data: {
                candidates: [{
                    content: {
                        parts: [{ text: '["Step 1","Step 2"]' }],
                    },
                }],
            },
        });

        const recommendations = await generateRecommendations('Phishing', {
            threatCategory: 'Social Engineering',
            affectedAsset: 'Device',
            likelihood: 3,
            impact: 2,
        });

        expect(recommendations).toEqual(['Step 1', 'Step 2']);
    });


    it('should include detected os and cpe context in ai prompt', async () => {
        axios.post.mockResolvedValue({
            data: {
                candidates: [{
                    content: {
                        parts: [{ text: '{"threatType":"Malware","likelihood":3,"impact":3}' }],
                    },
                }],
            },
        });

        await analyzeThreatWithAI('Suspicious process observed on host.', {
            liveScan: { enabled: true, target: '10.0.0.10', osInfo: 'Linux 6.6', observedOpenPorts: [22] },
            cve: { query: { cpeUri: 'cpe:/o:linux:linux_kernel:6.6', vendor: 'linux', product: 'linux_kernel', productVersion: '6.6' }, matches: [] },
        });

        expect(axios.post.mock.calls[0][1].contents[0].parts[0].text).toContain('Detected CPE URI: cpe:/o:linux:linux_kernel:6.6');
    });
    it('should use deterministic temperature by default for analysis requests', async () => {
        axios.post.mockResolvedValue({
            data: {
                candidates: [{
                    content: {
                        parts: [{ text: '{"threatType":"Malware","likelihood":3,"impact":3}' }],
                    },
                }],
            },
        });

        await analyzeThreatWithAI('POS machine is showing popups and running slow.');

        expect(axios.post.mock.calls[0][1].generationConfig.temperature).toBe(0);
    });
});
