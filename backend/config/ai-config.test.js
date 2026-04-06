process.env.GEMINI_API_KEY = 'AIzaSyDMjH9qSHLlaBZEeCyBX9c98Plu2uixS-w';
process.env.GEMINI_MODEL = 'gemini-2.5-flash';
process.env.GEMINI_MODEL_VERSION = 'v1beta';

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
});