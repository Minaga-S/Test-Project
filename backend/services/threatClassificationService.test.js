const threatService = require('./threatClassificationService');
const aiConfig = require('../config/ai-config');

jest.mock('../config/ai-config', () => ({
    analyzeThreatWithAI: jest.fn(),
}));

describe('threatClassificationService fallback scoring', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should score severe ransomware description as critical fallback', async () => {
        aiConfig.analyzeThreatWithAI.mockRejectedValue(new Error('Gemini unavailable'));

        const result = await threatService.classifyThreat(
            'Payment server encrypted, backup shares encrypted, admin account created, cannot process reservations.'
        );

        expect(result.threatType).toBe('Ransomware');
        expect(result.likelihood).toBe(4);
        expect(result.impact).toBe(4);
    });

    it('should score non-severe ransomware description as high fallback', async () => {
        aiConfig.analyzeThreatWithAI.mockRejectedValue(new Error('Gemini unavailable'));

        const result = await threatService.classifyThreat(
            'A workstation appears encrypted and locked with a ransom note.'
        );

        expect(result.threatType).toBe('Ransomware');
        expect(result.likelihood).toBe(3);
        expect(result.impact).toBe(4);
    });
});