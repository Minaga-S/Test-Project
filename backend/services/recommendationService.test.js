jest.mock('../config/ai-config', () => ({
    generateRecommendations: jest.fn(),
}));

const { generateRecommendations } = require('../config/ai-config');
const recommendationService = require('./recommendationService');

describe('recommendationService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return AI recommendations as trimmed string array', async () => {
        generateRecommendations.mockResolvedValue([' Step 1 ', 'Step 2']);

        const recommendations = await recommendationService.generateRecommendations('Phishing', { likelihood: 3 });

        expect(recommendations).toEqual(['Step 1', 'Step 2']);
    });

    it('should return knowledge-base mitigation steps as string array when AI fails', async () => {
        generateRecommendations.mockRejectedValue(new Error('quota exceeded'));

        const recommendations = await recommendationService.generateRecommendations('Phishing', { likelihood: 3 });

        expect(Array.isArray(recommendations)).toBe(true);
    });

    it('should return generic recommendations when threat type is unknown and AI fails', async () => {
        generateRecommendations.mockRejectedValue(new Error('quota exceeded'));

        const recommendations = await recommendationService.generateRecommendations('Unknown Threat', { likelihood: 2 });

        expect(recommendations.length > 0).toBe(true);
    });
});
