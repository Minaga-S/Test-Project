const { generateRecommendations } = require('../config/ai-config');
const nistThreatIntelService = require('./nistThreatIntelService');
const recommendationService = require('./recommendationService');

jest.mock('../config/ai-config', () => ({
    generateRecommendations: jest.fn(),
}));

jest.mock('./nistThreatIntelService', () => ({
    getNISTMapping: jest.fn(),
}));

describe('recommendationService', () => {
    beforeEach(() => {
        jest.clearAllMocks();

        nistThreatIntelService.getNISTMapping.mockReturnValue({
            functions: ['Protect', 'Detect'],
            controls: ['PR.AC', 'DE.CM'],
        });
    });

    it('should add NIST tags to AI recommendations that do not include a control code', async () => {
        generateRecommendations.mockResolvedValue(['Isolate affected hosts']);

        const result = await recommendationService.generateRecommendations('Ransomware', {});

        expect(result[0]).toContain('[PR.AC | Protect]');
    });

    it('should keep AI recommendations that already include a control code unchanged', async () => {
        generateRecommendations.mockResolvedValue(['[PR.AC | Protect] Enforce MFA for admin logins']);

        const result = await recommendationService.generateRecommendations('Unauthorized Access', {});

        expect(result[0]).toBe('[PR.AC | Protect] Enforce MFA for admin logins');
    });

    it('should return fallback recommendations with NIST tags when AI returns empty output', async () => {
        generateRecommendations.mockResolvedValue([]);

        const result = await recommendationService.generateRecommendations('Phishing', {});

        expect(result.every((item) => /\[[A-Z]{2}\.[A-Z]{2} \|/.test(item))).toBe(true);
    });

    it('should repair clipped recommendation text before applying NIST tags', async () => {
        generateRecommendations.mockResolvedValue([
            "Immediately isolate the server (192.168.204.128) from the network to contain potential threats and investigate its purpose, given the severe vulnerabilities and 'no",
        ]);

        const result = await recommendationService.generateRecommendations('Phishing', {});

        expect(result[0]).toContain('no critical findings reported.');
    });
});