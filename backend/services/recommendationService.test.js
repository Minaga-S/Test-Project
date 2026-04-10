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

    it('should add explicit NIST source labels to AI recommendations without a source tag', async () => {
        generateRecommendations.mockResolvedValue(['Isolate affected hosts']);

        const result = await recommendationService.generateRecommendations('Ransomware', {});

        expect(result[0]).toContain('[NIST | PR.AC | Protect]');
    });

    it('should keep recommendations already labeled as NIST', async () => {
        generateRecommendations.mockResolvedValue(['[NIST | PR.AC | Protect] Enforce MFA for admin logins']);

        const result = await recommendationService.generateRecommendations('Unauthorized Access', {});

        expect(result[0]).toBe('[NIST | PR.AC | Protect] Enforce MFA for admin logins');
    });

    it('should label non-NIST tagged AI recommendations as other source', async () => {
        generateRecommendations.mockResolvedValue(['[CISA] Block malicious domains at the email gateway']);

        const aligned = recommendationService.alignRecommendationsToNist('Phishing', ['[CISA] Block malicious domains at the email gateway']);

        expect(aligned[0]).toBe('[Other Source: CISA] Block malicious domains at the email gateway');
    });

    it('should return fallback recommendations with explicit NIST labels when AI returns empty output', async () => {
        generateRecommendations.mockResolvedValue([]);

        const result = await recommendationService.generateRecommendations('Phishing', {});

        expect(result.every((item) => /^\[NIST\s\|/.test(item))).toBe(true);
    });

    it('should return generic recommendations when no NIST recommendations can be prioritized', async () => {
        const prioritized = recommendationService.prioritizeRecommendations('Phishing', ['[Vendor Advisory] Rotate secrets now']);

        expect(prioritized.every((item) => /^\[General Recommendation\]/.test(item))).toBe(true);
    });

    it('should repair clipped recommendation text before applying NIST labels', async () => {
        generateRecommendations.mockResolvedValue([
            "Immediately isolate the server (192.168.204.128) from the network to contain potential threats and investigate its purpose, given the severe vulnerabilities and 'no",
        ]);

        const result = await recommendationService.generateRecommendations('Phishing', {});

        expect(result[0]).toContain('no critical findings reported.');
    });

    it('should return CVE database-driven recommendations when AI returns empty and CVE context exists', async () => {
        generateRecommendations.mockResolvedValue([]);

        const result = await recommendationService.generateRecommendations('Unauthorized Access', {
            securityContext: {
                cve: {
                    matches: [
                        { cveId: 'CVE-2026-0001', severity: 'CRITICAL', cvssScore: 9.8 },
                        { cveId: 'CVE-2026-0002', severity: 'HIGH', cvssScore: 7.5 },
                    ],
                },
                liveScan: {
                    services: [{ service: 'ssh' }],
                },
            },
        });

        expect(result[0]).toContain('CVE-2026-0001');
    });
});
