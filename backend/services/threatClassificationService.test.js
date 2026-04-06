const { analyzeThreatWithAI } = require('../config/ai-config');
const nistThreatIntelService = require('./nistThreatIntelService');
const threatClassificationService = require('./threatClassificationService');

jest.mock('../config/ai-config', () => ({
    analyzeThreatWithAI: jest.fn(),
}));

jest.mock('./nistThreatIntelService', () => ({
    classifyThreatFromCVEs: jest.fn(),
    getNISTMapping: jest.fn(),
    getThreatCharacteristics: jest.fn(),
    getAllThreatTypes: jest.fn(() => ['Unauthorized Access']),
}));

describe('threatClassificationService', () => {
    beforeEach(() => {
        jest.clearAllMocks();

        nistThreatIntelService.getNISTMapping.mockReturnValue({
            functions: ['Identify', 'Protect', 'Detect'],
            controls: ['ID.AM', 'PR.AC', 'DE.CM'],
        });

        nistThreatIntelService.getThreatCharacteristics.mockReturnValue({
            likelihood: 3,
            impact: 3,
            assets: ['Server'],
        });
    });

    it('should return max risk when critical CVEs exist', () => {
        const risk = threatClassificationService.deriveRiskFromCveSeverity([
            { severity: 'CRITICAL' },
        ], 3, 3);

        expect(risk.likelihood).toBe(4);
    });

    it('should set high likelihood when many high-severity CVEs exist', () => {
        const highCves = Array.from({ length: 10 }, () => ({ severity: 'HIGH' }));

        const risk = threatClassificationService.deriveRiskFromCveSeverity(highCves, 2, 2);

        expect(risk.likelihood).toBe(4);
    });

    it('should preserve deterministic impact for critical CVEs during classification', async () => {
        analyzeThreatWithAI.mockResolvedValue({
            threatType: 'Unauthorized Access',
            threatCategory: 'Vulnerability Management',
            affectedAsset: 'Server',
            confidence: 95,
            likelihood: 3,
            impact: 3,
            nistFunctions: ['Identify', 'Protect', 'Detect'],
            nistControls: ['ID.AM', 'PR.AC', 'DE.CM'],
            mitigationSteps: ['Isolate host'],
        });

        nistThreatIntelService.classifyThreatFromCVEs.mockResolvedValue({
            threatType: 'Unauthorized Access',
            confidence: 85,
        });

        const result = await threatClassificationService.classifyThreat('test description', {
            cve: {
                matches: [{ cveId: 'CVE-1', severity: 'CRITICAL' }],
            },
        });

        expect(result.impact).toBe(4);
    });

    it('should keep ai likelihood and impact when there are no CVEs', async () => {
        analyzeThreatWithAI.mockResolvedValue({
            threatType: 'Unauthorized Access',
            threatCategory: 'Vulnerability Management',
            affectedAsset: 'Server',
            confidence: 95,
            likelihood: 3,
            impact: 2,
            nistFunctions: ['Identify', 'Protect', 'Detect'],
            nistControls: ['ID.AM', 'PR.AC', 'DE.CM'],
            mitigationSteps: ['Isolate host'],
        });

        nistThreatIntelService.classifyThreatFromCVEs.mockResolvedValue({
            threatType: 'Unauthorized Access',
            confidence: 85,
        });

        const result = await threatClassificationService.classifyThreat('test description', {
            cve: {
                matches: [],
            },
        });

        expect(result.likelihood).toBe(3);
    });
});
