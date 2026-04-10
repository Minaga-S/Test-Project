/**
 * Threat Classification Service
 */
// NOTE: Service layer: contains core business logic used by controllers.

const { analyzeThreatWithAI } = require('../config/ai-config');
const nistThreatIntelService = require('./nistThreatIntelService');
const logger = require('../utils/logger');

// These keywords indicate the report may describe ransomware behavior.
const RANSOMWARE_KEYWORDS = ['ransomware', 'encrypted', 'locked'];

// These phrases indicate ransomware is disrupting core hotel operations.
const RANSOMWARE_SEVERE_INDICATORS = [
    'backup',
    'payment',
    'reservation',
    'admin account',
    'disabled protection',
    'cannot process',
];

const DETERMINISTIC_RISK_SCORING = process.env.DETERMINISTIC_RISK_SCORING !== 'false';

class ThreatClassificationService {
    /**
     * Classify threat based on description and security context
     * Enhanced with live CVE data and NIST threat mapping
     */
    async classifyThreat(description, securityContext = null) {
        try {
            // Extract CVE data from security context for threat analysis
            const cveList = this.extractCVEsFromContext(securityContext);

            // Get AI analysis with enhanced context
            const aiAnalysis = await analyzeThreatWithAI(description, securityContext);

            // Classify threat using live threat intelligence
            const threatIntelligence = await nistThreatIntelService.classifyThreatFromCVEs(cveList, description);

            // Blend AI analysis with threat intelligence
            const baseClassification = this.blendAnalysis(aiAnalysis, threatIntelligence, securityContext, cveList);

            // Guardrail: keep severe ransomware descriptions from being scored too low.
            const classification = this.applyRansomwareSeverityGuardrail(description, baseClassification);

            logger.info(`Threat classified: ${classification.threatType} (source: ${classification.source || 'ai+intel'})`);

            return classification;
        } catch (error) {
            logger.error('Threat classification error:', error.message);
            return await this.fallbackClassification(description, securityContext);
        }
    }

    /**
     * Extract CVE data from security context
     */
    extractCVEsFromContext(securityContext) {
        if (!securityContext || !securityContext.cve || !Array.isArray(securityContext.cve.matches)) {
            return [];
        }

        return securityContext.cve.matches.map(match => ({
            id: match.cveId || match.id,
            description: match.description || match.summary || '',
            severity: match.severity || match.baseSeverity || 'UNKNOWN',
            baseScore: match.baseScore || parseFloat(match.score) || 0,
        }));
    }

    getSeverityCounts(cveList = []) {
        return cveList.reduce((accumulator, cve) => {
            const severity = String(cve?.severity || 'UNKNOWN').toUpperCase();
            if (!accumulator[severity]) {
                accumulator[severity] = 0;
            }

            accumulator[severity] += 1;
            return accumulator;
        }, {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            UNKNOWN: 0,
        });
    }

    deriveRiskFromCveSeverity(cveList = [], defaultLikelihood = 2, defaultImpact = 2) {
        const severityCounts = this.getSeverityCounts(cveList);

        if (severityCounts.CRITICAL > 0) {
            return {
                likelihood: 4,
                impact: 4,
            };
        }

        if (severityCounts.HIGH >= 10) {
            return {
                likelihood: 4,
                impact: Math.max(defaultImpact, 3),
            };
        }

        if (severityCounts.HIGH > 0) {
            return {
                likelihood: Math.max(defaultLikelihood, 3),
                impact: Math.max(defaultImpact, 3),
            };
        }

        if (severityCounts.MEDIUM > 0) {
            return {
                likelihood: Math.max(defaultLikelihood, 3),
                impact: Math.max(defaultImpact, 2),
            };
        }

        return {
            likelihood: Math.max(1, Math.min(4, defaultLikelihood || 2)),
            impact: Math.max(1, Math.min(4, defaultImpact || 2)),
        };
    }

    /**
     * Blend AI analysis with threat intelligence
     */
    blendAnalysis(aiAnalysis, threatIntel, securityContext, cveList = []) {
        const threatType = aiAnalysis.threatType || threatIntel.threatType || 'Unknown';
        const nistMapping = nistThreatIntelService.getNISTMapping(threatType);
        const threatCharacteristics = nistThreatIntelService.getThreatCharacteristics(threatType);
        const fallbackLikelihood = aiAnalysis.likelihood || threatCharacteristics.likelihood || 2;
        const fallbackImpact = aiAnalysis.impact || threatCharacteristics.impact || 2;
        const deterministicRisk = DETERMINISTIC_RISK_SCORING
            ? this.deriveRiskFromCveSeverity(cveList, fallbackLikelihood, fallbackImpact)
            : {
                likelihood: Math.max(1, Math.min(4, fallbackLikelihood)),
                impact: Math.max(1, Math.min(4, fallbackImpact)),
            };

        return {
            threatType,
            threatCategory: aiAnalysis.threatCategory || threatIntel.threatType, 
            affectedAsset: aiAnalysis.affectedAsset || threatCharacteristics.assets?.[0] || 'General',
            confidence: Math.max(aiAnalysis.confidence || 0, threatIntel.confidence || 0),
            likelihood: deterministicRisk.likelihood,
            impact: deterministicRisk.impact,
            nistFunctions: aiAnalysis.nistFunctions || nistMapping.functions || [],
            nistControls: aiAnalysis.nistControls || nistMapping.controls || [],
            mitigationSteps: aiAnalysis.mitigationSteps || [],
            liveContextApplied: Boolean(securityContext?.cve?.matches?.length > 0),
            discoveredServices: securityContext?.services || [],
            cveCount: securityContext?.cve?.totalMatches || 0,
            source: 'ai_with_threat_intel',
        };
    }

    getRansomwareSignal(description) {
        const lowerDesc = String(description || '').toLowerCase();
        const hasRansomwareKeywords = RANSOMWARE_KEYWORDS.some((keyword) => lowerDesc.includes(keyword));
        const severeIndicatorCount = RANSOMWARE_SEVERE_INDICATORS
            .filter((indicator) => lowerDesc.includes(indicator))
            .length;

        return {
            hasRansomwareKeywords,
            severeIndicatorCount,
            isCriticalRansomware: severeIndicatorCount >= 2,
        };
    }

    applyRansomwareSeverityGuardrail(description, classification) {
        const signal = this.getRansomwareSignal(description);
        const normalizedThreatType = String(classification.threatType || '').toLowerCase();
        const shouldTreatAsRansomware = signal.hasRansomwareKeywords || normalizedThreatType === 'ransomware';

        if (!shouldTreatAsRansomware) {
            return classification;
        }

        if (signal.isCriticalRansomware) {
            return {
                ...classification,
                threatType: 'Ransomware',
                threatCategory: 'Malicious Software',
                confidence: Math.max(classification.confidence || 0, 85),
                likelihood: Math.max(classification.likelihood || 1, 4),
                impact: Math.max(classification.impact || 1, 4),
            };
        }

        return {
            ...classification,
            threatType: 'Ransomware',
            threatCategory: 'Malicious Software',
            confidence: Math.max(classification.confidence || 0, 75),
            likelihood: Math.max(classification.likelihood || 1, 3),
            impact: Math.max(classification.impact || 1, 4),
        };
    }

    async fallbackClassification(description, securityContext = null) {
        logger.warn('Using fallback threat classification');
        const cveList = this.extractCVEsFromContext(securityContext);

        if (cveList.length > 0) {
            const intelClassification = await nistThreatIntelService.classifyThreatFromCVEs(cveList, description);
            const threatType = intelClassification.threatType || 'Unauthorized Access';
            const nistMapping = nistThreatIntelService.getNISTMapping(threatType);
            const threatCharacteristics = nistThreatIntelService.getThreatCharacteristics(threatType);
            const deterministicRisk = this.deriveRiskFromCveSeverity(
                cveList,
                threatCharacteristics.likelihood || 2,
                threatCharacteristics.impact || 2
            );

            return {
                threatType,
                threatCategory: threatType,
                confidence: Math.max(65, intelClassification.confidence || 0),
                likelihood: deterministicRisk.likelihood,
                impact: deterministicRisk.impact,
                nistFunctions: nistMapping.functions || [],
                nistControls: nistMapping.controls || [],
                mitigationSteps: [],
                liveContextApplied: true,
                discoveredServices: securityContext?.liveScan?.services || [],
                cveCount: cveList.length,
                source: 'fallback_cve_intel',
            };
        }

        const lowerDesc = String(description || '').toLowerCase();

        if (lowerDesc.includes('email') || lowerDesc.includes('link') || lowerDesc.includes('clicked')) {
            return {
                threatType: 'Phishing',
                threatCategory: 'Social Engineering',
                confidence: 60,
                likelihood: 3,
                impact: 2,
                source: 'fallback_keyword',
            };
        }

        if (lowerDesc.includes('slow') || lowerDesc.includes('popup') || lowerDesc.includes('crash')) {
            return {
                threatType: 'Malware',
                threatCategory: 'Malicious Software',
                confidence: 60,
                likelihood: 3,
                impact: 3,
                source: 'fallback_keyword',
            };
        }

        const ransomwareSignal = this.getRansomwareSignal(description);
        if (ransomwareSignal.hasRansomwareKeywords) {
            return {
                threatType: 'Ransomware',
                threatCategory: 'Malicious Software',
                confidence: ransomwareSignal.isCriticalRansomware ? 85 : 75,
                likelihood: ransomwareSignal.isCriticalRansomware ? 4 : 3,
                impact: 4,
                source: 'fallback_ransomware',
            };
        }

        if (lowerDesc.includes('wifi') || lowerDesc.includes('network') || lowerDesc.includes('ddos')) {
            return {
                threatType: 'DDoS',
                threatCategory: 'Network Attack',
                confidence: 50,
                likelihood: 2,
                impact: 3,
                source: 'fallback_keyword',
            };
        }

        return {
            threatType: 'Unauthorized Access',
            threatCategory: 'Access Control',
            confidence: 50,
            likelihood: 2,
            impact: 2,
            source: 'fallback_default',
        };
    }

    getConfidenceLevel(confidence) {
        if (confidence >= 85) return 'Very High';
        if (confidence >= 70) return 'High';
        if (confidence >= 50) return 'Medium';
        return 'Low';
    }

    getValidThreatTypes() {
        return nistThreatIntelService.getAllThreatTypes();
    }

    isValidThreatType(threatType) {
        return this.getValidThreatTypes().includes(threatType);
    }
}

module.exports = new ThreatClassificationService();
