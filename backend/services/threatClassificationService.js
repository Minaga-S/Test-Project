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
            const baseClassification = this.blendAnalysis(aiAnalysis, threatIntelligence, securityContext);

            // Guardrail: keep severe ransomware descriptions from being scored too low.
            const classification = this.applyRansomwareSeverityGuardrail(description, baseClassification);

            logger.info(`Threat classified: ${classification.threatType} (source: ${classification.source || 'ai+intel'})`);

            return classification;
        } catch (error) {
            logger.error('Threat classification error:', error.message);
            return this.fallbackClassification(description);
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

    /**
     * Blend AI analysis with threat intelligence
     */
    blendAnalysis(aiAnalysis, threatIntel, securityContext) {
        const threatType = aiAnalysis.threatType || threatIntel.threatType || 'Unknown';
        const nistMapping = nistThreatIntelService.getNISTMapping(threatType);
        const threatCharacteristics = nistThreatIntelService.getThreatCharacteristics(threatType);

        return {
            threatType,
            threatCategory: aiAnalysis.threatCategory || threatIntel.threatType, 
            affectedAsset: aiAnalysis.affectedAsset || threatCharacteristics.assets?.[0] || 'General',
            confidence: Math.max(aiAnalysis.confidence || 0, threatIntel.confidence || 0),
            likelihood: Math.max(1, Math.min(4, aiAnalysis.likelihood || threatCharacteristics.likelihood || 2)),
            impact: Math.max(1, Math.min(4, aiAnalysis.impact || threatCharacteristics.impact || 2)),
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

    fallbackClassification(description) {
        logger.warn('Using fallback threat classification');
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
