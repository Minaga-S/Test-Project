/**
 * Threat Classification Service
 */
// NOTE: Service layer: contains core business logic used by controllers.


const { analyzeThreatWithAI } = require('../config/ai-config');
const { THREAT_KNOWLEDGE_BASE } = require('../utils/constants');
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
     * Classify threat based on description
     */
    async classifyThreat(description) {
        try {
            const aiAnalysis = await analyzeThreatWithAI(description);
            const baseClassification = this.enrichThreatData(aiAnalysis);

            // Guardrail: keep severe ransomware descriptions from being scored too low.
            const classification = this.applyRansomwareSeverityGuardrail(description, baseClassification);

            logger.info(`Threat classified: ${classification.threatType}`);

            return classification;
        } catch (error) {
            logger.error('Threat classification error:', error.message);
            return this.fallbackClassification(description);
        }
    }

    /**
     * Enrich threat data with knowledge base information
     */
    enrichThreatData(aiAnalysis) {
        const knowledgeEntry = THREAT_KNOWLEDGE_BASE.find(
            (entry) => entry.threatType === aiAnalysis.threatType
        );

        return {
            threatType: aiAnalysis.threatType || 'Unknown',
            threatCategory: aiAnalysis.threatCategory || 'Other',
            affectedAsset: aiAnalysis.affectedAsset || 'General',
            confidence: aiAnalysis.confidence || 75,
            likelihood: Math.max(1, Math.min(4, aiAnalysis.likelihood || 2)),
            impact: Math.max(1, Math.min(4, aiAnalysis.impact || 2)),
            nistFunctions: aiAnalysis.nistFunctions || [],
            nistControls: aiAnalysis.nistControls || [],
            mitigationSteps: aiAnalysis.mitigationSteps || [],
            knowledgeBase: knowledgeEntry || null,
        };
    }

    // Detect ransomware signals and how severe they are in the incident text.
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

    // Enforce minimum scores for ransomware so AI underestimation does not hide real risk.
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

    /**
     * Fallback classification if AI fails
     */
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
            };
        }

        if (lowerDesc.includes('slow') || lowerDesc.includes('popup') || lowerDesc.includes('crash')) {
            return {
                threatType: 'Malware',
                threatCategory: 'Malicious Software',
                confidence: 60,
                likelihood: 3,
                impact: 3,
            };
        }

        const ransomwareSignal = this.getRansomwareSignal(description);

        if (ransomwareSignal.hasRansomwareKeywords) {
            const isCriticalRansomware = ransomwareSignal.isCriticalRansomware;

            return {
                threatType: 'Ransomware',
                threatCategory: 'Malicious Software',
                confidence: isCriticalRansomware ? 85 : 75,
                likelihood: isCriticalRansomware ? 4 : 3,
                impact: 4,
            };
        }

        if (lowerDesc.includes('wifi') || lowerDesc.includes('network') || lowerDesc.includes('ddos')) {
            return {
                threatType: 'DDoS',
                threatCategory: 'Network Attack',
                confidence: 50,
                likelihood: 2,
                impact: 3,
            };
        }

        // Safe default when no known attack pattern is detected.
        return {
            threatType: 'Unauthorized Access',
            threatCategory: 'Access Control',
            confidence: 50,
            likelihood: 2,
            impact: 2,
        };
    }

    /**
     * Get threat confidence score
     */
    getConfidenceLevel(confidence) {
        if (confidence >= 85) return 'Very High';
        if (confidence >= 70) return 'High';
        if (confidence >= 50) return 'Medium';
        return 'Low';
    }

    /**
     * Validate threat type
     */
    isValidThreatType(threatType) {
        return THREAT_KNOWLEDGE_BASE.some((entry) => entry.threatType === threatType);
    }
}

module.exports = new ThreatClassificationService();

