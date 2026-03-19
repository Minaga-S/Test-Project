/**
 * Threat Classification Service
 */

const { analyzeThreatWithAI } = require('../config/ai-config');
const { THREAT_KNOWLEDGE_BASE, RISK_LEVELS } = require('../utils/constants');
const logger = require('../utils/logger');

class ThreatClassificationService {
    /**
     * Classify threat based on description
     */
    async classifyThreat(description) {
        try {
            // Call AI service for analysis
            const aiAnalysis = await analyzeThreatWithAI(description);

            // Validate and enrich analysis
            const classification = this.enrichThreatData(aiAnalysis);

            logger.info(`Threat classified: ${classification.threatType}`);

            return classification;

        } catch (error) {
            logger.error('Threat classification error:', error.message);
            // Fallback to knowledge base matching
            return this.fallbackClassification(description);
        }
    }

    /**
     * Enrich threat data with knowledge base information
     */
    enrichThreatData(aiAnalysis) {
        const knowledgeEntry = THREAT_KNOWLEDGE_BASE.find(
            t => t.threatType === aiAnalysis.threatType
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

    /**
     * Fallback classification if AI fails
     */
    fallbackClassification(description) {
        logger.warn('Using fallback threat classification');

        const lowerDesc = description.toLowerCase();

        // Simple keyword matching
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

        if (lowerDesc.includes('ransomware') || lowerDesc.includes('encrypted') || lowerDesc.includes('locked')) {
            return {
                threatType: 'Ransomware',
                threatCategory: 'Malicious Software',
                confidence: 75,
                likelihood: 2,
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

        // Default
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
        return THREAT_KNOWLEDGE_BASE.some(t => t.threatType === threatType);
    }
}

module.exports = new ThreatClassificationService();