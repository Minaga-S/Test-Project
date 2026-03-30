/**
 * Recommendation Service
 */

const { generateRecommendations } = require('../config/ai-config');
const { THREAT_KNOWLEDGE_BASE } = require('../utils/constants');
const logger = require('../utils/logger');

class RecommendationService {
    /**
     * Generate recommendations for a threat
     */
    async generateRecommendations(threatType, threatDetails) {
        try {
            const aiRecommendations = await generateRecommendations(threatType, threatDetails);

            if (Array.isArray(aiRecommendations) && aiRecommendations.length > 0) {
                logger.info(`AI recommendations generated for threat: ${threatType}`);
                return this.toRecommendationArray(aiRecommendations);
            }

            logger.info(`Using knowledge base recommendations for threat: ${threatType}`);
            const fallbackRecommendations = this.getKnowledgeBaseRecommendations(threatType);
            return this.toRecommendationArray(fallbackRecommendations);
        } catch (error) {
            logger.error(`Recommendation generation error: ${error.message}`);
            const fallbackRecommendations = this.getKnowledgeBaseRecommendations(threatType);
            return this.toRecommendationArray(fallbackRecommendations);
        }
    }

    /**
     * Always normalize recommendation payloads into string arrays.
     */
    toRecommendationArray(payload) {
        if (!payload) {
            return [];
        }

        if (Array.isArray(payload)) {
            return payload
                .map((item) => String(item || '').trim())
                .filter(Boolean);
        }

        if (Array.isArray(payload.all)) {
            return payload.all
                .map((item) => String(item || '').trim())
                .filter(Boolean);
        }

        if (Array.isArray(payload.recommendations)) {
            return payload.recommendations
                .map((item) => {
                    if (typeof item === 'string') {
                        return item.trim();
                    }

                    if (item && typeof item.text === 'string') {
                        return item.text.trim();
                    }

                    return '';
                })
                .filter(Boolean);
        }

        return [];
    }

    /**
     * Get recommendations from knowledge base
     */
    getKnowledgeBaseRecommendations(threatType) {
        const threatEntry = THREAT_KNOWLEDGE_BASE.find((t) => t.threatType === threatType);

        if (!threatEntry) {
            return this.getGenericRecommendations();
        }

        return threatEntry.mitigationSteps;
    }

    /**
     * Get generic recommendations
     */
    getGenericRecommendations() {
        return [
            'Implement multi-factor authentication (MFA)',
            'Keep all systems and software up to date',
            'Regular backup and disaster recovery testing',
            'Employee cybersecurity awareness training',
            'Implement network segmentation',
            'Enable logging and monitoring',
            'Regular security assessments',
        ];
    }

    /**
     * Get recommendation priority level
     */
    getRecommendationPriority(riskScore) {
        if (riskScore >= 13) return 'Critical - Implement immediately';
        if (riskScore >= 9) return 'High - Implement within 1 week';
        if (riskScore >= 5) return 'Medium - Implement within 2 weeks';
        return 'Low - Plan implementation';
    }

    /**
     * Get action items
     */
    getActionItems(recommendations, riskScore) {
        return {
            priority: this.getRecommendationPriority(riskScore),
            items: recommendations.map((rec, index) => ({
                id: `ACTION-${Date.now()}-${index}`,
                description: rec,
                status: 'Pending',
                dueDate: this.calculateDueDate(riskScore, index),
                assignedTo: 'Team Lead',
            })),
        };
    }

    /**
     * Calculate due date based on priority
     */
    calculateDueDate(riskScore, index) {
        const baseDate = new Date();

        if (riskScore >= 13) {
            return new Date(baseDate.getTime() + (index + 1) * 24 * 60 * 60 * 1000);
        }

        if (riskScore >= 9) {
            return new Date(baseDate.getTime() + (index + 1) * 7 * 24 * 60 * 60 * 1000);
        }

        return new Date(baseDate.getTime() + (index + 1) * 14 * 24 * 60 * 60 * 1000);
    }
}

module.exports = new RecommendationService();
