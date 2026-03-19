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
            // Try to get AI-generated recommendations
            const aiRecommendations = await generateRecommendations(threatType, threatDetails);

            if (aiRecommendations && aiRecommendations.length > 0) {
                logger.info(`AI recommendations generated for threat: ${threatType}`);
                return this.prioritizeRecommendations(aiRecommendations, threatDetails.likelihood);
            }

            // Fallback to knowledge base
            logger.info(`Using knowledge base recommendations for threat: ${threatType}`);
            return this.getKnowledgeBaseRecommendations(threatType, threatDetails);

        } catch (error) {
            logger.error('Recommendation generation error:', error.message);
            return this.getKnowledgeBaseRecommendations(threatType, threatDetails);
        }
    }

    /**
     * Get recommendations from knowledge base
     */
    getKnowledgeBaseRecommendations(threatType, threatDetails) {
        const threatEntry = THREAT_KNOWLEDGE_BASE.find(t => t.threatType === threatType);

        if (!threatEntry) {
            return this.getGenericRecommendations();
        }

        return {
            immediate: threatEntry.mitigationSteps.slice(0, 2),
            shortTerm: threatEntry.mitigationSteps.slice(2, 4),
            longTerm: this.getLongTermRecommendations(threatType),
            all: threatEntry.mitigationSteps,
        };
    }

    /**
     * Prioritize recommendations based on risk
     */
    prioritizeRecommendations(recommendations, likelihood) {
        const priority = likelihood >= 3 ? 'immediate' : 'standard';

        return {
            priority,
            recommendations: recommendations.map((rec, index) => ({
                id: index + 1,
                text: rec,
                priority: index < 3 ? 'High' : 'Medium',
                category: this.categorizeRecommendation(rec),
            })),
            all: recommendations,
        };
    }

    /**
     * Categorize recommendation
     */
    categorizeRecommendation(recommendation) {
        const lower = recommendation.toLowerCase();

        if (lower.includes('password') || lower.includes('authentication') || lower.includes('mfa')) {
            return 'Access Control';
        }

        if (lower.includes('patch') || lower.includes('update') || lower.includes('software')) {
            return 'Patch Management';
        }

        if (lower.includes('backup') || lower.includes('recovery')) {
            return 'Backup & Recovery';
        }

        if (lower.includes('training') || lower.includes('awareness') || lower.includes('educate')) {
            return 'Training & Awareness';
        }

        if (lower.includes('monitor') || lower.includes('log') || lower.includes('detect')) {
            return 'Detection & Monitoring';
        }

        if (lower.includes('firewall') || lower.includes('network') || lower.includes('filter')) {
            return 'Network Security';
        }

        if (lower.includes('isolate') || lower.includes('disconnect') || lower.includes('quarantine')) {
            return 'Incident Response';
        }

        return 'General Security';
    }

    /**
     * Get long-term recommendations
     */
    getLongTermRecommendations(threatType) {
        const longTermMap = {
            'Phishing': [
                'Implement DMARC, SPF, and DKIM email authentication',
                'Establish cybersecurity governance framework',
                'Regular security audits and assessments',
            ],
            'Malware': [
                'Deploy endpoint detection and response (EDR) solutions',
                'Establish secure development practices',
                'Regular vulnerability assessments',
            ],
            'Ransomware': [
                'Implement immutable backup solutions',
                'Establish Business Continuity plan',
                'Regular tabletop exercises and drills',
            ],
            'DDoS': [
                'Implement DDoS mitigation service',
                'Establish ISP coordination procedures',
                'Regular incident response training',
            ],
            'Unauthorized Access': [
                'Implement Zero Trust security model',
                'Regular access reviews and cleanup',
                'Implement privileged access management (PAM)',
            ],
        };

        return longTermMap[threatType] || this.getGenericLongTermRecommendations();
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
     * Get generic long-term recommendations
     */
    getGenericLongTermRecommendations() {
        return [
            'Establish a cybersecurity governance framework',
            'Implement security operations center (SOC)',
            'Regular penetration testing and assessments',
            'Incident response plan and testing',
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
            return new Date(baseDate.getTime() + (index + 1) * 24 * 60 * 60 * 1000); // Days
        }

        if (riskScore >= 9) {
            return new Date(baseDate.getTime() + (index + 1) * 7 * 24 * 60 * 60 * 1000); // Weeks
        }

        return new Date(baseDate.getTime() + (index + 1) * 14 * 24 * 60 * 60 * 1000); // 2 weeks
    }
}

module.exports = new RecommendationService();