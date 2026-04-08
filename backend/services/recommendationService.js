/**
 * Recommendation Service
 */
// NOTE: Service layer: contains core business logic used by controllers.

const { generateRecommendations } = require('../config/ai-config');
const nistThreatIntelService = require('./nistThreatIntelService');
const logger = require('../utils/logger');

class RecommendationService {
    /**
     * Generate recommendations for a threat using AI and threat intelligence.
     * Every recommendation is normalized into NIST-aligned wording.
     */
    async generateRecommendations(threatType, threatDetails) {
        try {
            const aiRecommendations = await generateRecommendations(threatType, threatDetails);

            if (Array.isArray(aiRecommendations) && aiRecommendations.length > 0) {
                logger.info(`AI recommendations generated for threat: ${threatType}`);
                const normalizedRecommendations = this.toRecommendationArray(aiRecommendations);
                const prioritizedRecommendations = this.prioritizeRecommendations(threatType, normalizedRecommendations);

                if (prioritizedRecommendations.length > 0) {
                    return prioritizedRecommendations;
                }
            }

            logger.info(`Using threat intelligence recommendations for threat: ${threatType}`);
            const fallbackRecommendations = this.getThreatIntelRecommendations(threatType);
            const normalizedFallback = this.toRecommendationArray(fallbackRecommendations);

            if (normalizedFallback.length > 0) {
                return this.prioritizeRecommendations(threatType, normalizedFallback);
            }

            return this.getGenericRecommendations();
        } catch (error) {
            logger.error(`Recommendation generation error: ${error.message}`);
            const fallbackRecommendations = this.getThreatIntelRecommendations(threatType);
            const normalizedFallback = this.toRecommendationArray(fallbackRecommendations);

            if (normalizedFallback.length > 0) {
                return this.prioritizeRecommendations(threatType, normalizedFallback);
            }

            return this.getGenericRecommendations();
        }
    }

    prioritizeRecommendations(threatType, recommendations) {
        const alignedRecommendations = this.alignRecommendationsToNist(threatType, recommendations);
        const nistRecommendations = alignedRecommendations.filter((item) => this.isNistRecommendation(item));
        const nonNistRecommendations = alignedRecommendations
            .filter((item) => !this.isNistRecommendation(item));

        if (nistRecommendations.length > 0) {
            return [...nistRecommendations, ...nonNistRecommendations];
        }

        return this.getGenericRecommendations();
    }

    /**
     * Normalize recommendation payloads into string arrays.
     */
    toRecommendationArray(payload) {
        if (!payload) return [];

        if (Array.isArray(payload)) {
            return payload
                .map((item) => this.normalizeRecommendationText(item))
                .filter(Boolean);
        }

        if (Array.isArray(payload.all)) {
            return payload.all
                .map((item) => this.normalizeRecommendationText(item))
                .filter(Boolean);
        }

        if (Array.isArray(payload.recommendations)) {
            return payload.recommendations.map(item => {
                if (typeof item === 'string') return this.normalizeRecommendationText(item);
                if (item && typeof item.text === 'string') return this.normalizeRecommendationText(item.text);
                return '';
            }).filter(Boolean);
        }

        return [];
    }

    normalizeRecommendationText(rawText) {
        const collapsedText = String(rawText || '').replace(/\s+/g, ' ').trim();
        if (!collapsedText) {
            return '';
        }

        if (/^\[[^\]]+\]\s+/.test(collapsedText)) {
            return collapsedText;
        }

        // Repair common clipped AI tail where a quoted "no ..." phrase is truncated.
        let normalizedText = collapsedText.replace(/\s+['"]no$/i, ' no critical findings reported');

        if (/['"]$/.test(normalizedText)) {
            normalizedText = normalizedText.slice(0, -1).trim();
        }

        const hasTerminalPunctuation = /[.!?]$/.test(normalizedText);
        if (!hasTerminalPunctuation) {
            normalizedText = `${normalizedText}.`;
        }

        return normalizedText;
    }

    /**
     * Enforce NIST alignment by attaching a control/function context to each recommendation.
     */
    alignRecommendationsToNist(threatType, recommendations) {
        const mapping = nistThreatIntelService.getNISTMapping(threatType) || {};
        const controls = Array.isArray(mapping.controls) && mapping.controls.length > 0
            ? mapping.controls
            : ['PR.AC'];
        const functions = Array.isArray(mapping.functions) && mapping.functions.length > 0
            ? mapping.functions
            : ['Protect'];

        return recommendations
            .map((recommendation, index) => this.toNistAlignedRecommendation(
                recommendation,
                controls[index % controls.length],
                functions[index % functions.length]
            ))
            .filter(Boolean);
    }

    toNistAlignedRecommendation(recommendation, controlCode, functionName) {
        const text = String(recommendation || '').trim();
        if (!text) {
            return '';
        }

        const taggedRecommendation = text.match(/^\[([^\]]+)\]\s*(.*)$/);
        if (taggedRecommendation) {
            const rawLabel = taggedRecommendation[1].trim();
            const message = (taggedRecommendation[2] || '').trim();

            if (this.isNistLabel(rawLabel)) {
                if (/^NIST\b/i.test(rawLabel)) {
                    return text;
                }

                const normalizedMessage = message || text;
                return `[NIST | ${rawLabel}] ${normalizedMessage}`;
            }

            const normalizedMessage = message || text;
            return `[Other Source: ${rawLabel}] ${normalizedMessage}`;
        }

        return `[NIST | ${controlCode} | ${functionName}] ${text}`;
    }

    isNistLabel(label) {
        const normalizedLabel = String(label || '').trim();
        if (!normalizedLabel) {
            return false;
        }

        if (/^NIST\b/i.test(normalizedLabel)) {
            return true;
        }

        return /[A-Z]{2}\.[A-Z]{2}(?:-\d+)?/.test(normalizedLabel);
    }

    isNistRecommendation(recommendation) {
        const text = String(recommendation || '').trim();
        if (!text) {
            return false;
        }

        const taggedRecommendation = text.match(/^\[([^\]]+)\]/);
        if (!taggedRecommendation) {
            return false;
        }

        return this.isNistLabel(taggedRecommendation[1]);
    }

    /**
     * Get recommendations from threat intelligence service.
     */
    getThreatIntelRecommendations(threatType) {
        const mapping = nistThreatIntelService.getNISTMapping(threatType);
        const controls = Array.isArray(mapping.controls) && mapping.controls.length > 0
            ? mapping.controls
            : ['PR.AC', 'DE.CM', 'RS.RP'];
        const functions = Array.isArray(mapping.functions) && mapping.functions.length > 0
            ? mapping.functions
            : ['Protect', 'Detect', 'Respond'];

        return [
            `[NIST | ${controls[0]} | ${functions[0]}] Enforce least-privilege and strong authentication on affected systems`,
            `[NIST | ${controls[1 % controls.length]} | ${functions[1 % functions.length]}] Enable continuous monitoring for threat-specific indicators and anomalies`,
            `[NIST | ${controls[2 % controls.length]} | ${functions[2 % functions.length]}] Patch or harden exposed services identified in the incident context`,
            `[NIST | ${controls[0]} | ${functions[0]}] Validate backup integrity and recovery plans for impacted operations`,
            `[NIST | ${controls[1 % controls.length]} | ${functions[1 % functions.length]}] Document and rehearse incident response tasks mapped to this threat`,
            `[NIST | ${controls[2 % controls.length]} | ${functions[2 % functions.length]}] Deliver targeted staff awareness guidance to prevent recurrence`
        ];
    }

    /**
     * Get generic recommendations as last resort.
     */
    getGenericRecommendations() {
        return [
            '[General Recommendation] Implement multi-factor authentication (MFA)',
            '[General Recommendation] Keep all systems and software up to date',
            '[General Recommendation] Regular backup and disaster recovery testing',
            '[General Recommendation] Employee cybersecurity awareness training',
            '[General Recommendation] Implement network segmentation',
            '[General Recommendation] Enable logging and monitoring',
            '[General Recommendation] Regular security assessments',
        ];
    }

    /**
     * Get recommendation priority level.
     */
    getRecommendationPriority(riskScore) {
        if (riskScore >= 13) return 'Critical - Implement immediately';
        if (riskScore >= 9) return 'High - Implement within 1 week';
        if (riskScore >= 5) return 'Medium - Implement within 2 weeks';
        return 'Low - Plan implementation';
    }

    /**
     * Get action items with due dates.
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
     * Calculate due date based on risk priority.
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
