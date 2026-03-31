/**
 * Risk Calculation Service
 */
// NOTE: Service layer: contains core business logic used by controllers.


const { RISK_LEVELS } = require('../utils/constants');
const logger = require('../utils/logger');

class RiskCalculationService {
    /**
     * Calculate risk based on likelihood and impact
     */
    calculateRisk(likelihood, impact) {
        try {
            // Validate inputs
            if (!this.isValidScore(likelihood) || !this.isValidScore(impact)) {
                throw new Error('Invalid likelihood or impact score');
            }

            // Core formula: risk score = likelihood x impact.
            // Calculate risk score
            const riskScore = likelihood * impact;

            // Map the numeric score into a business-friendly label (Low/Medium/High/Critical).
            // Determine risk level
            const riskLevel = this.determineRiskLevel(riskScore);

            const result = {
                likelihood,
                impact,
                score: riskScore,
                level: riskLevel.level,
                severity: riskLevel.severity,
                color: riskLevel.color,
                recommendation: this.getRiskRecommendation(riskLevel.level),
            };

            logger.debug(`Risk calculated: score=${riskScore}, level=${riskLevel.level}`);

            return result;

        } catch (error) {
            logger.error('Risk calculation error:', error.message);
            throw error;
        }
    }

    /**
     * Determine risk level based on score
     */
    determineRiskLevel(score) {
        // Score bands are intentionally strict so urgent threats are escalated quickly.
        if (score >= 13) {
            return {
                level: 'Critical',
                severity: 'Immediate action required',
                color: '#c0392b',
                range: [13, 16],
            };
        }

        if (score >= 9) {
            return {
                level: 'High',
                severity: 'Should be addressed soon',
                color: '#e74c3c',
                range: [9, 12],
            };
        }

        if (score >= 5) {
            return {
                level: 'Medium',
                severity: 'Should be monitored',
                color: '#f39c12',
                range: [5, 8],
            };
        }

        return {
            level: 'Low',
            severity: 'Acceptable risk',
            color: '#27ae60',
            range: [1, 4],
        };
    }

    /**
     * Validate score (1-4)
     */
    isValidScore(score) {
        return Number.isInteger(score) && score >= 1 && score <= 4;
    }

    /**
     * Get risk recommendation
     */
    getRiskRecommendation(riskLevel) {
        const recommendations = {
            'Critical': 'Immediate action required. Consider disabling affected systems.',
            'High': 'Address this risk as soon as possible. Prioritize remediation.',
            'Medium': 'Plan mitigation actions. Monitor the situation closely.',
            'Low': 'Monitor the situation. Standard security practices apply.',
        };

        return recommendations[riskLevel] || 'Unknown risk level';
    }

    /**
     * Calculate risk trend
     */
    calculateRiskTrend(previousScore, currentScore) {
        const difference = currentScore - previousScore;

        if (difference > 0) {
            return {
                trend: 'increasing',
                change: difference,
                emoji: '📈',
            };
        }

        if (difference < 0) {
            return {
                trend: 'decreasing',
                change: Math.abs(difference),
                emoji: '📉',
            };
        }

        return {
            trend: 'stable',
            change: 0,
            emoji: '➡️',
        };
    }

    /**
     * Calculate matrix position
     */
    calculateMatrixPosition(likelihood, impact) {
        return {
            x: likelihood,
            y: impact,
            zone: this.getMatrixZone(likelihood, impact),
        };
    }

    /**
     * Get matrix zone (quadrant)
     */
    getMatrixZone(likelihood, impact) {
        if (likelihood <= 2 && impact <= 2) return 'Low Priority Zone';
        if (likelihood <= 2 && impact > 2) return 'Monitor Zone';
        if (likelihood > 2 && impact <= 2) return 'Watch Zone';
        return 'Critical Zone';
    }
}

module.exports = new RiskCalculationService();



