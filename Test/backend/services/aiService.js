/**
 * AI Service - Wrapper for AI operations
 */

const { analyzeThreatWithAI, generateRecommendations } = require('../config/ai-config');
const logger = require('../utils/logger');

class AIService {
    /**
     * Analyze incident with AI
     */
    async analyzeIncident(description) {
        try {
            logger.info('Starting AI analysis for incident');

            const analysis = await analyzeThreatWithAI(description);

            return {
                success: true,
                analysis,
                timestamp: new Date(),
            };

        } catch (error) {
            logger.error('AI analysis error:', error.message);
            throw new Error('Failed to analyze incident with AI');
        }
    }

    /**
     * Generate AI recommendations
     */
    async generateAIRecommendations(threatType, threatDetails) {
        try {
            logger.info(`Generating AI recommendations for threat: ${threatType}`);

            const recommendations = await generateRecommendations(threatType, threatDetails);

            return {
                success: true,
                recommendations,
                timestamp: new Date(),
            };

        } catch (error) {
            logger.error('AI recommendation generation error:', error.message);
            throw new Error('Failed to generate recommendations');
        }
    }

    /**
     * Batch analyze incidents
     */
    async batchAnalyzeIncidents(incidents) {
        try {
            const results = [];

            for (const incident of incidents) {
                try {
                    const analysis = await this.analyzeIncident(incident.description);
                    results.push({
                        incidentId: incident._id,
                        ...analysis,
                    });
                } catch (error) {
                    logger.error(`Batch analysis error for incident ${incident._id}:`, error.message);
                    results.push({
                        incidentId: incident._id,
                        success: false,
                        error: error.message,
                    });
                }
            }

            return results;

        } catch (error) {
            logger.error('Batch analysis error:', error.message);
            throw error;
        }
    }

    /**
     * Check AI service status
     */
    async checkServiceStatus() {
        try {
            const testDescription = 'Test threat analysis';
            await analyzeThreatWithAI(testDescription);

            return {
                status: 'operational',
                timestamp: new Date(),
            };

        } catch (error) {
            logger.error('AI service status check failed:', error.message);
            return {
                status: 'error',
                error: error.message,
                timestamp: new Date(),
            };
        }
    }
}

module.exports = new AIService();