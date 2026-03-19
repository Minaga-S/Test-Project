/**
 * Threat Controller
 */

const threatService = require('../services/threatClassificationService');
const { THREAT_KNOWLEDGE_BASE, THREAT_TYPES } = require('../utils/constants');
const logger = require('../utils/logger');

class ThreatController {
    /**
     * Analyze threat
     */
    async analyzeThreat(req, res, next) {
        try {
            const { description } = req.body;

            if (!description || description.trim().length < 20) {
                return res.status(400).json({
                    success: false,
                    message: 'Description must be at least 20 characters',
                });
            }

            const analysis = await threatService.classifyThreat(description);

            logger.info(`Threat analyzed by user ${req.user.userId}`);

            res.json({
                success: true,
                analysis,
            });

        } catch (error) {
            logger.error('Analyze threat error:', error.message);
            next(error);
        }
    }

    /**
     * Get threat knowledge base
     */
    async getKnowledgeBase(req, res, next) {
        try {
            res.json({
                success: true,
                knowledgeBase: THREAT_KNOWLEDGE_BASE,
                count: THREAT_KNOWLEDGE_BASE.length,
            });

        } catch (error) {
            logger.error('Get knowledge base error:', error.message);
            next(error);
        }
    }

    /**
     * Get threat categories
     */
    async getThreatCategories(req, res, next) {
        try {
            const categories = [...new Set(THREAT_KNOWLEDGE_BASE.map(t => t.threatCategory))];

            res.json({
                success: true,
                categories,
                count: categories.length,
            });

        } catch (error) {
            logger.error('Get categories error:', error.message);
            next(error);
        }
    }

    /**
     * Get threat types
     */
    async getThreatTypes(req, res, next) {
        try {
            res.json({
                success: true,
                threatTypes: THREAT_TYPES,
                count: THREAT_TYPES.length,
            });

        } catch (error) {
            logger.error('Get threat types error:', error.message);
            next(error);
        }
    }

    /**
     * Get threat details
     */
    async getThreatDetails(req, res, next) {
        try {
            const { threatType } = req.params;

            const threatDetails = THREAT_KNOWLEDGE_BASE.find(t => t.threatType === threatType);

            if (!threatDetails) {
                return res.status(404).json({
                    success: false,
                    message: 'Threat type not found',
                });
            }

            res.json({
                success: true,
                threat: threatDetails,
            });

        } catch (error) {
            logger.error('Get threat details error:', error.message);
            next(error);
        }
    }
}

module.exports = new ThreatController();