/**
 * Threat Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.


const threatService = require('../services/threatClassificationService');
const { THREAT_KNOWLEDGE_BASE, THREAT_TYPES } = require('../utils/constants');
const Threat = require('../models/Threat');
const ThreatKnowledgeBase = require('../models/ThreatKnowledgeBase');
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

            // Persist analysis history for audit and reporting.
            await Threat.create({
                ...analysis,
                sourceDescription: description,
                userId: req.user.userId,
            });

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
     * Classify threat (alias for analyze endpoint)
     */
    async classifyThreat(req, res, next) {
        return this.analyzeThreat(req, res, next);
    }

    /**
     * Get threat knowledge base
     */
    async getKnowledgeBase(req, res, next) {
        try {
            const storedKnowledge = await ThreatKnowledgeBase.find().sort({ threatType: 1 });
            const knowledgeBase = storedKnowledge.length > 0 ? storedKnowledge : THREAT_KNOWLEDGE_BASE;

            res.json({
                success: true,
                knowledgeBase,
                count: knowledgeBase.length,
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
            const storedKnowledge = await ThreatKnowledgeBase.find({}, { threatCategory: 1, _id: 0 });
            const source = storedKnowledge.length > 0 ? storedKnowledge : THREAT_KNOWLEDGE_BASE;
            const categories = [...new Set(source.map((t) => t.threatCategory))];

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

            const threatDetails = await ThreatKnowledgeBase.findOne({ threatType })
                || THREAT_KNOWLEDGE_BASE.find((t) => t.threatType === threatType);

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
