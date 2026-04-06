/**
 * Threat Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.

const threatService = require('../services/threatClassificationService');
const nistThreatIntelService = require('../services/nistThreatIntelService');
const Threat = require('../models/Threat');
const logger = require('../utils/logger');

class ThreatController {
    /**
     * Analyze threat - AI-powered with live threat intelligence
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
     * Get threat types available in threat intelligence database
     */
    async getThreatTypes(req, res, next) {
        try {
            const threatTypes = nistThreatIntelService.getAllThreatTypes();

            res.json({
                success: true,
                threatTypes,
                count: threatTypes.length,
                source: 'NIST Threat Intelligence',
            });

        } catch (error) {
            logger.error('Get threat types error:', error.message);
            next(error);
        }
    }

    /**
     * Get threat details with NIST mapping
     */
    async getThreatDetails(req, res, next) {
        try {
            const { threatType } = req.params;

            const validTypes = nistThreatIntelService.getAllThreatTypes();
            if (!validTypes.includes(threatType)) {
                return res.status(404).json({
                    success: false,
                    message: 'Threat type not found in threat intelligence database',
                });
            }

            const nistMapping = nistThreatIntelService.getNISTMapping(threatType);
            const characteristics = nistThreatIntelService.getThreatCharacteristics(threatType);

            res.json({
                success: true,
                threat: {
                    threatType,
                    ...nistMapping,
                    ...characteristics,
                    source: 'NIST Threat Intelligence Database',
                    description: `Threat profile for ${threatType} based on NIST threat intelligence and CVE analysis`,
                },
            });

        } catch (error) {
            logger.error('Get threat details error:', error.message);
            next(error);
        }
    }
}

module.exports = new ThreatController();
