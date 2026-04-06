/**
 * NIST Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.

const Incident = require('../models/Incident');
const { NIST_FUNCTIONS } = require('../utils/constants');
const nistThreatIntelService = require('../services/nistThreatIntelService');
const nistService = require('../services/nistMappingService');
const recommendationService = require('../services/recommendationService');
const logger = require('../utils/logger');

class NISTController {
    async getFunctions(req, res, next) {
        try {
            const functions = nistService.getAllFunctions() || NIST_FUNCTIONS;
            res.json({ success: true, functions });
        } catch (error) {
            logger.error('Get NIST functions error:', error.message);
            next(error);
        }
    }

    async getControlsForThreatType(req, res, next) {
        try {
            const { threatType } = req.params;
            const mapping = nistThreatIntelService.getNISTMapping(threatType);
            const controls = mapping.controls || [];
            
            res.json({ 
                success: true, 
                controls,
                source: 'NIST Threat Intelligence',
            });
        } catch (error) {
            logger.error('Get controls for threat type error:', error.message);
            next(error);
        }
    }

    async getMappingForIncident(req, res, next) {
        try {
            const incident = await Incident.findOne({
                _id: req.params.incidentId,
                userId: req.user.userId,
            });

            if (!incident) {
                return res.status(404).json({ success: false, message: 'Incident not found' });
            }

            res.json({
                success: true,
                mapping: {
                    functions: incident.nistFunctions || [],
                    controls: incident.nistControls || [],
                },
            });
        } catch (error) {
            logger.error('Get NIST mapping for incident error:', error.message);
            next(error);
        }
    }

    async getRecommendationsForThreatType(req, res, next) {
        try {
            const { threatType } = req.params;
            const recommendations = recommendationService.getThreatIntelRecommendations(threatType);
            
            res.json({ 
                success: true, 
                recommendations,
                source: 'NIST Threat Intelligence + AI',
            });
        } catch (error) {
            logger.error('Get recommendations for threat type error:', error.message);
            next(error);
        }
    }
}

module.exports = new NISTController();
