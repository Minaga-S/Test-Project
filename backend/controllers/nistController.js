/**
 * NIST Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.


const Incident = require('../models/Incident');
const ThreatKnowledgeBase = require('../models/ThreatKnowledgeBase');
const { NIST_FUNCTIONS, THREAT_KNOWLEDGE_BASE } = require('../utils/constants');
const nistService = require('../services/nistMappingService');
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
            const threat = await ThreatKnowledgeBase.findOne({ threatType })
                || THREAT_KNOWLEDGE_BASE.find((t) => t.threatType === threatType);

            const controls = threat ? threat.nistControls : [];
            res.json({ success: true, controls });
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
            const threat = await ThreatKnowledgeBase.findOne({ threatType })
                || THREAT_KNOWLEDGE_BASE.find((t) => t.threatType === threatType);

            const recommendations = threat ? threat.mitigationSteps : [];
            res.json({ success: true, recommendations });
        } catch (error) {
            logger.error('Get recommendations for threat type error:', error.message);
            next(error);
        }
    }
}

module.exports = new NISTController();

