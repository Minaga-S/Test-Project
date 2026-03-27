/**
 * Incident Controller
 */

const Incident = require('../models/Incident');
const Asset = require('../models/Asset');
const threatService = require('../services/threatClassificationService');
const riskService = require('../services/riskCalculationService');
const recommendationService = require('../services/recommendationService');
const nistService = require('../services/nistMappingService');
const { validateIncident } = require('../utils/validators');
const { generateIncidentId } = require('../utils/constants');
const logger = require('../utils/logger');

class IncidentController {
    /**
     * Create incident
     */
    async createIncident(req, res, next) {
        try {
            const { assetId, description, incidentTime, guestAffected, sensitiveDataInvolved } = req.body;

            // Validate input
            const validation = validateIncident({ assetId, description });
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: validation.errors,
                });
            }

            // Check if asset exists
            const asset = await Asset.findOne({
                _id: assetId,
                userId: req.user.userId,
            });

            if (!asset) {
                return res.status(404).json({
                    success: false,
                    message: 'Asset not found',
                });
            }

            // Analyze threat
            const threatAnalysis = await threatService.classifyThreat(description);

            // Calculate risk
            const riskAssessment = riskService.calculateRisk(
                threatAnalysis.likelihood,
                threatAnalysis.impact
            );

            // Get NIST mappings
            const nistMapping = nistService.getNISTMapping(threatAnalysis.threatType);

            // Generate recommendations
            const recommendations = await recommendationService.generateRecommendations(
                threatAnalysis.threatType,
                threatAnalysis
            );

            // Create incident
            const incident = new Incident({
                incidentId: generateIncidentId(),
                description,
                assetId,
                asset: {
                    _id: asset._id,
                    assetName: asset.assetName,
                    assetType: asset.assetType,
                    location: asset.location,
                },
                threatType: threatAnalysis.threatType,
                threatCategory: threatAnalysis.threatCategory,
                confidence: threatAnalysis.confidence,
                likelihood: threatAnalysis.likelihood,
                impact: threatAnalysis.impact,
                riskScore: riskAssessment.score,
                riskLevel: riskAssessment.level,
                nistFunctions: nistMapping.functions,
                nistControls: nistMapping.controls,
                recommendations,
                userId: req.user.userId,
                guestAffected: guestAffected || false,
                sensitiveDataInvolved: sensitiveDataInvolved || false,
            });

            await incident.save();

            logger.info(`Incident created: ${incident.incidentId} for user ${req.user.userId}`);

            res.status(201).json({
                success: true,
                message: 'Incident created and analyzed',
                incident,
                analysis: {
                    threat: threatAnalysis,
                    risk: riskAssessment,
                    nist: nistMapping,
                    recommendations,
                },
            });

        } catch (error) {
            logger.error('Create incident error:', error.message);
            next(error);
        }
    }

    /**
     * Get all incidents
     */
    async getIncidents(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId })
                .sort({ createdAt: -1 });

            res.json({
                success: true,
                count: incidents.length,
                incidents,
            });

        } catch (error) {
            logger.error('Get incidents error:', error.message);
            next(error);
        }
    }

    /**
     * Get incident by ID
     */
    async getIncident(req, res, next) {
        try {
            const incident = await Incident.findOne({
                _id: req.params.id,
                userId: req.user.userId,
            });

            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            res.json({
                success: true,
                incident,
            });

        } catch (error) {
            logger.error('Get incident error:', error.message);
            next(error);
        }
    }

    /**
     * Update incident
     */
    async updateIncident(req, res, next) {
        try {
            const incident = await Incident.findOne({
                _id: req.params.id,
                userId: req.user.userId,
            });

            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            const allowedFields = [
                'description',
                'guestAffected',
                'sensitiveDataInvolved',
                'status',
                'likelihood',
                'impact',
            ];

            allowedFields.forEach((field) => {
                if (req.body[field] !== undefined) {
                    incident[field] = req.body[field];
                }
            });

            incident.updatedAt = new Date();
            await incident.save();

            res.json({
                success: true,
                message: 'Incident updated successfully',
                incident,
            });

        } catch (error) {
            logger.error('Update incident error:', error.message);
            next(error);
        }
    }

    /**
     * Update incident status
     */
    async updateIncidentStatus(req, res, next) {
        try {
            const { status } = req.body;

            const validStatuses = ['Open', 'InProgress', 'Resolved'];
            if (!validStatuses.includes(status)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid status',
                });
            }

            const updateData = {
                status,
                updatedAt: new Date(),
            };

            if (status === 'Resolved') {
                updateData.resolvedAt = new Date();
                updateData.resolvedBy = req.user.userId;
            }

            const incident = await Incident.findOneAndUpdate(
                { _id: req.params.id, userId: req.user.userId },
                updateData,
                { new: true }
            );

            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            logger.info(`Incident status updated: ${incident.incidentId} -> ${status}`);

            res.json({
                success: true,
                message: 'Incident status updated',
                incident,
            });

        } catch (error) {
            logger.error('Update incident status error:', error.message);
            next(error);
        }
    }

    /**
     * Add note to incident
     */
    async addNote(req, res, next) {
        try {
            const { note } = req.body;

            if (!note || !note.trim()) {
                return res.status(400).json({
                    success: false,
                    message: 'Note cannot be empty',
                });
            }

            const incident = await Incident.findOne({
                _id: req.params.id,
                userId: req.user.userId,
            });

            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            incident.notes.push(note);
            incident.updatedAt = new Date();
            await incident.save();

            logger.info(`Note added to incident: ${incident.incidentId}`);

            res.json({
                success: true,
                message: 'Note added successfully',
                incident,
            });

        } catch (error) {
            logger.error('Add note error:', error.message);
            next(error);
        }
    }

    /**
     * Search incidents
     */
    async searchIncidents(req, res, next) {
        try {
            const query = req.query.query || '';

            const incidents = await Incident.find({
                userId: req.user.userId,
                $or: [
                    { incidentId: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } },
                    { threatType: { $regex: query, $options: 'i' } },
                ],
            }).sort({ createdAt: -1 });

            res.json({
                success: true,
                count: incidents.length,
                incidents,
            });

        } catch (error) {
            logger.error('Search incidents error:', error.message);
            next(error);
        }
    }

    /**
     * Delete incident
     */
    async deleteIncident(req, res, next) {
        try {
            const incident = await Incident.findOneAndDelete({
                _id: req.params.id,
                userId: req.user.userId,
            });

            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            logger.info(`Incident deleted: ${incident.incidentId}`);

            res.json({
                success: true,
                message: 'Incident deleted successfully',
            });

        } catch (error) {
            logger.error('Delete incident error:', error.message);
            next(error);
        }
    }
}

module.exports = new IncidentController();