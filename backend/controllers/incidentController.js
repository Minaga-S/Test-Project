/**
 * Incident Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.

const Incident = require('../models/Incident');
const Asset = require('../models/Asset');
const threatService = require('../services/threatClassificationService');
const riskService = require('../services/riskCalculationService');
const recommendationService = require('../services/recommendationService');
const nistService = require('../services/nistMappingService');
const assetSecurityContextService = require('../services/assetSecurityContextService');
const scanHistoryService = require('../services/scanHistoryService');
const nmapScanService = require('../services/nmapScanService');
const auditLogService = require('../services/auditLogService');
const { validateIncident } = require('../utils/validators');
const { generateIncidentId } = require('../utils/constants');
const logger = require('../utils/logger');
function normalizeText(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function mergeClientSecurityContext(securityContext, clientSecurityContext) {
    if (!clientSecurityContext || typeof clientSecurityContext !== 'object') {
        return securityContext;
    }

    const nextContext = {
        ...(securityContext || {}),
        clientReported: clientSecurityContext,
    };

    const persistedLiveScan = securityContext?.liveScan || {};
    const mergedLiveScan = {
        ...persistedLiveScan,
        ...(clientSecurityContext?.liveScan || {}),
    };

    const persistedObservedOpenPorts = Array.isArray(persistedLiveScan.observedOpenPorts)
        ? persistedLiveScan.observedOpenPorts
        : [];
    const clientObservedOpenPorts = Array.isArray(clientSecurityContext?.liveScan?.observedOpenPorts)
        ? clientSecurityContext.liveScan.observedOpenPorts
        : [];
    mergedLiveScan.observedOpenPorts = clientObservedOpenPorts.length > 0 ? clientObservedOpenPorts : persistedObservedOpenPorts;

    const persistedOsInfo = normalizeText(persistedLiveScan.osInfo);
    const clientOsInfo = normalizeText(clientSecurityContext?.liveScan?.osInfo);
    mergedLiveScan.osInfo = clientOsInfo || persistedOsInfo;

    // Merge services (client services fallback to persisted)
    const persistedServices = Array.isArray(persistedLiveScan.services) ? persistedLiveScan.services : [];
    const clientServices = Array.isArray(clientSecurityContext?.liveScan?.services) ? clientSecurityContext.liveScan.services : [];
    mergedLiveScan.services = clientServices.length > 0 ? clientServices : persistedServices;

    nextContext.liveScan = mergedLiveScan;

    const mergedCve = {
        ...(securityContext?.cve || {}),
        ...(clientSecurityContext?.cve || {}),
    };

    const clientCveMatches = Array.isArray(clientSecurityContext?.cve?.matches)
        ? clientSecurityContext.cve.matches
        : [];
    if (clientCveMatches.length > 0) {
        mergedCve.matches = clientCveMatches;
        mergedCve.totalMatches = clientCveMatches.length;
    }

    const persistedQuery = securityContext?.cve?.query || {};
    const mergedQuery = {
        ...persistedQuery,
        ...(clientSecurityContext?.cve?.query || {}),
    };

    mergedQuery.osName = normalizeText(mergedQuery.osName) || normalizeText(persistedQuery.osName);
    mergedQuery.vendor = normalizeText(mergedQuery.vendor) || normalizeText(persistedQuery.vendor);
    mergedQuery.product = normalizeText(mergedQuery.product) || normalizeText(persistedQuery.product);
    mergedQuery.productVersion = normalizeText(mergedQuery.productVersion) || normalizeText(persistedQuery.productVersion);
    mergedQuery.cpeUri = normalizeText(mergedQuery.cpeUri) || normalizeText(persistedQuery.cpeUri);

    mergedCve.query = mergedQuery;
    nextContext.cve = mergedCve;

    if (clientSecurityContext.enrichment && typeof clientSecurityContext.enrichment === 'object') {
        nextContext.enrichment = {
            ...(securityContext?.enrichment || {}),
            ...clientSecurityContext.enrichment,
        };
    }

    return nextContext;
}
class IncidentController {
    async createIncident(req, res, next) {
        try {
            const {
                assetId,
                description,
                incidentTime,
                guestAffected,
                paymentsAffected,
                sensitiveDataInvolved,
                clientSecurityContext,
            } = req.body;

            const validation = validateIncident({ assetId, description });
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: validation.errors,
                });
            }

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

            const liveScanTarget = String(asset?.liveScan?.target || '').trim();
            if (liveScanTarget) {
                if (!nmapScanService.isAllowedScanTarget(liveScanTarget)) {
                    return res.status(400).json({
                        success: false,
                        message: 'Scan target must be internal/private. External targets are not allowed.',
                    });
                }

                try {
                    nmapScanService.assertTargetWithinRequesterNetwork(liveScanTarget, req.ip || '');
                } catch (scopeError) {
                    return res.status(400).json({
                        success: false,
                        message: scopeError.message,
                    });
                }
            }

            const latestScanHistory = await scanHistoryService.getLatestScanHistory(asset._id, req.user.userId);
            const securityContext = mergeClientSecurityContext(assetSecurityContextService.buildForAsset(asset, latestScanHistory), clientSecurityContext);

            const threatAnalysis = await threatService.classifyThreat(description, securityContext);
            const riskAssessment = riskService.calculateRisk(
                threatAnalysis.likelihood,
                threatAnalysis.impact
            );

            const nistMapping = nistService.getNISTMapping(threatAnalysis.threatType);

            const parsedIncidentTime = incidentTime ? new Date(incidentTime) : null;
            if (incidentTime && Number.isNaN(parsedIncidentTime.getTime())) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid incident time',
                });
            }

            const recommendations = await recommendationService.generateRecommendations(
                threatAnalysis.threatType,
                { ...threatAnalysis, securityContext }
            );

            const aiModel = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
            const aiVersion = process.env.GEMINI_MODEL_VERSION || 'v1beta';

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
                incidentTime: parsedIncidentTime,
                aiModel,
                aiVersion,
                aiAnalyzedAt: new Date(),
                nistFunctions: nistMapping.functions,
                nistControls: nistMapping.controls,
                recommendations,
                userId: req.user.userId,
                guestAffected: guestAffected || false,
                paymentsAffected: paymentsAffected || false,
                sensitiveDataInvolved: sensitiveDataInvolved || false,
                securityContext,
                cveMatches: securityContext?.cve?.matches || [],
            });

            await incident.save();

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'INCIDENT_CREATE',
                entityType: 'Incident',
                entityId: String(incident._id),
                after: {
                    incidentId: incident.incidentId,
                    riskLevel: incident.riskLevel,
                    threatType: incident.threatType,
                },
                ipAddress: req.ip || '',
            });

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
                    securityContext,
                },
            });
        } catch (error) {
            logger.error(`Create incident error: ${error.message}`);
            next(error);
        }
    }

    async getIncidents(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId }).sort({ createdAt: -1 });

            res.json({
                success: true,
                count: incidents.length,
                incidents,
            });
        } catch (error) {
            logger.error(`Get incidents error: ${error.message}`);
            next(error);
        }
    }

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
            logger.error(`Get incident error: ${error.message}`);
            next(error);
        }
    }

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

            const before = {
                description: incident.description,
                status: incident.status,
                likelihood: incident.likelihood,
                impact: incident.impact,
            };

            const allowedFields = [
                'description',
                'guestAffected',
                'paymentsAffected',
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

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'INCIDENT_UPDATE',
                entityType: 'Incident',
                entityId: String(incident._id),
                before,
                after: {
                    description: incident.description,
                    status: incident.status,
                    likelihood: incident.likelihood,
                    impact: incident.impact,
                },
                ipAddress: req.ip || '',
            });

            res.json({
                success: true,
                message: 'Incident updated successfully',
                incident,
            });
        } catch (error) {
            logger.error(`Update incident error: ${error.message}`);
            next(error);
        }
    }

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

            const incident = await Incident.findOne({ _id: req.params.id, userId: req.user.userId });
            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            const beforeStatus = incident.status;
            incident.status = status;
            incident.updatedAt = new Date();
            if (status === 'Resolved') {
                incident.resolvedAt = new Date();
                incident.resolvedBy = req.user.userId;
            }
            await incident.save();

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'INCIDENT_STATUS_UPDATE',
                entityType: 'Incident',
                entityId: String(incident._id),
                before: { status: beforeStatus },
                after: { status },
                ipAddress: req.ip || '',
            });

            logger.info(`Incident status updated: ${incident.incidentId} -> ${status}`);

            res.json({
                success: true,
                message: 'Incident status updated',
                incident,
            });
        } catch (error) {
            logger.error(`Update incident status error: ${error.message}`);
            next(error);
        }
    }

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

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'INCIDENT_NOTE_ADD',
                entityType: 'Incident',
                entityId: String(incident._id),
                meta: { noteLength: note.length },
                ipAddress: req.ip || '',
            });

            logger.info(`Note added to incident: ${incident.incidentId}`);

            res.json({
                success: true,
                message: 'Note added successfully',
                incident,
            });
        } catch (error) {
            logger.error(`Add note error: ${error.message}`);
            next(error);
        }
    }

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
            logger.error(`Search incidents error: ${error.message}`);
            next(error);
        }
    }

    async deleteIncident(req, res, next) {
        try {
            const incident = await Incident.findOneAndUpdate(
                {
                    _id: req.params.id,
                    userId: req.user.userId,
                },
                {
                    isDeleted: true,
                    deletedAt: new Date(),
                    updatedAt: new Date(),
                },
                { new: true }
            );

            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'INCIDENT_DELETE',
                entityType: 'Incident',
                entityId: String(incident._id),
                before: { incidentId: incident.incidentId, status: incident.status },
                ipAddress: req.ip || '',
            });

            logger.info(`Incident soft-deleted: ${incident.incidentId}`);

            res.json({
                success: true,
                message: 'Incident deleted successfully',
            });
        } catch (error) {
            logger.error(`Delete incident error: ${error.message}`);
            next(error);
        }
    }
}

module.exports = new IncidentController();
