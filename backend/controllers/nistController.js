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

function csvEscape(value) {
    const text = String(value ?? '');
    if (/[",\n]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
    }

    return text;
}

function buildComplianceCsvRows(reportPayload) {
    const rows = [['Section', 'Key', 'Value']];
    rows.push(['Summary', 'GeneratedAt', reportPayload.generatedAt]);
    rows.push(['Summary', 'IncidentCount', reportPayload.incidentCount]);
    rows.push(['Summary', 'Coverage', reportPayload.report?.summary || '']);

    const functionCoverage = reportPayload.report?.functions || {};
    Object.entries(functionCoverage).forEach(([key, value]) => {
        rows.push(['Functions', key, value]);
    });

    const controlCoverage = reportPayload.report?.controls || {};
    Object.entries(controlCoverage).forEach(([key, value]) => {
        rows.push(['Controls', key, value]);
    });

    return rows.map((columns) => columns.map(csvEscape).join(',')).join('\n');
}

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

    async getComplianceReport(req, res, next) {
        try {
            const requestedFormat = String(req.query.format || 'json').trim().toLowerCase();

            const incidents = await Incident.find({ userId: req.user.userId })
                .select('incidentId threatType riskLevel status createdAt nistFunctions nistControls');

            const report = nistService.getComplianceReport(incidents);
            const payload = {
                success: true,
                generatedAt: new Date().toISOString(),
                incidentCount: incidents.length,
                report,
            };

            if (requestedFormat === 'csv') {
                const csvContent = buildComplianceCsvRows(payload);
                res.setHeader('Content-Type', 'text/csv; charset=utf-8');
                res.setHeader('Content-Disposition', 'attachment; filename="compliance-report.csv"');
                return res.status(200).send(csvContent);
            }

            return res.json(payload);
        } catch (error) {
            logger.error('Get compliance report error:', error.message);
            return next(error);
        }
    }
}

module.exports = new NISTController();
