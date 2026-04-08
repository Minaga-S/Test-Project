/**
 * Risk Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.


const Incident = require('../models/Incident');
const Asset = require('../models/Asset');
const RiskAssessment = require('../models/RiskAssessment');
const riskService = require('../services/riskCalculationService');
const logger = require('../utils/logger');

const RISK_LEVEL_RANK = {
    Low: 1,
    Medium: 2,
    High: 3,
    Critical: 4,
};

const CRITICALITY_RISK_SCORE = {
    Low: 4,
    Medium: 8,
    High: 12,
    Critical: 16,
};

function getRiskRank(level) {
    return RISK_LEVEL_RANK[level] || 1;
}

function getHigherRiskLevel(currentLevel, nextLevel) {
    if (getRiskRank(nextLevel) > getRiskRank(currentLevel)) {
        return nextLevel;
    }

    return currentLevel || nextLevel || 'Low';
}

function buildAssetRiskRecord(asset) {
    const riskLevel = asset?.criticality || 'Low';

    return {
        assetId: String(asset?._id || ''),
        assetName: asset?.assetName || 'Unknown',
        assetType: asset?.assetType || 'Unknown',
        criticality: riskLevel,
        vulnerabilityProfile: asset?.vulnerabilityProfile || {},
        incidents: [],
        maxRiskScore: CRITICALITY_RISK_SCORE[riskLevel] || 4,
        riskLevel,
    };
}

class RiskController {
    /**
     * Calculate risk
     */
    async calculateRisk(req, res, next) {
        try {
            const { likelihood, impact } = req.body;

            if (!likelihood || !impact || likelihood < 1 || likelihood > 4 || impact < 1 || impact > 4) {
                return res.status(400).json({
                    success: false,
                    message: 'Likelihood and impact must be between 1 and 4',
                });
            }

            const riskAssessment = riskService.calculateRisk(likelihood, impact);

            await RiskAssessment.create({
                likelihood,
                impact,
                riskScore: riskAssessment.score,
                riskLevel: riskAssessment.level,
                recommendation: riskAssessment.recommendation || '',
                userId: req.user.userId,
                updatedAt: new Date(),
            });

            res.json({
                success: true,
                riskAssessment,
            });

        } catch (error) {
            logger.error('Calculate risk error:', error.message);
            next(error);
        }
    }

    /**
     * Get risk assessment for incident
     */
    async getRiskAssessment(req, res, next) {
        try {
            const incident = await Incident.findOne({
                _id: req.params.incidentId,
                userId: req.user.userId,
            });

            if (!incident) {
                return res.status(404).json({
                    success: false,
                    message: 'Incident not found',
                });
            }

            const assessment = {
                incidentId: incident.incidentId,
                likelihood: incident.likelihood,
                impact: incident.impact,
                riskScore: incident.riskScore,
                riskLevel: incident.riskLevel,
                threatType: incident.threatType,
                asset: incident.asset,
            };

            await RiskAssessment.findOneAndUpdate(
                {
                    incidentId: incident._id,
                    userId: req.user.userId,
                },
                {
                    incidentId: incident._id,
                    likelihood: incident.likelihood,
                    impact: incident.impact,
                    riskScore: incident.riskScore,
                    riskLevel: incident.riskLevel,
                    recommendation: riskService.getRiskRecommendation(incident.riskLevel),
                    userId: req.user.userId,
                    updatedAt: new Date(),
                },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            );

            res.json({
                success: true,
                assessment,
            });

        } catch (error) {
            logger.error('Get risk assessment error:', error.message);
            next(error);
        }
    }

    /**
     * Get risk matrix data
     */
    async getRiskMatrix(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId });

            const matrix = incidents.map(incident => ({
                x: incident.likelihood,
                y: incident.impact,
                r: 15,
                label: incident.incidentId,
                riskLevel: incident.riskLevel,
                threatType: incident.threatType,
            }));

            res.json({
                success: true,
                matrix,
                count: matrix.length,
            });

        } catch (error) {
            logger.error('Get risk matrix error:', error.message);
            next(error);
        }
    }

    /**
     * Get risk trends
     */
    async getRiskTrends(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId })
                .sort({ createdAt: 1 });

            const trendData = incidents.map(incident => ({
                date: incident.createdAt,
                riskScore: incident.riskScore,
                riskLevel: incident.riskLevel,
            }));

            const labels = trendData.map(t => new Date(t.date).toLocaleDateString());
            const data = trendData.map(t => t.riskScore);

            res.json({
                success: true,
                labels,
                data,
                trendData,
            });

        } catch (error) {
            logger.error('Get risk trends error:', error.message);
            next(error);
        }
    }

    /**
     * Get risk by asset
     */
    async getRiskByAsset(req, res, next) {
        try {
            const [assets, incidents] = await Promise.all([
                Asset.find({ userId: req.user.userId }),
                Incident.find({ userId: req.user.userId }),
            ]);

            const assetRiskMap = new Map();

            assets.forEach((asset) => {
                assetRiskMap.set(String(asset._id), buildAssetRiskRecord(asset));
            });

            incidents.forEach((incident) => {
                const assetId = String(incident.assetId || '');
                const fallbackAsset = incident.asset || {};
                const existingRecord = assetRiskMap.get(assetId) || buildAssetRiskRecord({
                    _id: assetId,
                    assetName: fallbackAsset.assetName || 'Unknown',
                    assetType: fallbackAsset.assetType || 'Unknown',
                    criticality: 'Low',
                    vulnerabilityProfile: {},
                });

                existingRecord.incidents.push({
                    incidentId: incident.incidentId,
                    riskScore: incident.riskScore,
                    threatType: incident.threatType,
                });

                existingRecord.maxRiskScore = Math.max(existingRecord.maxRiskScore, Number(incident.riskScore) || 0);
                existingRecord.riskLevel = getHigherRiskLevel(existingRecord.riskLevel, incident.riskLevel);
                assetRiskMap.set(assetId || existingRecord.assetId, existingRecord);
            });

            const assetRisks = Array.from(assetRiskMap.values()).sort((left, right) => {
                const riskDifference = getRiskRank(right.riskLevel) - getRiskRank(left.riskLevel);
                if (riskDifference !== 0) {
                    return riskDifference;
                }

                return left.assetName.localeCompare(right.assetName);
            });

            res.json({
                success: true,
                assetRisks,
                count: assetRisks.length,
            });

        } catch (error) {
            logger.error('Get risk by asset error:', error.message);
            next(error);
        }
    }

    /**
     * Get risk summary
     */
    async getRiskSummary(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId });

            const summary = {
                totalIncidents: incidents.length,
                criticalCount: incidents.filter(i => i.riskLevel === 'Critical').length,
                highCount: incidents.filter(i => i.riskLevel === 'High').length,
                mediumCount: incidents.filter(i => i.riskLevel === 'Medium').length,
                lowCount: incidents.filter(i => i.riskLevel === 'Low').length,
                averageRiskScore: incidents.length > 0 
                    ? (incidents.reduce((sum, i) => sum + i.riskScore, 0) / incidents.length).toFixed(2)
                    : 0,
                highestRiskScore: incidents.length > 0 
                    ? Math.max(...incidents.map(i => i.riskScore))
                    : 0,
            };

            res.json({
                success: true,
                summary,
            });

        } catch (error) {
            logger.error('Get risk summary error:', error.message);
            next(error);
        }
    }
}

module.exports = new RiskController();
