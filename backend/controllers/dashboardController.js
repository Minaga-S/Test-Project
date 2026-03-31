/**
 * Dashboard Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.


const Incident = require('../models/Incident');
const Asset = require('../models/Asset');
const logger = require('../utils/logger');

class DashboardController {
    /**
     * Get dashboard metrics
     */
    async getMetrics(req, res, next) {
        try {
            const totalAssets = await Asset.countDocuments({ userId: req.user.userId });
            const openIncidents = await Incident.countDocuments({ 
                userId: req.user.userId, 
                status: 'Open' 
            });
            const criticalRisks = await Incident.countDocuments({ 
                userId: req.user.userId, 
                riskLevel: 'Critical' 
            });
            const resolvedIssues = await Incident.countDocuments({ 
                userId: req.user.userId, 
                status: 'Resolved' 
            });

            const metrics = {
                totalAssets,
                openIncidents,
                criticalRisks,
                resolvedIssues,
                timestamp: new Date(),
            };

            res.json({
                success: true,
                metrics,
            });

        } catch (error) {
            logger.error('Get metrics error:', error.message);
            next(error);
        }
    }

    /**
     * Get risk distribution chart
     */
    async getRiskDistributionChart(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId });

            const distribution = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
            };

            incidents.forEach(incident => {
                distribution[incident.riskLevel]++;
            });

            const chartData = {
                labels: Object.keys(distribution),
                data: Object.values(distribution),
            };

            res.json({
                success: true,
                chart: chartData,
            });

        } catch (error) {
            logger.error('Get risk distribution chart error:', error.message);
            next(error);
        }
    }

    /**
     * Get threat categories chart
     */
    async getThreatCategoriesChart(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId });

            const threatCounts = {};

            incidents.forEach(incident => {
                const threat = incident.threatType;
                threatCounts[threat] = (threatCounts[threat] || 0) + 1;
            });

            const chartData = {
                labels: Object.keys(threatCounts),
                data: Object.values(threatCounts),
            };

            res.json({
                success: true,
                chart: chartData,
            });

        } catch (error) {
            logger.error('Get threat categories chart error:', error.message);
            next(error);
        }
    }

    /**
     * Get vulnerable assets chart
     */
    async getVulnerableAssetsChart(req, res, next) {
        try {
            const incidents = await Incident.find({ userId: req.user.userId });

            const assetVulnerability = {};

            incidents.forEach(incident => {
                const assetName = incident.asset?.assetName || 'Unknown';
                assetVulnerability[assetName] = (assetVulnerability[assetName] || 0) + 1;
            });

            // Sort by count and get top 10
            const sorted = Object.entries(assetVulnerability)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);

            const chartData = {
                labels: sorted.map(s => s[0]),
                data: sorted.map(s => s[1]),
            };

            res.json({
                success: true,
                chart: chartData,
            });

        } catch (error) {
            logger.error('Get vulnerable assets chart error:', error.message);
            next(error);
        }
    }

    /**
     * Get recent incidents
     */
    async getRecentIncidents(req, res, next) {
        try {
            const recentIncidents = await Incident.find({ userId: req.user.userId })
                .sort({ createdAt: -1 })
                .limit(10);

            res.json({
                success: true,
                incidents: recentIncidents,
                count: recentIncidents.length,
            });

        } catch (error) {
            logger.error('Get recent incidents error:', error.message);
            next(error);
        }
    }

    /**
     * Get dashboard overview
     */
    async getOverview(req, res, next) {
        try {
            const totalAssets = await Asset.countDocuments({ userId: req.user.userId });
            const totalIncidents = await Incident.countDocuments({ userId: req.user.userId });
            const openIncidents = await Incident.countDocuments({ 
                userId: req.user.userId, 
                status: 'Open' 
            });
            const criticalRisks = await Incident.countDocuments({ 
                userId: req.user.userId, 
                riskLevel: 'Critical' 
            });

            const overview = {
                totalAssets,
                totalIncidents,
                openIncidents,
                criticalRisks,
                systemHealth: this.calculateSystemHealth(totalAssets, openIncidents, criticalRisks),
                lastUpdate: new Date(),
            };

            res.json({
                success: true,
                overview,
            });

        } catch (error) {
            logger.error('Get overview error:', error.message);
            next(error);
        }
    }

    /**
     * Get 7-day trends for metrics (sparkline data)
     */
    async getMetricsTrends(req, res, next) {
        try {
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            const days = [];
            const trends = {
                totalAssets: [],
                openIncidents: [],
                criticalRisks: [],
                resolvedIssues: [],
            };

            for (let i = 6; i >= 0; i--) {
                const dayStart = new Date(today);
                dayStart.setDate(dayStart.getDate() - i);
                
                const dayEnd = new Date(dayStart);
                dayEnd.setDate(dayEnd.getDate() + 1);
                dayEnd.setMilliseconds(-1);

                days.push(dayStart.toISOString().split('T')[0]);

                // Count assets created by this day
                const assetsCount = await Asset.countDocuments({
                    userId: req.user.userId,
                    createdAt: { $lte: dayEnd },
                });

                // Count open incidents on this day
                const openCount = await Incident.countDocuments({
                    userId: req.user.userId,
                    status: 'Open',
                    createdAt: { $lte: dayEnd },
                });

                // Count critical risks on this day
                const criticalCount = await Incident.countDocuments({
                    userId: req.user.userId,
                    riskLevel: 'Critical',
                    createdAt: { $lte: dayEnd },
                });

                // Count resolved issues created on this day
                const resolvedCount = await Incident.countDocuments({
                    userId: req.user.userId,
                    status: 'Resolved',
                    resolvedAt: { $gte: dayStart, $lte: dayEnd },
                });

                trends.totalAssets.push(assetsCount);
                trends.openIncidents.push(openCount);
                trends.criticalRisks.push(criticalCount);
                trends.resolvedIssues.push(resolvedCount);
            }

            res.json({
                success: true,
                days,
                trends,
            });

        } catch (error) {
            logger.error('Get metrics trends error:', error.message);
            next(error);
        }
    }

    /**
     * Calculate system health score
     */
    calculateSystemHealth(totalAssets, openIncidents, criticalRisks) {
        if (totalAssets === 0) return 100;

        const incidentRatio = (openIncidents / totalAssets) * 100;
        const criticalRatio = (criticalRisks / totalAssets) * 100;

        let healthScore = 100;
        healthScore -= Math.min(incidentRatio * 0.3, 30);
        healthScore -= Math.min(criticalRatio * 0.7, 50);

        return Math.max(0, Math.round(healthScore));
    }
}

module.exports = new DashboardController();
