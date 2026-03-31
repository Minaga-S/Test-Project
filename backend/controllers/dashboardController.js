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
