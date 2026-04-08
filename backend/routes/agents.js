/**
 * Agent Routes - API endpoints for local scanning agents
 */
// NOTE: Provides endpoints for agents to poll pending scans and upload results.

const express = require('express');
const ScanJob = require('../models/ScanJob');
const logger = require('../utils/logger');

const router = express.Router();

// Authentication for agents using API key
function agentAuth(req, res, next) {
    const apiKey = req.get('X-Agent-API-Key');
    if (!apiKey || apiKey !== process.env.AGENT_API_KEY) {
        return res.status(401).json({
            success: false,
            message: 'Invalid or missing agent API key',
        });
    }

    const agentId = req.get('X-Agent-ID') || 'unknown';
    req.agentId = agentId;
    next();
}

/**
 * GET /api/agents/pending-scans
 * Returns up to 5 pending scan jobs for the agent to pick up
 */
router.get('/pending-scans', agentAuth, async (req, res, next) => {
    try {
        const jobs = await ScanJob.find({ status: 'Pending' })
            .limit(5)
            .sort({ createdAt: 1 });

        if (jobs.length > 0) {
            // Mark as Running and set agent
            await ScanJob.updateMany(
                { _id: { $in: jobs.map((j) => j._id) } },
                { status: 'Running', agentId: req.agentId, scanStartedAt: Date.now() },
            );

            logger.info(`Agent ${req.agentId} picked up ${jobs.length} scan job(s)`);
        }

        res.json({
            success: true,
            jobs: jobs.map((job) => ({
                id: String(job._id),
                target: job.target,
                ports: job.ports,
            })),
        });
    } catch (error) {
        logger.error(`Agent pending scans error: ${error.message}`);
        next(error);
    }
});

/**
 * POST /api/agents/scan-results
 * Agent submits scan results for a completed job
 */
router.post('/scan-results', agentAuth, async (req, res, next) => {
    try {
        const { jobId, nmapResult, cveResult, error } = req.body;

        if (!jobId) {
            return res.status(400).json({
                success: false,
                message: 'jobId is required',
            });
        }

        const job = await ScanJob.findById(jobId);
        if (!job) {
            return res.status(404).json({
                success: false,
                message: 'Scan job not found',
            });
        }

        if (error) {
            job.status = 'Failed';
            job.error = error;
        } else {
            job.status = 'Completed';
            job.nmapResult = nmapResult || null;
            job.cveResult = cveResult || null;
        }

        job.scanCompletedAt = Date.now();
        await job.save();

        logger.info(`Agent ${req.agentId} completed scan job ${jobId}`);

        res.json({
            success: true,
            message: 'Scan results received',
        });
    } catch (error) {
        logger.error(`Agent scan results error: ${error.message}`);
        next(error);
    }
});

/**
 * GET /api/agents/scan-status/:jobId
 * Check status of a specific scan job
 */
router.get('/scan-status/:jobId', async (req, res, next) => {
    try {
        const job = await ScanJob.findById(req.params.jobId);

        if (!job) {
            return res.status(404).json({
                success: false,
                message: 'Scan job not found',
            });
        }

        res.json({
            success: true,
            status: job.status,
            nmapResult: job.nmapResult,
            cveResult: job.cveResult,
            error: job.error,
        });
    } catch (error) {
        logger.error(`Get scan status error: ${error.message}`);
        next(error);
    }
});

module.exports = router;
