#!/usr/bin/env node

/**
 * Local Scanning Agent
 * Runs on user's network to execute nmap scans for private assets
 * Polls backend for pending jobs and uploads results
 */

const axios = require('axios');
const { execFile } = require('child_process');
const util = require('util');

const execFileAsync = util.promisify(execFile);

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5000';
const AGENT_API_KEY = process.env.AGENT_API_KEY || 'default-dev-key';
const AGENT_ID = process.env.AGENT_ID || `agent-${Date.now()}`;
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '5000', 10);

const api = axios.create({
    baseURL: `${BACKEND_URL}/api`,
    timeout: 30000,
    headers: {
        'X-Agent-API-Key': AGENT_API_KEY,
        'X-Agent-ID': AGENT_ID,
    },
});

console.log(`🚀 Local Scanning Agent Started`);
console.log(`   Backend: ${BACKEND_URL}`);
console.log(`   Agent ID: ${AGENT_ID}`);
console.log(`   Poll Interval: ${POLL_INTERVAL_MS}ms`);

async function runNmapScan(target, ports = '1-65535') {
    try {
        console.log(`   Running nmap: ${target}:${ports}`);

        const { stdout } = await execFileAsync('nmap', [
            target,
            '-p',
            ports,
            '-sV',
            '-sC',
            '-oX',
            '-',
        ]);

        return {
            success: true,
            result: stdout,
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
        };
    }
}

async function pollAndExecute() {
    try {
        const response = await api.get('/agents/pending-scans');
        const { jobs } = response.data;

        if (jobs.length === 0) {
            return;
        }

        console.log(`📋 Picked up ${jobs.length} job(s)`);

        for (const job of jobs) {
            await executeScanJob(job);
        }
    } catch (error) {
        if (error.response?.status === 401) {
            console.error('❌ Authentication failed. Check AGENT_API_KEY.');
            process.exit(1);
        }
        console.error(`Error polling jobs: ${error.message}`);
    }
}

async function executeScanJob(job) {
    console.log(`\n🔍 Executing scan: ${job.id}`);
    console.log(`   Target: ${job.target}`);
    console.log(`   Ports: ${job.ports}`);

    const scanResult = await runNmapScan(job.target, job.ports);

    if (scanResult.success) {
        console.log(`✅ Scan completed, uploading results...`);
        await uploadResults(job.id, {
            nmapResult: { raw: scanResult.result },
        });
    } else {
        console.log(`❌ Scan failed: ${scanResult.error}`);
        await uploadResults(job.id, null, scanResult.error);
    }
}

async function uploadResults(jobId, results, error = null) {
    try {
        const payload = {
            jobId,
            nmapResult: results?.nmapResult || null,
            cveResult: results?.cveResult || null,
            error,
        };

        await api.post('/agents/scan-results', payload);
        console.log(`   Results uploaded ✓`);
    } catch (error) {
        console.error(`Error uploading results: ${error.message}`);
    }
}

async function startAgent() {
    setInterval(pollAndExecute, POLL_INTERVAL_MS);

    // Initial poll
    await pollAndExecute();
}

startAgent().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n👋 Agent shutting down...');
    process.exit(0);
});
