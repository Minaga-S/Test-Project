/**
 * Seed test assets and incidents for CVE + deep-link QA.
 */

require('dotenv').config();

const mongoose = require('mongoose');
const { connectDatabase, closeDatabase } = require('../config/database');
const User = require('../models/User');
const Asset = require('../models/Asset');
const Incident = require('../models/Incident');
const nistCveService = require('../services/nistCveService');
const assetSecurityContextService = require('../services/assetSecurityContextService');
const { generateIncidentId } = require('../utils/constants');

const TEST_ASSETS = [
    {
        assetName: 'Front Desk Web Gateway QA',
        assetType: 'Server',
        description: 'QA seed asset for frontend gateway incident testing.',
        location: 'Front Desk',
        status: 'Active',
        criticality: 'High',
        owner: 'QA Team',
        liveScan: {
            enabled: false,
            target: '',
            ports: '',
            frequency: 'OnDemand',
        },
        vulnerabilityProfile: {
            osName: 'Ubuntu 22.04',
            vendor: 'Apache',
            product: 'Log4j',
            productVersion: '2.14.1',
            cpeUri: '',
        },
    },
    {
        assetName: 'Reservation Citrix Node QA',
        assetType: 'Server',
        description: 'QA seed asset for reservation access layer testing.',
        location: 'Back Office',
        status: 'Active',
        criticality: 'Critical',
        owner: 'QA Team',
        liveScan: {
            enabled: false,
            target: '',
            ports: '',
            frequency: 'OnDemand',
        },
        vulnerabilityProfile: {
            osName: 'Windows Server 2019',
            vendor: 'Citrix',
            product: 'ADC',
            productVersion: '13.0',
            cpeUri: '',
        },
    },
];

const INCIDENT_TEMPLATES = [
    {
        description: 'Front desk web gateway received suspicious malformed requests and unusual header patterns, indicating potential exploitation attempts on outdated web dependencies.',
        threatType: 'Malware',
        threatCategory: 'Application Security',
        confidence: 88,
        likelihood: 3,
        impact: 4,
        riskLevel: 'High',
        riskScore: 12,
        nistFunctions: ['Detect', 'Respond'],
        nistControls: ['DE.CM-1', 'RS.AN-1'],
        recommendations: [
            'Review web application logs for IOC patterns from the last 24 hours.',
            'Patch affected software components to the latest secure version.',
            'Apply temporary WAF rules to block malicious request signatures.',
        ],
        guestAffected: true,
        paymentsAffected: false,
        sensitiveDataInvolved: true,
    },
    {
        description: 'Reservation access node triggered repeated authentication anomalies and session resets, consistent with targeted exploitation or credential abuse attempts.',
        threatType: 'Unauthorized Access',
        threatCategory: 'Identity and Access',
        confidence: 84,
        likelihood: 3,
        impact: 3,
        riskLevel: 'High',
        riskScore: 9,
        nistFunctions: ['Protect', 'Detect', 'Respond'],
        nistControls: ['PR.AC-1', 'DE.AE-2', 'RS.MI-1'],
        recommendations: [
            'Force password reset and session revocation for exposed accounts.',
            'Enable conditional access controls for sensitive administrative paths.',
            'Correlate endpoint and identity logs to identify lateral movement.',
        ],
        guestAffected: false,
        paymentsAffected: true,
        sensitiveDataInvolved: true,
    },
];

async function resolveTargetUser() {
    const targetEmail = String(process.env.SEED_TEST_USER_EMAIL || '').trim().toLowerCase();

    if (targetEmail) {
        const byEmail = await User.findOne({ email: targetEmail });
        if (byEmail) {
            return byEmail;
        }
    }

    return User.findOne({ isActive: true }).sort({ createdAt: 1 });
}

async function upsertAssetForUser(userId, assetSeed) {
    const existing = await Asset.findOne({ userId, assetName: assetSeed.assetName });

    if (existing) {
        Object.assign(existing, assetSeed, { updatedAt: new Date() });
        await existing.save();
        return existing;
    }

    return Asset.create({
        ...assetSeed,
        userId,
    });
}

async function createIncidentForAsset(userId, asset, template) {
    const cveProfile = {
        cpeUri: asset?.vulnerabilityProfile?.cpeUri || '',
        vendor: asset?.vulnerabilityProfile?.vendor || '',
        product: asset?.vulnerabilityProfile?.product || '',
        productVersion: asset?.vulnerabilityProfile?.productVersion || '',
        osName: asset?.vulnerabilityProfile?.osName || '',
        serviceNames: [],
    };

    let cveResult = null;
    try {
        cveResult = await nistCveService.lookupCves(cveProfile, {
            userId: String(userId),
            assetId: String(asset._id),
            ipAddress: '127.0.0.1',
        });
    } catch (error) {
        cveResult = {
            source: 'NIST NVD API',
            query: { keywordSearch: '', searchTerms: [] },
            matches: [],
            totalMatches: 0,
            retrievedAt: new Date().toISOString(),
            confidence: 'Low',
            cacheHit: false,
        };
    }

    const securityContext = assetSecurityContextService.buildFallbackContext(
        asset,
        'Live scan disabled for QA seed data.',
        cveResult
    );

    return Incident.create({
        incidentId: generateIncidentId(),
        description: template.description,
        assetId: asset._id,
        asset: {
            _id: asset._id,
            assetName: asset.assetName,
            assetType: asset.assetType,
            location: asset.location,
        },
        threatType: template.threatType,
        threatCategory: template.threatCategory,
        confidence: template.confidence,
        incidentTime: new Date(),
        likelihood: template.likelihood,
        impact: template.impact,
        riskScore: template.riskScore,
        riskLevel: template.riskLevel,
        status: 'Open',
        aiModel: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
        aiVersion: process.env.GEMINI_MODEL_VERSION || 'v1beta',
        aiAnalyzedAt: new Date(),
        nistFunctions: template.nistFunctions,
        nistControls: template.nistControls,
        recommendations: template.recommendations,
        userId,
        guestAffected: template.guestAffected,
        paymentsAffected: template.paymentsAffected,
        sensitiveDataInvolved: template.sensitiveDataInvolved,
        securityContext,
        cveMatches: Array.isArray(securityContext?.cve?.matches) ? securityContext.cve.matches : [],
        createdAt: new Date(),
        updatedAt: new Date(),
    });
}

async function run() {
    await connectDatabase();

    try {
        const user = await resolveTargetUser();
        if (!user) {
            throw new Error('No active user found. Create/login a user first and rerun this script.');
        }

        const seededAssets = [];
        for (const assetSeed of TEST_ASSETS) {
            const asset = await upsertAssetForUser(user._id, assetSeed);
            seededAssets.push(asset);
        }

        const existingSeedIncidents = await Incident.find({
            userId: user._id,
            assetId: { $in: seededAssets.map((asset) => asset._id) },
        });

        if (existingSeedIncidents.length > 0) {
            await Incident.deleteMany({ _id: { $in: existingSeedIncidents.map((item) => item._id) } });
        }

        const createdIncidents = [];
        for (let index = 0; index < seededAssets.length; index += 1) {
            const incident = await createIncidentForAsset(user._id, seededAssets[index], INCIDENT_TEMPLATES[index]);
            createdIncidents.push(incident);
        }

        console.log('Seed complete.');
        console.log(`User: ${user.email}`);
        console.log('Assets:');
        seededAssets.forEach((asset) => {
            console.log(`- ${asset.assetName} (${asset._id}) liveScan.enabled=${asset.liveScan?.enabled}`);
        });

        console.log('Incidents:');
        createdIncidents.forEach((incident) => {
            const cveCount = Array.isArray(incident.cveMatches) ? incident.cveMatches.length : 0;
            console.log(`- ${incident.incidentId} (${incident._id}) CVEs=${cveCount}`);
        });
    } finally {
        await closeDatabase();
        await mongoose.disconnect();
    }
}

run().catch((error) => {
    console.error('Seed failed:', error.message);
    process.exitCode = 1;
});